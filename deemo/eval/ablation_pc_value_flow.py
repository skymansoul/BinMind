#!/usr/bin/env python3
"""
路径条件后向值流消融实验 — Baseline vs 约束求解 vs 约束求解+后向值流 vs 约束求解+后向值流+路径条件后向值流.

五组配置:
  A. Baseline: 纯pattern检测器, 无约束求解过滤
  B. 约束求解: baseline + 约束联结求解器
  C. 约束求解+后向值流: 约束求解 + DD-后向值流追踪
  D. 约束求解+后向值流+路径条件后向值流: 约束求解 + 后向值流 + 路径条件后向值流路径约束感知判定

证明路径条件后向值流在后向值流-INCONCLUSIVE场景上的增量贡献:
  - 后向值流无法判定的"fixed alloc + guarded write var"场景
  - 路径条件后向值流利用路径约束收紧变量值域后正确判定SAFE/OVERFLOW

输出: eval/results/ablation_pc_value_flow.json + ablation_pc_value_flow.csv + 图表
"""
import json, os, sys, csv
from pathlib import Path
from typing import Any, Dict, List, Tuple

_BASE = Path(__file__).resolve().parent.parent
if str(_BASE) not in sys.path:
    sys.path.insert(0, str(_BASE))

try:
    from analysis.uaf_obj_graph_cross_func import HoigCrossFuncVerifier  # noqa
    import analysis.uaf_obj_graph_propagator as _uaf_prop
    if not hasattr(_uaf_prop, 'HoigCrossFuncVerifier'):
        _uaf_prop.HoigCrossFuncVerifier = HoigCrossFuncVerifier
except Exception:
    pass

PCBVF_SAMPLES_DIR = _BASE / "tests" / "pcbvf_samples"
RESULTS_DIR = _BASE / "eval" / "results"

PCBVF_EXPECTED = {
    'pcbvf_01': False, 'pcbvf_02': True, 'pcbvf_03': False,
    'pcbvf_04': True, 'pcbvf_05': False, 'pcbvf_06': False,
    'pcbvf_07': True, 'pcbvf_08': False, 'pcbvf_09': False,
    'pcbvf_10': True, 'pcbvf_11': False, 'pcbvf_12': False,
}

CONFIGS = ["Baseline", "CJ", "CJ+BVF", "CJ+BVF+PC-BVF"]


def _extract_candidates(code: str) -> Tuple[list, list]:
    from tests.value_flow_candidate_extractor import extract_candidates_from_code
    return extract_candidates_from_code(code)


def _run_baseline(candidates: list, ir_lines: list, code: str) -> str:
    """配置A: 纯pattern检测, 不经过约束求解/后向值流/路径条件后向值流."""
    if not candidates:
        return "SAFE"
    return "VULN"


def _run_cj(candidates: list, ir_lines: list, code: str) -> str:
    """配置B: 仅约束求解器, 关闭后向值流和路径条件后向值流."""
    from core.constraint_solver import solve_candidate
    from core.constraint_constraint_types import SolverVerdict
    if not candidates:
        return "SAFE"
    detected = False
    for c in candidates:
        result, _ = _solve_cj_only(c, ir_lines, code)
        if result.verdict == SolverVerdict.PROVEN_OVERFLOW:
            detected = True
            break
    return "VULN" if detected else "SAFE"


def _solve_cj_only(candidate, ir_lines, code):
    """仅约束求解: 仿射→约束收集→区间域→FM消元, 不触发后向值流/路径条件后向值流."""
    from core.constraint_affine_bridge import try_affine_proof
    from core.constraint_constraint_collector import collect_constraints
    from core.constraint_interval_domain import interval_refine
    from core.constraint_constraint_types import ConstraintSystem
    from core.constraint_solver import ConstraintJoinSolver
    platform = "x86_64"
    affine = try_affine_proof(candidate, ir_lines, platform)
    if affine is not None:
        return affine, ConstraintSystem(
            mnemonic=candidate.overflow_store.mnemonic)
    sys_obj = collect_constraints(candidate, ir_lines, code)
    alloc_pc = candidate.alloc_site.pc
    write_pc = candidate.overflow_store.pc
    sys_obj = interval_refine(sys_obj, ir_lines, code, alloc_pc, write_pc)
    solver = ConstraintJoinSolver(platform)
    return solver.solve(sys_obj), sys_obj


def _run_cj_bvf(candidates: list, ir_lines: list, code: str) -> str:
    """配置C: 约束求解 + 后向值流, 关闭路径条件后向值流."""
    import core.constraint_solver as cj_mod
    import core.constraint_pc_value_flow_bridge as pcbvf_bridge
    original_pcbvf = pcbvf_bridge.try_pcbvf_proof
    pcbvf_bridge.try_pcbvf_proof = lambda *a, **kw: None

    try:
        from core.constraint_solver import solve_candidate
        from core.constraint_constraint_types import SolverVerdict
        if not candidates:
            return "SAFE"
        detected = False
        for c in candidates:
            result, _ = solve_candidate(c, ir_lines, code)
            if result.verdict == SolverVerdict.PROVEN_OVERFLOW:
                detected = True
                break
        return "VULN" if detected else "SAFE"
    finally:
        pcbvf_bridge.try_pcbvf_proof = original_pcbvf


def _run_cj_bvf_pcbvf(candidates: list, ir_lines: list,
                       code: str) -> str:
    """配置D: 完整管线 约束求解 + 后向值流 + 路径条件后向值流."""
    from core.constraint_solver import solve_candidate
    from core.constraint_constraint_types import SolverVerdict
    if not candidates:
        return "SAFE"
    detected = False
    for c in candidates:
        result, _ = solve_candidate(c, ir_lines, code)
        if result.verdict == SolverVerdict.PROVEN_OVERFLOW:
            detected = True
            break
    return "VULN" if detected else "SAFE"


def run_pcbvf_ablation() -> Tuple[List[Dict], Dict]:
    results = []
    for sample_dir in sorted(PCBVF_SAMPLES_DIR.iterdir()):
        if not sample_dir.is_dir():
            continue
        vuln_c = sample_dir / 'vuln.c'
        if not vuln_c.exists():
            continue
        name = sample_dir.name
        expected = PCBVF_EXPECTED.get(name)
        if expected is None:
            continue

        code = vuln_c.read_text(encoding='utf-8', errors='replace')
        candidates, ir_lines = _extract_candidates(code)

        b = _run_baseline(candidates, ir_lines, code)
        c = _run_cj(candidates, ir_lines, code)
        d = _run_cj_bvf(candidates, ir_lines, code)
        e = _run_cj_bvf_pcbvf(candidates, ir_lines, code)

        row = {
            "sample": name, "expected_vuln": expected,
            "n_candidates": len(candidates),
            "Baseline": b, "CJ": c, "CJ+BVF": d, "CJ+BVF+PC-BVF": e,
        }
        results.append(row)
        print(f"  {name}: B={b} CJ={c} CJ+BVF={d} CJ+BVF+PC-BVF={e} "
              f"(expect={'VULN' if expected else 'SAFE'})")

    metrics = _compute_metrics(results)
    return results, metrics


def _compute_metrics(results: List[Dict]) -> Dict:
    metrics = {}
    for cfg in CONFIGS:
        tp = fp = tn = fn = 0
        for r in results:
            v = r[cfg]
            if r["expected_vuln"]:
                if v == "VULN": tp += 1
                else: fn += 1
            else:
                if v == "VULN": fp += 1
                else: tn += 1
        prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = 2 * prec * rec / (prec + rec) if (prec + rec) > 0 else 0.0
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        metrics[cfg] = {
            "tp": tp, "fp": fp, "tn": tn, "fn": fn,
            "precision": round(prec, 4), "recall": round(rec, 4),
            "f1": round(f1, 4), "fpr": round(fpr, 4),
        }
    return metrics


def print_table(results, metrics):
    print(f"\n{'='*85}")
    print(f" PC-BVF Ablation: Baseline vs CJ vs CJ+BVF vs CJ+BVF+PC-BVF")
    print(f"{'='*85}")
    print(f" Samples: {len(results)} (PC-BVF-targeted)")
    print(f"\n{'Config':<20} {'TP':>4} {'FP':>4} {'TN':>4} {'FN':>4} "
          f"{'Prec':>8} {'Recall':>8} {'F1':>8} {'FPR':>8}")
    print("-" * 85)
    for cfg in CONFIGS:
        m = metrics[cfg]
        print(f"{cfg:<20} {m['tp']:>4} {m['fp']:>4} {m['tn']:>4} "
              f"{m['fn']:>4} {m['precision']:>8.4f} "
              f"{m['recall']:>8.4f} {m['f1']:>8.4f} "
              f"{m['fpr']:>8.4f}")

    bvf_f1 = metrics["CJ+BVF"]["f1"]
    pcbvf_f1 = metrics["CJ+BVF+PC-BVF"]["f1"]
    bvf_rec = metrics["CJ+BVF"]["recall"]
    pcbvf_rec = metrics["CJ+BVF+PC-BVF"]["recall"]
    print(f"\n Recall improvement (CJ+BVF → CJ+BVF+PC-BVF): "
          f"{bvf_rec:.4f} → {pcbvf_rec:.4f}")
    print(f" F1 improvement: {bvf_f1:.4f} → {pcbvf_f1:.4f}")

    diff = [r for r in results
            if r["CJ+BVF"] != r["CJ+BVF+PC-BVF"]]
    if diff:
        print(f"\n PC-BVF changes verdicts on {len(diff)} samples "
              f"vs CJ+BVF:")
        for r in diff:
            print(f"  {r['sample']}: "
                  f"CJ+BVF={r['CJ+BVF']} → "
                  f"CJ+BVF+PC-BVF={r['CJ+BVF+PC-BVF']} "
                  f"(expect={'VULN' if r['expected_vuln'] else 'SAFE'})")
    else:
        print("\n PC-BVF produces same verdicts as CJ+BVF on all samples.")
    print(f"{'='*85}")


def save_results(results, metrics):
    os.makedirs(RESULTS_DIR, exist_ok=True)
    csv_path = RESULTS_DIR / "ablation_pc_value_flow.csv"
    with open(csv_path, 'w', newline='') as f:
        w = csv.writer(f)
        w.writerow(["sample", "expected", "n_candidates"] + CONFIGS)
        for r in results:
            w.writerow([r["sample"], r["expected_vuln"],
                        r["n_candidates"]] +
                       [r[c] for c in CONFIGS])
    print(f" CSV: {csv_path}")

    json_path = RESULTS_DIR / "ablation_pc_value_flow.json"
    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump({"results": results, "metrics": metrics}, f, indent=2)
    print(f" JSON: {json_path}")


def generate_chart(metrics):
    try:
        import matplotlib
        matplotlib.use('Agg')
        import matplotlib.pyplot as plt
        import numpy as np
    except ImportError:
        print(" matplotlib not available, skipping chart")
        return

    x = np.arange(len(CONFIGS))
    width = 0.18
    fig, ax1 = plt.subplots(figsize=(11, 5.5))
    precs = [metrics[c]["precision"] for c in CONFIGS]
    recs = [metrics[c]["recall"] for c in CONFIGS]
    f1s = [metrics[c]["f1"] for c in CONFIGS]
    fprs = [metrics[c]["fpr"] for c in CONFIGS]
    ax1.bar(x - 1.5*width, precs, width, label='Precision',
            color='#2196F3')
    ax1.bar(x - 0.5*width, recs, width, label='Recall',
            color='#4CAF50')
    ax1.bar(x + 0.5*width, f1s, width, label='F1', color='#FF9800')
    ax1.bar(x + 1.5*width, fprs, width, label='FPR', color='#F44336')
    ax1.set_ylabel('Score', fontsize=12)
    ax1.set_xticks(x)
    ax1.set_xticklabels(CONFIGS, fontsize=9, rotation=10)
    ax1.set_ylim(-0.05, 1.15)
    ax1.legend(loc='upper left', fontsize=10)
    ax1.set_title(
        'PC-BVF Ablation: Precision/Recall/F1/FPR across 4 configs',
        fontsize=13)
    ax1.axhline(y=1.0, color='gray', linestyle='--', alpha=0.3)
    for i, (p, r, f, fp) in enumerate(zip(precs, recs, f1s, fprs)):
        for val, off in [(p, -1.5), (r, -0.5), (f, 0.5), (fp, 1.5)]:
            if val > 0.01:
                ax1.text(x[i] + off*width, val + 0.01,
                         f'{val:.2f}', ha='center', va='bottom',
                         fontsize=7)
    chart_path = RESULTS_DIR / "ablation_pc_value_flow_chart.png"
    fig.tight_layout()
    fig.savefig(chart_path, dpi=150)
    plt.close(fig)
    print(f" Chart: {chart_path}")


if __name__ == '__main__':
    print("[PC-BVF Ablation] Baseline vs CJ vs CJ+BVF "
          "vs CJ+BVF+PC-BVF")
    print("[1/3] Running on 12 PC-BVF samples...")
    results, metrics = run_pcbvf_ablation()
    print_table(results, metrics)
    save_results(results, metrics)
    print("\n[2/3] Generating chart...")
    generate_chart(metrics)
    print("[3/3] Done.")
