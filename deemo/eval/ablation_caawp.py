#!/usr/bin/env python3
"""
CAAWP消融实验 — Baseline vs CJ vs CJ+BVF vs CJ+BVF+CAAWP 精度对比.

四组配置:
  A. Baseline: 纯pattern检测器, 无CJ过滤
  B. CJ: baseline + 约束联结求解器(含仿射证明+FM边界)
  C. CJ+BVF: CJ + DD-BVF反向值流追踪(关闭CAAWP)
  D. CJ+BVF+CAAWP: 完整管线(含上下文敏感仿射证明)

通过monkey-patch控制CAAWP开关, 不修改任何功能代码.
输出: eval/results/ablation_caawp.json + ablation_caawp.csv + 图表
"""
import json, os, sys, csv
from pathlib import Path
from typing import Dict, List, Tuple

_BASE = Path(__file__).resolve().parent.parent
if str(_BASE) not in sys.path:
    sys.path.insert(0, str(_BASE))

CAAWP_SAMPLES_DIR = _BASE / "tests" / "caawp_samples"
RESULTS_DIR = _BASE / "eval" / "results"

CAAWP_EXPECTED = {
    'caawp_01_ctx_safe': False,
    'caawp_02_ctx_overflow': True,
    'caawp_03_ctx_dual_safe_overflow': True,
    'caawp_04_callchain_deep_safe': False,
    'caawp_05_callchain_deep_overflow': True,
    'caawp_06_calloc_product_overflow': True,
    'caawp_07_calloc_product_safe': False,
    'caawp_08_const_diff_safe': False,
    'caawp_09_const_diff_overflow': True,
    'caawp_10_taint_fixed_alloc_overflow': True,
    'caawp_11_taint_var_alloc_safe': False,
    'caawp_12_offset_const_safe': False,
    'caawp_13_offset_const_overflow': True,
    'caawp_14_coefficient_ratio_safe': False,
    'caawp_15_coefficient_ratio_overflow': True,
    'caawp_16_multivar_subset_safe': False,
    'caawp_17_multivar_independent_overflow': True,
    'caawp_18_realloc_shrink_overflow': True,
    'caawp_19_wrapper_indirect_overflow': True,
    'caawp_20_wrapper_indirect_safe': False,
}


def _run_baseline(code, ir_lines):
    """配置A: 纯pattern检测, 不经过CJ."""
    try:
        from core.heap_overflow_detector import detect_heap_overflow
        candidates = detect_heap_overflow(ir_lines, code)
        return len(candidates) > 0
    except Exception:
        return False


def _run_cj(code, ir_lines, candidates):
    """配置B: CJ求解器, 关闭BVF和CAAWP."""
    import core.cj_solver as cj_mod
    from core.cj_constraint_types import SolverVerdict
    original = cj_mod.solve_candidate

    def _solve_no_bvf_no_caawp(c, ir, txt="", plat="x86_64"):
        from core.cj_affine_bridge import try_affine_proof
        from core.cj_constraint_collector import collect_constraints
        from core.cj_constraint_types import ConstraintSystem
        affine = try_affine_proof(c, ir, plat)
        if affine is not None:
            return affine, ConstraintSystem(
                mnemonic=c.overflow_store.mnemonic)
        sys_obj = collect_constraints(c, ir, txt)
        solver = cj_mod.ConstraintJoinSolver(plat)
        return solver.solve(sys_obj), sys_obj

    cj_mod.solve_candidate = _solve_no_bvf_no_caawp
    try:
        return _eval(candidates, ir_lines, code)
    finally:
        cj_mod.solve_candidate = original


def _run_cj_bvf_no_caawp(code, ir_lines, candidates):
    """配置C: CJ+BVF, 关闭CAAWP."""
    import core.caawp_bridge as bridge_mod
    orig = bridge_mod.try_caawp_proof
    bridge_mod.try_caawp_proof = lambda *a, **kw: None
    try:
        return _eval(candidates, ir_lines, code)
    finally:
        bridge_mod.try_caawp_proof = orig


def _run_full(code, ir_lines, candidates):
    """配置D: CJ+BVF+CAAWP 完整管线."""
    return _eval(candidates, ir_lines, code)


def _eval(candidates, ir_lines, code):
    """运行候选检测, 返回是否检出溢出."""
    from core.cj_solver import solve_candidate
    from core.cj_constraint_types import SolverVerdict
    if not candidates:
        return False
    for c in candidates:
        result, _ = solve_candidate(c, ir_lines, code)
        if result.verdict == SolverVerdict.PROVEN_OVERFLOW:
            return True
    return False


def run_caawp_ablation():
    """在CAAWP样本集上运行四组消融对比."""
    results = []
    configs = ["Baseline", "CJ", "CJ+BVF", "CJ+BVF+CAAWP"]

    for sample_dir in sorted(CAAWP_SAMPLES_DIR.iterdir()):
        if not sample_dir.is_dir():
            continue
        vuln_c = sample_dir / 'vuln.c'
        if not vuln_c.exists():
            continue
        name = sample_dir.name
        expected = CAAWP_EXPECTED.get(name)
        if expected is None:
            continue

        code = vuln_c.read_text(encoding='utf-8', errors='replace')
        from tests.bvf_candidate_extractor import (
            extract_candidates_from_code)
        candidates, ir_lines = extract_candidates_from_code(code)

        b_det = _run_baseline(code, ir_lines)
        cj_det = _run_cj(code, ir_lines, candidates)
        cjb_det = _run_cj_bvf_no_caawp(code, ir_lines, candidates)
        full_det = _run_full(code, ir_lines, candidates)

        row = {
            "sample": name, "expected_vuln": expected,
            "n_candidates": len(candidates),
            "Baseline": b_det, "CJ": cj_det,
            "CJ+BVF": cjb_det, "CJ+BVF+CAAWP": full_det,
        }
        for cfg in configs:
            det = row[cfg]
            if expected:
                row[f"{cfg}_verdict"] = "VULN" if det else "MISS"
            else:
                row[f"{cfg}_verdict"] = "FP" if det else "SAFE"
        results.append(row)

        print(f"  {name}: B={row['Baseline_verdict']} "
              f"CJ={row['CJ_verdict']} "
              f"CJ+BVF={row['CJ+BVF_verdict']} "
              f"CJ+BVF+CAAWP={row['CJ+BVF+CAAWP_verdict']}")

    metrics = _compute_metrics(results, configs)
    return results, metrics


def _compute_metrics(results, configs):
    metrics = {}
    for cfg in configs:
        tp = fp = tn = fn = 0
        for r in results:
            v = r[f"{cfg}_verdict"]
            if r["expected_vuln"]:
                if v == "VULN": tp += 1
                else: fn += 1
            else:
                if v == "FP": fp += 1
                else: tn += 1
        prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = 2*prec*rec/(prec+rec) if (prec+rec) > 0 else 0.0
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        metrics[cfg] = {
            "tp": tp, "fp": fp, "tn": tn, "fn": fn,
            "precision": round(prec, 4),
            "recall": round(rec, 4),
            "f1": round(f1, 4),
            "fpr": round(fpr, 4),
        }
    return metrics


def print_table(results, metrics):
    configs = ["Baseline", "CJ", "CJ+BVF", "CJ+BVF+CAAWP"]
    print(f"\n{'='*85}")
    print(f" CAAWP Ablation: Baseline vs CJ vs CJ+BVF vs CJ+BVF+CAAWP")
    print(f"{'='*85}")
    print(f" Samples: {len(results)} (CAAWP-targeted)")
    print(f"\n{'Config':<20} {'TP':>4} {'FP':>4} {'TN':>4} {'FN':>4} "
          f"{'Prec':>8} {'Recall':>8} {'F1':>8} {'FPR':>8}")
    print("-" * 85)
    for cfg in configs:
        m = metrics[cfg]
        print(f"{cfg:<20} {m['tp']:>4} {m['fp']:>4} {m['tn']:>4} "
              f"{m['fn']:>4} {m['precision']:>8.4f} {m['recall']:>8.4f} "
              f"{m['f1']:>8.4f} {m['fpr']:>8.4f}")

    cjb = metrics["CJ+BVF"]
    full = metrics["CJ+BVF+CAAWP"]
    if cjb["fpr"] > 0:
        red = (1 - full["fpr"] / cjb["fpr"]) * 100
        print(f"\n FPR reduction (CJ+BVF -> +CAAWP): "
              f"{cjb['fpr']:.4f} -> {full['fpr']:.4f} ({red:.1f}% down)")

    diff = [r for r in results
            if r["CJ+BVF_verdict"] != r["CJ+BVF+CAAWP_verdict"]]
    if diff:
        print(f"\n CAAWP changes verdicts on {len(diff)} samples vs CJ+BVF:")
        for r in diff:
            print(f"  {r['sample']}: CJ+BVF={r['CJ+BVF_verdict']} "
                  f"-> +CAAWP={r['CJ+BVF+CAAWP_verdict']} "
                  f"(expect={'VULN' if r['expected_vuln'] else 'SAFE'})")
    else:
        print("\n CAAWP produces same verdicts as CJ+BVF on all samples.")
    print(f"{'='*85}")


def save_results(results, metrics):
    os.makedirs(RESULTS_DIR, exist_ok=True)
    csv_path = RESULTS_DIR / "ablation_caawp.csv"
    with open(csv_path, 'w', newline='') as f:
        w = csv.writer(f)
        w.writerow(["sample", "expected", "n_candidates",
                     "baseline", "cj", "cj_bvf", "full",
                     "bl_v", "cj_v", "cjb_v", "full_v"])
        for r in results:
            w.writerow([r["sample"], r["expected_vuln"], r["n_candidates"],
                        r["Baseline"], r["CJ"], r["CJ+BVF"],
                        r["CJ+BVF+CAAWP"],
                        r["Baseline_verdict"], r["CJ_verdict"],
                        r["CJ+BVF_verdict"], r["CJ+BVF+CAAWP_verdict"]])
    print(f" CSV: {csv_path}")
    json_path = RESULTS_DIR / "ablation_caawp.json"
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
    configs = ["Baseline", "CJ", "CJ+BVF", "CJ+BVF+CAAWP"]
    x = np.arange(len(configs))
    width = 0.18
    fig, ax1 = plt.subplots(figsize=(10, 5.5))
    precs = [metrics[c]["precision"] for c in configs]
    recs = [metrics[c]["recall"] for c in configs]
    f1s = [metrics[c]["f1"] for c in configs]
    fprs = [metrics[c]["fpr"] for c in configs]
    bars1 = ax1.bar(x-1.5*width, precs, width, label='Precision', color='#2196F3')
    bars2 = ax1.bar(x-0.5*width, recs, width, label='Recall', color='#4CAF50')
    bars3 = ax1.bar(x+0.5*width, f1s, width, label='F1', color='#FF9800')
    bars4 = ax1.bar(x+1.5*width, fprs, width, label='FPR', color='#F44336')
    ax1.set_ylabel('Score', fontsize=12)
    ax1.set_xticks(x)
    ax1.set_xticklabels(configs, fontsize=10)
    ax1.set_ylim(-0.05, 1.15)
    ax1.legend(loc='upper left', fontsize=10)
    ax1.set_title(
        'CAAWP Ablation: Precision/Recall/F1/FPR across 4 configs',
        fontsize=13)
    ax1.axhline(y=1.0, color='gray', linestyle='--', alpha=0.3)
    for bars in [bars1, bars2, bars3, bars4]:
        for bar in bars:
            h = bar.get_height()
            if h > 0.01:
                ax1.text(bar.get_x()+bar.get_width()/2., h+0.01,
                         f'{h:.2f}', ha='center', va='bottom', fontsize=7)
    chart_path = RESULTS_DIR / "ablation_caawp_chart.png"
    fig.tight_layout()
    fig.savefig(chart_path, dpi=150)
    plt.close(fig)
    print(f" Chart: {chart_path}")


if __name__ == '__main__':
    print("[CAAWP Ablation] Baseline vs CJ vs CJ+BVF vs CJ+BVF+CAAWP")
    print("[1/3] Running on 20 CAAWP samples...")
    results, metrics = run_caawp_ablation()
    print_table(results, metrics)
    save_results(results, metrics)
    print("\n[2/3] Generating chart...")
    generate_chart(metrics)
    print("[3/3] Done.")
