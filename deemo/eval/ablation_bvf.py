#!/usr/bin/env python3
"""
DD-BVF消融实验 — Baseline vs CJ vs CJ+Interval vs CJ+BVF 精度对比.

四组配置:
  A. Baseline: 纯pattern检测器, 无CJ过滤
  B. CJ: baseline + 约束联结求解器(含FM边界推理+跨函数)
  C. CJ+Interval: CJ + 路径敏感区间域抽象解释器
  D. CJ+BVF: CJ + DD-BVF反向值流追踪(完整管线)

通过monkey-patch控制各模块开关, 不修改任何功能代码.
输出: eval/results/ablation_bvf.json + ablation_bvf.csv + 图表
"""
import json, os, sys, time, csv
from pathlib import Path
from typing import Any, Dict, List, Tuple

_BASE = Path(__file__).resolve().parent.parent
if str(_BASE) not in sys.path:
    sys.path.insert(0, str(_BASE))

# 修复analysis.__init__导入链: HoigCrossFuncVerifier在uaf_hoig_cross_func而非uaf_hoig_propagator
# 提前注入避免ImportError
try:
    from analysis.uaf_hoig_cross_func import HoigCrossFuncVerifier  # noqa
    import analysis.uaf_hoig_propagator as _uaf_prop
    if not hasattr(_uaf_prop, 'HoigCrossFuncVerifier'):
        _uaf_prop.HoigCrossFuncVerifier = HoigCrossFuncVerifier
except Exception:
    pass

# BVF样本目录和ground truth
BVF_SAMPLES_DIR = _BASE / "tests" / "bvf_samples"
# CJ消融样本目录(32个CVE模拟样本)
CJ_SAMPLES_DIR = _BASE / "tests" / "cve_samples" / "heap_overflow"
CJ_GT_PATH = CJ_SAMPLES_DIR / "ground_truth.json"
RESULTS_DIR = _BASE / "eval" / "results"

BVF_EXPECTED = {
    'bvf_01_shared_var_safe': False,
    'bvf_02_shared_var_overflow': True,
    'bvf_03_arith_safe': False,
    'bvf_04_arith_overflow': True,
    'bvf_05_multihop_chain': False,
    'bvf_06_no_shared_unrelated': False,
    'bvf_07_offset_safe': False,
    'bvf_08_offset_overflow': True,
    'bvf_09_taint_unbounded': True,
    'bvf_10_guard_capped_safe': False,
    'bvf_11_calloc_safe': False,
    'bvf_12_calloc_overflow': True,
    'bvf_13_realloc_expand_safe': False,
    'bvf_14_realloc_noexpand_overflow': True,
    'bvf_15_loop_accum_overflow': True,
    'bvf_16_loop_safe': False,
    'bvf_17_struct_field_safe': False,
    'bvf_18_struct_field_overflow': True,
}


def _run_bvf_baseline(code: str, ir_lines: list) -> int:
    """配置A: 纯pattern检测, 不经过CJ过滤."""
    try:
        from core.heap_overflow_detector import detect_heap_overflow
        candidates = detect_heap_overflow(ir_lines, code)
        return len(candidates)
    except Exception:
        return 0


def _run_cj_only(code: str, ir_lines: list, candidates: list) -> Tuple[int, str]:
    """配置B: CJ求解器, 关闭区间域和BVF.

    通过monkey-patch solve_candidate替换为不含interval_refine和BVF的版本.
    绕过analysis.__init__导入链: 直接import cj_affine_bridge内部的函数.
    """
    import core.cj_solver as cj_mod

    original = cj_mod.solve_candidate

    def _solve_no_iv_no_bvf(candidate, ir, decompiled_text="", platform="x86_64"):
        from core.cj_affine_bridge import try_affine_proof
        from core.cj_constraint_collector import collect_constraints
        from core.cj_constraint_types import ConstraintSystem
        affine = try_affine_proof(candidate, ir, platform)
        if affine is not None:
            return affine, ConstraintSystem(mnemonic=candidate.overflow_store.mnemonic)
        sys_obj = collect_constraints(candidate, ir, decompiled_text)
        solver = cj_mod.ConstraintJoinSolver(platform)
        return solver.solve(sys_obj), sys_obj

    cj_mod.solve_candidate = _solve_no_iv_no_bvf
    try:
        return _evaluate_candidates(candidates, ir_lines, code)
    finally:
        cj_mod.solve_candidate = original


def _run_cj_interval(code: str, ir_lines: list, candidates: list) -> Tuple[int, str]:
    """配置C: CJ + 区间域, 关闭BVF."""
    import core.cj_solver as cj_mod
    original = cj_mod.solve_candidate

    # 临时拦截BVF: 让try_bvf_proof返回None
    import core.cj_bvf_solver_bridge as bridge
    bridge_original = bridge.try_bvf_proof
    bridge.try_bvf_proof = lambda *a, **kw: None
    # 同时patch cj_solver中的引用
    cj_bvf_ref = getattr(cj_mod, '_try_bvf_proof', None)
    if cj_bvf_ref:
        cj_mod._try_bvf_proof = lambda *a, **kw: None

    try:
        return _evaluate_candidates(candidates, ir_lines, code)
    finally:
        cj_mod.solve_candidate = original
        bridge.try_bvf_proof = bridge_original
        if cj_bvf_ref:
            cj_mod._try_bvf_proof = cj_bvf_ref


def _run_cj_bvf(code: str, ir_lines: list, candidates: list) -> Tuple[int, str]:
    """配置D: 完整管线 CJ + Interval + BVF."""
    return _evaluate_candidates(candidates, ir_lines, code)


def _evaluate_candidates(candidates: list, ir_lines: list, code: str) -> Tuple[int, str]:
    """运行候选检测, 返回 (检出数, 判定摘要)."""
    from core.cj_solver import solve_candidate
    from core.cj_constraint_types import SolverVerdict
    if not candidates:
        return 0, "no_candidates"
    detected = False
    verdict_str = "inconclusive"
    for c in candidates:
        result, _ = solve_candidate(c, ir_lines, code)
        if result.verdict == SolverVerdict.PROVEN_OVERFLOW:
            detected = True
            verdict_str = result.reason[:80]
            break
        if result.verdict == SolverVerdict.PROVEN_SAFE:
            verdict_str = result.reason[:80]
    return (1 if detected else 0), verdict_str


def _extract_bvf_candidates(code: str) -> Tuple[list, list]:
    """从BVF样本源码提取候选."""
    from tests.bvf_candidate_extractor import extract_candidates_from_code
    return extract_candidates_from_code(code)


def run_bvf_ablation() -> Tuple[List[Dict], Dict]:
    """在BVF样本集上运行四组消融对比."""
    results = []
    configs = ["Baseline", "CJ", "CJ+Interval", "CJ+BVF"]

    for sample_dir in sorted(BVF_SAMPLES_DIR.iterdir()):
        if not sample_dir.is_dir():
            continue
        vuln_c = sample_dir / 'vuln.c'
        if not vuln_c.exists():
            continue
        name = sample_dir.name
        expected = BVF_EXPECTED.get(name)
        if expected is None:
            continue

        code = vuln_c.read_text(encoding='utf-8', errors='replace')
        candidates, ir_lines = _extract_bvf_candidates(code)
        n_candidates = len(candidates)

        base_det = _run_bvf_baseline(code, ir_lines)
        cj_det, cj_v = _run_cj_only(code, ir_lines, candidates)
        cji_det, cji_v = _run_cj_interval(code, ir_lines, candidates)
        cjf_det, cjf_v = _run_cj_bvf(code, ir_lines, candidates)

        row = {
            "sample": name,
            "expected_vuln": expected,
            "n_candidates": n_candidates,
            "Baseline": base_det,
            "CJ": cj_det,
            "CJ+Interval": cji_det,
            "CJ+BVF": cjf_det,
        }
        for cfg in configs:
            cnt = row[cfg]
            detected = cnt > 0
            if expected:
                row[f"{cfg}_verdict"] = "VULN" if detected else "MISS"
            else:
                row[f"{cfg}_verdict"] = "FP" if detected else "SAFE"
        results.append(row)

        print(f"  {name}: B={row['Baseline_verdict']} "
              f"CJ={row['CJ_verdict']} CJ+IV={row['CJ+Interval_verdict']} "
              f"CJ+BVF={row['CJ+BVF_verdict']}")

    metrics = _compute_metrics(results, configs)
    return results, metrics


def _compute_metrics(results: List[Dict], configs: List[str]) -> Dict:
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
        f1 = 2 * prec * rec / (prec + rec) if (prec + rec) > 0 else 0.0
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        metrics[cfg] = {
            "tp": tp, "fp": fp, "tn": tn, "fn": fn,
            "precision": round(prec, 4),
            "recall": round(rec, 4),
            "f1": round(f1, 4),
            "fpr": round(fpr, 4),
        }
    return metrics


def print_ablation_table(results: List[Dict], metrics: Dict):
    configs = ["Baseline", "CJ", "CJ+Interval", "CJ+BVF"]
    print(f"\n{'='*80}")
    print(f" DD-BVF Ablation Study: Baseline vs CJ vs CJ+Interval vs CJ+BVF")
    print(f"{'='*80}")
    print(f" Samples: {len(results)} (BVF-targeted)")
    print(f"\n{'Config':<16} {'TP':>4} {'FP':>4} {'TN':>4} {'FN':>4} "
          f"{'Prec':>8} {'Recall':>8} {'F1':>8} {'FPR':>8}")
    print("-" * 80)
    for cfg in configs:
        m = metrics[cfg]
        print(f"{cfg:<16} {m['tp']:>4} {m['fp']:>4} {m['tn']:>4} {m['fn']:>4} "
              f"{m['precision']:>8.4f} {m['recall']:>8.4f} "
              f"{m['f1']:>8.4f} {m['fpr']:>8.4f}")

    base_fpr = metrics["Baseline"]["fpr"]
    cjf_fpr = metrics["CJ+BVF"]["fpr"]
    if base_fpr > 0:
        reduction = (1 - cjf_fpr / base_fpr) * 100
        print(f"\n FPR reduction (Baseline → CJ+BVF): "
              f"{base_fpr:.4f} → {cjf_fpr:.4f} ({reduction:.1f}% ↓)")

    diff = [r for r in results if r["CJ_verdict"] != r["CJ+BVF_verdict"]]
    if diff:
        print(f"\n CJ+BVF changes verdicts on {len(diff)} samples vs CJ:")
        for r in diff:
            print(f"  {r['sample']}: CJ={r['CJ_verdict']} → "
                  f"CJ+BVF={r['CJ+BVF_verdict']} "
                  f"(expect={'VULN' if r['expected_vuln'] else 'SAFE'})")
    else:
        print("\n CJ+BVF produces same verdicts as CJ on all BVF samples.")
    print(f"{'='*80}")


def save_results(results: List[Dict], metrics: Dict):
    os.makedirs(RESULTS_DIR, exist_ok=True)
    csv_path = RESULTS_DIR / "ablation_bvf.csv"
    with open(csv_path, 'w', newline='') as f:
        w = csv.writer(f)
        w.writerow(["sample", "expected", "n_candidates",
                     "baseline_det", "cj_det", "cj_interval_det", "cj_bvf_det",
                     "baseline_v", "cj_v", "cj_interval_v", "cj_bvf_v"])
        for r in results:
            w.writerow([r["sample"], r["expected_vuln"], r["n_candidates"],
                        r["Baseline"], r["CJ"], r["CJ+Interval"], r["CJ+BVF"],
                        r["Baseline_verdict"], r["CJ_verdict"],
                        r["CJ+Interval_verdict"], r["CJ+BVF_verdict"]])
    print(f" CSV: {csv_path}")

    json_path = RESULTS_DIR / "ablation_bvf.json"
    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump({"results": results, "metrics": metrics}, f, indent=2)
    print(f" JSON: {json_path}")


def generate_chart(metrics: Dict):
    """生成消融对比柱状图."""
    try:
        import matplotlib
        matplotlib.use('Agg')
        import matplotlib.pyplot as plt
        import numpy as np
    except ImportError:
        print(" matplotlib not available, skipping chart")
        return

    configs = ["Baseline", "CJ", "CJ+Interval", "CJ+BVF"]
    x = np.arange(len(configs))
    width = 0.18

    fig, ax1 = plt.subplots(figsize=(10, 5.5))

    precs = [metrics[c]["precision"] for c in configs]
    recs = [metrics[c]["recall"] for c in configs]
    f1s = [metrics[c]["f1"] for c in configs]
    fprs = [metrics[c]["fpr"] for c in configs]

    bars1 = ax1.bar(x - 1.5*width, precs, width, label='Precision', color='#2196F3')
    bars2 = ax1.bar(x - 0.5*width, recs, width, label='Recall', color='#4CAF50')
    bars3 = ax1.bar(x + 0.5*width, f1s, width, label='F1', color='#FF9800')
    bars4 = ax1.bar(x + 1.5*width, fprs, width, label='FPR', color='#F44336')

    ax1.set_ylabel('Score', fontsize=12)
    ax1.set_xticks(x)
    ax1.set_xticklabels(configs, fontsize=11)
    ax1.set_ylim(-0.05, 1.15)
    ax1.legend(loc='upper left', fontsize=10)
    ax1.set_title('DD-BVF Ablation: Precision/Recall/F1/FPR across 4 configs',
                  fontsize=13)
    ax1.axhline(y=1.0, color='gray', linestyle='--', alpha=0.3)

    for bars in [bars1, bars2, bars3, bars4]:
        for bar in bars:
            h = bar.get_height()
            if h > 0.01:
                ax1.text(bar.get_x() + bar.get_width()/2., h + 0.01,
                         f'{h:.2f}', ha='center', va='bottom', fontsize=7)

    chart_path = RESULTS_DIR / "ablation_bvf_chart.png"
    fig.tight_layout()
    fig.savefig(chart_path, dpi=150)
    plt.close(fig)
    print(f" Chart: {chart_path}")


if __name__ == '__main__':
    print("[DD-BVF Ablation] Baseline vs CJ vs CJ+Interval vs CJ+BVF")
    print("[1/3] Running on 18 BVF samples...")
    results, metrics = run_bvf_ablation()
    print_ablation_table(results, metrics)
    save_results(results, metrics)
    print("\n[2/3] Generating chart...")
    generate_chart(metrics)
    print("[3/3] Done.")
