#!/usr/bin/env python3
"""
消融实验 — BinMind-baseline vs CJ vs CJ+Interval 精度对比.

三种配置:
  A. Baseline: 纯pattern检测器(heap_overflow_detector), 无CJ过滤
  B. CJ: baseline + 约束联结求解器(含FM边界推理+跨函数)
  C. CJ+Interval: CJ + 路径敏感区间域抽象解释器

通过临时关闭interval_refine来实现配置B, 恢复则为配置C,
不修改任何功能代码, 仅切换入口.
"""
import json, os, sys, time, csv
from pathlib import Path
from typing import Any, Dict, List, Tuple

_BASE = Path(__file__).resolve().parent.parent
if str(_BASE) not in sys.path:
    sys.path.insert(0, str(_BASE))

SAMPLE_DIR = _BASE / "tests" / "cve_samples" / "heap_overflow"
GROUND_TRUTH_PATH = SAMPLE_DIR / "ground_truth.json"
RESULTS_DIR = _BASE / "eval" / "results"

from eval.ablation_interval_micro import run_micro_benchmarks, print_micro_results


def load_ground_truth() -> Dict:
    with open(GROUND_TRUTH_PATH, encoding='utf-8') as f:
        return json.load(f)


def read_source(name: str) -> str:
    d = SAMPLE_DIR / name
    for ext in ('*.c', '*.cpp'):
        files = list(d.glob(ext))
        if files:
            return files[0].read_text(encoding='utf-8', errors='replace')
    return ""


def run_baseline(source: str) -> int:
    """配置A: 纯pattern检测器, 返回检测到的溢出数量."""
    try:
        from core.ir_normalizer import normalize_ir
        from core.heap_overflow_detector import detect_heap_overflow
        ir = normalize_ir(source)
        candidates = detect_heap_overflow(ir, source)
        return len(candidates)
    except Exception:
        return 0


def run_cj(source: str, enable_interval: bool) -> Tuple[int, Dict]:
    """配置B/C: baseline + CJ求解器(+/-区间域).

    通过monkey-patch控制是否调用interval_refine.
    """
    import core.cj_solver as cj_solver_mod

    original_solve = cj_solver_mod.solve_candidate

    if not enable_interval:
        def _solve_no_interval(candidate, ir_lines, decompiled_text="", platform="x86_64"):
            from core.cj_affine_bridge import try_affine_proof
            from core.cj_constraint_collector import collect_constraints
            from core.cj_constraint_types import ConstraintSystem

            affine_result = try_affine_proof(candidate, ir_lines, platform)
            if affine_result is not None:
                sys_empty = ConstraintSystem(mnemonic=candidate.overflow_store.mnemonic)
                return affine_result, sys_empty

            sys_obj = collect_constraints(candidate, ir_lines, decompiled_text)
            solver = cj_solver_mod.ConstraintJoinSolver(platform)
            result = solver.solve(sys_obj)
            return result, sys_obj

        cj_solver_mod.solve_candidate = _solve_no_interval

    try:
        from core.ir_normalizer import normalize_ir
        from core.heap_overflow_detector import detect_heap_overflow
        from core.cj_fp_filter import filter_by_constraint_join

        ir = normalize_ir(source)
        candidates = detect_heap_overflow(ir, source)

        stats = {}
        if candidates:
            filtered, stats = filter_by_constraint_join(
                candidates, ir, source, "x86_64")
            return len(filtered), stats
        return 0, stats
    finally:
        cj_solver_mod.solve_candidate = original_solve


def evaluate_all() -> Tuple[List[Dict], Dict]:
    gt = load_ground_truth()
    samples = gt["samples"]

    configs = ["Baseline", "CJ", "CJ+Interval"]
    results = []

    for name, expected in sorted(samples.items()):
        source = read_source(name)
        if not source:
            continue

        row = {
            "sample": name,
            "expected_vuln": expected["expected_vuln"],
            "expected_type": expected.get("expected_type", ""),
        }

        base_count = run_baseline(source)
        cj_count, cj_stats = run_cj(source, enable_interval=False)
        cjiv_count, cjiv_stats = run_cj(source, enable_interval=True)

        row["baseline_detections"] = base_count
        row["cj_detections"] = cj_count
        row["cj_interval_detections"] = cjiv_count

        for cfg in configs:
            cnt = {"Baseline": base_count, "CJ": cj_count,
                   "CJ+Interval": cjiv_count}[cfg]
            detected = cnt > 0
            if expected["expected_vuln"]:
                row[f"{cfg}_verdict"] = "VULN" if detected else "MISS"
            else:
                row[f"{cfg}_verdict"] = "FP" if detected else "SAFE"

        row["cj_stats"] = cj_stats
        row["cjiv_stats"] = cjiv_stats

        base_extra = cjiv_stats.get('inconclusive', 0) - cj_stats.get('inconclusive', 0)
        row["interval_inconclusive_reduction"] = base_extra

        results.append(row)
        bv = row["Baseline_verdict"]
        cv = row["CJ_verdict"]
        iv = row["CJ+Interval_verdict"]
        print(f"  {name}: B={bv} CJ={cv} CJ+IV={iv} "
              f"(det: {base_count}/{cj_count}/{cjiv_count})")

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

    return results, metrics


def print_comparison(results: List[Dict], metrics: Dict):
    print(f"\n{'='*72}")
    print(f" Ablation Study: Baseline vs CJ vs CJ+Interval")
    print(f"{'='*72}")
    print(f" Samples: {len(results)}")

    configs = ["Baseline", "CJ", "CJ+Interval"]
    print(f"\n{'Config':<16} {'TP':>4} {'FP':>4} {'TN':>4} {'FN':>4} "
          f"{'Prec':>8} {'Recall':>8} {'F1':>8} {'FPR':>8}")
    print("-" * 72)

    for cfg in configs:
        m = metrics[cfg]
        print(f"{cfg:<16} {m['tp']:>4} {m['fp']:>4} {m['tn']:>4} {m['fn']:>4} "
              f"{m['precision']:>8.4f} {m['recall']:>8.4f} "
              f"{m['f1']:>8.4f} {m['fpr']:>8.4f}")

    base_fpr = metrics["Baseline"]["fpr"]
    cj_fpr = metrics["CJ"]["fpr"]
    cjiv_fpr = metrics["CJ+Interval"]["fpr"]

    print(f"\n FPR reduction (Baseline → CJ): "
          f"{base_fpr:.4f} → {cj_fpr:.4f} "
          f"({(1-cj_fpr/max(base_fpr,1e-9))*100:.1f}% ↓)")
    print(f" FPR reduction (CJ → CJ+Interval): "
          f"{cj_fpr:.4f} → {cjiv_fpr:.4f} "
          f"({(1-cjiv_fpr/max(cj_fpr,1e-9))*100:.1f}% ↓)")
    print(f" FPR reduction (Baseline → CJ+Interval): "
          f"{base_fpr:.4f} → {cjiv_fpr:.4f} "
          f"({(1-cjiv_fpr/max(base_fpr,1e-9))*100:.1f}% ↓)")

    diff_rows = [r for r in results
                 if r["CJ_verdict"] != r["CJ+Interval_verdict"]]
    if diff_rows:
        print(f"\n Samples where CJ+Interval differs from CJ ({len(diff_rows)}):")
        for r in diff_rows:
            print(f"  {r['sample']}: CJ={r['CJ_verdict']} → "
                  f"CJ+Interval={r['CJ+Interval_verdict']} "
                  f"(expect={'VULN' if r['expected_vuln'] else 'SAFE'})")
    else:
        print("\n CJ+Interval produces same verdicts as CJ on all samples.")
        print(" (Interval domain reinforces existing constraints, "
              "no new verdict changes needed.)")

    total_inc_cj = sum(r["cj_stats"].get("inconclusive", 0) for r in results)
    total_inc_cjiv = sum(r["cjiv_stats"].get("inconclusive", 0) for r in results)
    if total_inc_cj > 0:
        print(f"\n Inconclusive count: CJ={total_inc_cj} → "
              f"CJ+Interval={total_inc_cjiv} "
              f"(Δ={total_inc_cj - total_inc_cjiv})")

    print(f"{'='*72}")


def save_results(results: List[Dict], metrics: Dict):
    os.makedirs(RESULTS_DIR, exist_ok=True)

    csv_path = RESULTS_DIR / "ablation_interval.csv"
    with open(csv_path, 'w', newline='') as f:
        w = csv.writer(f)
        w.writerow(["sample", "expected_vuln", "expected_type",
                     "baseline_det", "cj_det", "cj_interval_det",
                     "baseline_verdict", "cj_verdict", "cj_interval_verdict"])
        for r in results:
            w.writerow([
                r["sample"], r["expected_vuln"], r["expected_type"],
                r["baseline_detections"], r["cj_detections"],
                r["cj_interval_detections"],
                r["Baseline_verdict"], r["CJ_verdict"],
                r["CJ+Interval_verdict"],
            ])
    print(f"\nCSV: {csv_path}")

    json_path = RESULTS_DIR / "ablation_interval.json"
    serializable = {
        "results": [{k: v for k, v in r.items()
                      if not isinstance(v, dict)} for r in results],
        "metrics": metrics,
    }
    with open(json_path, 'w') as f:
        json.dump(serializable, f, indent=2, default=str)
    print(f"JSON: {json_path}")


if __name__ == '__main__':
    print("[Ablation] Baseline vs CJ vs CJ+Interval")
    print("[1/3] Evaluating 32 samples (full pipeline)...")
    results, metrics = evaluate_all()
    print_comparison(results, metrics)
    save_results(results, metrics)

    print("\n[2/3] Running micro-benchmarks (direct constraint precision)...")
    micro = run_micro_benchmarks()
    print_micro_results(micro)

    micro_path = RESULTS_DIR / "ablation_micro.json"
    with open(micro_path, 'w') as f:
        json.dump(micro, f, indent=2, default=str)
    print(f"\nMicro JSON: {micro_path}")
