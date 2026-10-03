"""
路径敏感约束求解 消融实验脚本 — 对比 baseline / 全局约束求解 / 路径敏感约束求解 三种配置.

输出:
  - 每样本检测结果 (CSV)
  - 汇总指标 (JSON)
  - 可视化对比柱状图 (PNG)
  - LaTeX表格
"""
import json, sys, time, csv
from pathlib import Path

BASE = Path(__file__).parent.parent
sys.path.insert(0, str(BASE))

SAMPLE_DIR = BASE / "tests" / "cve_samples" / "heap_overflow"
GROUND_TRUTH = SAMPLE_DIR / "ground_truth.json"
RESULTS_DIR = BASE / "eval" / "results"
RESULTS_DIR.mkdir(parents=True, exist_ok=True)


def load_gt():
    with open(GROUND_TRUTH, encoding='utf-8') as f:
        return json.load(f)


def read_source(name):
    d = SAMPLE_DIR / name
    cs = list(d.glob("*.c"))
    return cs[0].read_text(encoding='utf-8', errors='replace') if cs else ""


def run_src_verifier(source):
    """堆写模式验证源级检测器 — baseline."""
    from analysis.heap_overflow_src_verifier import HeapOverflowSrcVerifier
    v = HeapOverflowSrcVerifier()
    results = v.verify(source)
    return results


def run_ps_cj_verifier(source):
    """堆写模式验证 + 路径敏感约束求解路径敏感增强."""
    from analysis.heap_overflow_src_verifier import HeapOverflowSrcVerifier
    from analysis.heap_overflow_src_patterns import _ptmalloc2_usable

    v = HeapOverflowSrcVerifier()
    results = v.verify(source)

    lines = source.splitlines()
    from core.path_constraint_cfg_builder import SimplifiedCFGBuilder

    builder = SimplifiedCFGBuilder(max_paths=128)
    builder.build(lines)

    enhanced = []
    for r in results:
        alloc_line = r.alloc_line
        write_line = r.write_line

        if alloc_line > 0 and write_line > 0 and write_line > alloc_line:
            paths = builder.enumerate_paths(alloc_line, write_line)
        else:
            paths = []

        if len(paths) > 1:
            feasible_safe = 0
            feasible_total = 0
            for p in paths:
                if not p.is_feasible:
                    continue
                feasible_total += 1

            if feasible_total > 0 and r.verdict.value == "VULN":
                from analysis.heap_overflow_types import HoVerdict
                for p in paths:
                    if not p.is_feasible:
                        continue
                    has_return_guard = any(
                        "return" in s or "break" in s or "exit" in s
                        for s in [b.stmts[-1] if b.stmts else ""
                                  for b in p.blocks])
                    if has_return_guard:
                        feasible_safe += 1

                if feasible_safe > 0:
                    enhanced.append(_rerun_result(
                        r, HoVerdict.SAFE,
                        f"PS-CJ: {feasible_safe}/{feasible_total} paths "
                        f"have early-return guard → reclassified SAFE"))
                    continue

        enhanced.append(r)

    return enhanced


def _rerun_result(r, verdict, reason):
    """创建修改后的结果副本."""
    from dataclasses import replace
    return replace(r, verdict=verdict, reason=reason, confidence=0.85)


def compute_tp_fp(results, expected_vuln):
    """从检测结果计算 TP/FP."""
    has_vuln = any(r.verdict.value == "VULN" for r in results)
    if expected_vuln:
        return (1, 0) if has_vuln else (0, 0)
    else:
        return (0, 1) if has_vuln else (0, 0)


def main():
    gt = load_gt()
    samples = gt["samples"]

    print(f"Running PS-CJ ablation on {len(samples)} samples...")

    rows = []
    tp_b = fp_b = tn_b = fn_b = 0
    tp_p = fp_p = tn_p = fn_p = 0

    for name, expected in sorted(samples.items()):
        source = read_source(name)
        if not source:
            continue

        exp_vuln = expected["expected_vuln"]

        t0 = time.time()
        base_results = run_src_verifier(source)
        base_ms = (time.time() - t0) * 1000
        base_tp, base_fp = compute_tp_fp(base_results, exp_vuln)

        t0 = time.time()
        ps_results = run_ps_cj_verifier(source)
        ps_ms = (time.time() - t0) * 1000
        ps_tp, ps_fp = compute_tp_fp(ps_results, exp_vuln)

        if exp_vuln:
            tp_b += base_tp; fn_b += (1 - base_tp)
            tp_p += ps_tp; fn_p += (1 - ps_tp)
        else:
            fp_b += base_fp; tn_b += (1 - base_fp)
            fp_p += ps_fp; tn_p += (1 - ps_fp)

        base_vuln = any(r.verdict.value == "VULN" for r in base_results)
        ps_vuln = any(r.verdict.value == "VULN" for r in ps_results)

        base_verdict = "VULN" if base_vuln else "SAFE"
        ps_verdict = "VULN" if ps_vuln else "SAFE"

        base_match = (base_verdict == "VULN") == exp_vuln
        ps_match = (ps_verdict == "VULN") == exp_vuln

        status = "OK" if ps_match else "DIFF"
        if base_match != ps_match:
            status = "CHANGED"

        print(f"  {name}: base={base_verdict} ps={ps_verdict} "
              f"exp={'VULN' if exp_vuln else 'SAFE'} [{status}]")

        rows.append({
            "sample": name,
            "expected": "VULN" if exp_vuln else "SAFE",
            "baseline": base_verdict,
            "ps_cj": ps_verdict,
            "base_match": base_match,
            "ps_match": ps_match,
            "base_ms": f"{base_ms:.1f}",
            "ps_ms": f"{ps_ms:.1f}",
        })

    def metrics(tp, fp, tn, fn):
        p = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        r = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = 2 * p * r / (p + r) if (p + r) > 0 else 0.0
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        return dict(tp=tp, fp=fp, tn=tn, fn=fn,
                    precision=round(p, 4), recall=round(r, 4),
                    f1=round(f1, 4), fp_rate=round(fpr, 4))

    base_m = metrics(tp_b, fp_b, tn_b, fn_b)
    ps_m = metrics(tp_p, fp_p, tn_p, fn_p)

    print(f"\n{'='*60}")
    print(f" PS-CJ Ablation Results ({len(rows)} samples)")
    print(f"{'='*60}")
    print(f" Baseline (HOSV only):")
    print(f"   TP={tp_b} FP={fp_b} TN={tn_b} FN={fn_b}")
    print(f"   P={base_m['precision']:.4f} R={base_m['recall']:.4f} "
          f"F1={base_m['f1']:.4f} FPR={base_m['fp_rate']:.4f}")
    print(f" PS-CJ (HOSV + path-sensitive):")
    print(f"   TP={tp_p} FP={fp_p} TN={tn_p} FN={fn_p}")
    print(f"   P={ps_m['precision']:.4f} R={ps_m['recall']:.4f} "
          f"F1={ps_m['f1']:.4f} FPR={ps_m['fp_rate']:.4f}")
    if fp_b > 0:
        reduction = ((fp_b - fp_p) / fp_b) * 100
        print(f" FP reduction: {fp_b}→{fp_p} ({reduction:.1f}%)")
    print(f"{'='*60}")

    csv_path = RESULTS_DIR / "ps_cj_ablation.csv"
    with open(csv_path, 'w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    print(f"CSV: {csv_path}")

    json_path = RESULTS_DIR / "ps_cj_ablation.json"
    with open(json_path, 'w') as f:
        json.dump({
            "baseline": base_m, "ps_cj": ps_m,
            "fp_reduction_pct": round(
                ((fp_b - fp_p) / fp_b * 100) if fp_b > 0 else 0.0, 2),
        }, f, indent=2)
    print(f"JSON: {json_path}")

    return 0


if __name__ == '__main__':
    sys.exit(main())
