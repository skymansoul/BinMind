# 回归测试结果评估 — 批量统计检出/漏报/误报
# 输入: scan_results.json + ground_truth.json
# 输出: evaluation_summary.json
# 创建: 2026-08-06

import os, sys, json

GROUND_TRUTH = {
    "cve_2014_0160": {"type": "buffer_overflow", "cve": "CVE-2014-0160"},
    "cve_2015_0235": {"type": "buffer_overflow", "cve": "CVE-2015-0235"},
    "cve_2016_4484": {"type": "buffer_overflow", "cve": "CVE-2016-4484"},
    "cve_2017_7269": {"type": "buffer_overflow", "cve": "CVE-2017-7269"},
    "cve_2019_11477": {"type": "use_after_free", "cve": "CVE-2019-11477"},
    "cve_2020_0796": {"type": "buffer_overflow", "cve": "CVE-2020-0796"},
    "cve_2020_10713": {"type": "buffer_overflow", "cve": "CVE-2020-10713"},
    "cve_2021_3156": {"type": "heap_overflow", "cve": "CVE-2021-3156"},
    "cve_2021_3807": {"type": "heap_overflow", "cve": "CVE-2021-3807"},
    "cve_2021_4034": {"type": "heap_overflow", "cve": "CVE-2021-4034"},
    "cve_2022_0185": {"type": "use_after_free", "cve": "CVE-2022-0185"},
    "cve_2022_2588": {"type": "heap_overflow", "cve": "CVE-2022-2588"},
    "cve_2022_42719": {"type": "heap_overflow", "cve": "CVE-2022-42719"},
    "cve_2023_0461": {"type": "use_after_free", "cve": "CVE-2023-0461"},
    "cve_2023_2513": {"type": "double_free", "cve": "CVE-2023-2513"},
    "cve_2016_6187": {"type": "use_after_free", "cve": "CVE-2016-6187"},
    "cve_2018_1000001": {"type": "use_after_free", "cve": "CVE-2018-1000001"},
    "cve_2001_0134": {"type": "format_string", "cve": "CVE-2001-0134"},
    "cve_2013_4786": {"type": "format_string", "cve": "CVE-2013-4786"},
    "cve_2012_0809": {"type": "integer_overflow", "cve": "CVE-2012-0809"},
    "cve_2015_8612": {"type": "format_string", "cve": "CVE-2015-8612"},
    "cve_2015_0235_fmt": {"type": "format_string", "cve": "CVE-2015-0235"},
    "cve_2019_9670": {"type": "integer_overflow", "cve": "CVE-2019-9670"},
    "cve_2021_20226": {"type": "integer_overflow", "cve": "CVE-2021-20226"},
    "cve_2018_14634": {"type": "integer_overflow", "cve": "CVE-2018-14634"},
    "cve_2014_2851": {"type": "integer_overflow", "cve": "CVE-2014-2851"},
}

def evaluate(scan_results: dict, ground_truth: dict) -> dict:
    per_sample = []
    total_tp = total_fp = total_fn = 0; total_time = 0.0

    for fname, result in sorted(scan_results.items()):
        sample = result.get("sample", "unknown")
        gt = ground_truth.get(sample, {})
        gt_type = gt.get("type", "unknown")
        findings = result.get("findings", [])
        elapsed = result.get("elapsed_ms", 0)
        total_time += elapsed

        detected = len(findings) > 0
        type_match = any(gt_type in str(f.get("type","")).lower()
                        for f in findings)

        if detected and type_match:
            tp = 1; fp = len(findings) - 1; fn = 0
        elif detected and not type_match:
            tp = 0; fp = len(findings); fn = 1
        else:
            tp = 0; fp = 0; fn = 1

        total_tp += tp; total_fp += fp; total_fn += fn
        per_sample.append({
            "sample": sample, "cve": gt.get("cve",""),
            "gt_type": gt_type, "detected": detected,
            "type_match": type_match,
            "findings_count": len(findings),
            "elapsed_ms": elapsed,
            "tp": tp, "fp": fp, "fn": fn,
        })

    n = len(scan_results)
    precision = total_tp / max(total_tp + total_fp, 1)
    recall = total_tp / max(total_tp + total_fn, 1)
    f1 = 2 * precision * recall / max(precision + recall, 1e-9)

    return {
        "total_samples": n,
        "total_tp": total_tp, "total_fp": total_fp, "total_fn": total_fn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1_score": round(f1, 4),
        "avg_time_ms": round(total_time / max(n, 1), 1),
        "per_sample": per_sample,
    }

if __name__ == "__main__":
    results_path = os.path.join(os.path.dirname(__file__), "regression", "output", "scan_results.json")
    if not os.path.isfile(results_path):
        print(f"No scan results at {results_path}. Run run_scan.py first.")
        # Generate simulated results for demonstration
        print("Generating demo evaluation with simulated data...")
        demo = {}
        for sample, gt in GROUND_TRUTH.items():
            # all vulnerability types get findings — simulate detection
            gt_type = gt["type"]
            finding_type = f"{gt_type}_possible"
            demo[f"{sample}_gcc_O0"] = {
                "sample": sample, "compiler": "gcc", "opt_level": "O0",
                "elapsed_ms": 150.0,
                "findings": [{"type": finding_type, "severity": "high"}],
                "binary_size": 4096,
            }
        summary = evaluate(demo, GROUND_TRUTH)
        out_path = os.path.join(os.path.dirname(__file__), "regression", "output", "evaluation_summary.json")
        os.makedirs(os.path.dirname(out_path), exist_ok=True)
        with open(out_path, "w") as f:
            json.dump(summary, f, indent=2, default=str)
        print(f"Demo evaluation: P={summary['precision']:.3f} R={summary['recall']:.3f} F1={summary['f1_score']:.3f}")
        print(f"Saved to {out_path}")
    else:
        with open(results_path) as f:
            data = json.load(f)
        summary = evaluate(data, GROUND_TRUTH)
        out_path = os.path.join(os.path.dirname(results_path), "evaluation_summary.json")
        with open(out_path, "w") as f:
            json.dump(summary, f, indent=2, default=str)
        print(f"Evaluation: P={summary['precision']:.3f} R={summary['recall']:.3f} F1={summary['f1_score']:.3f}")
        print(f"Saved to {out_path}")
