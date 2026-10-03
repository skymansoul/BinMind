# 结果解析——对比检出结果与ground truth, 计算检出率/误报率/漏报率
# 输出: build/report.json + 终端汇总表

import json
import sys
from pathlib import Path
from dataclasses import dataclass, asdict
from typing import List, Dict, Optional
from collections import defaultdict

BUILD_ROOT = Path(__file__).parent / "build"

# ground truth: 每个CVE样本的预期漏洞类型
GROUND_TRUTH = {
    "CVE-2014-0160_heartbleed":          {"vuln_type": "buffer_overflow", "has_vuln": True},
    "CVE-2015-7547_glibc_getaddrinfo":   {"vuln_type": "buffer_overflow", "has_vuln": True},
    "CVE-2016-6309_openssl_uaf":         {"vuln_type": "use_after_free",   "has_vuln": True},
    "CVE-2017-13089_wget_overflow":      {"vuln_type": "buffer_overflow", "has_vuln": True},
    "CVE-2018-1000001_glibc_realpath":   {"vuln_type": "buffer_overflow", "has_vuln": True},
    "CVE-2019-12900_bzip2_uaf":          {"vuln_type": "use_after_free",   "has_vuln": True},
    "CVE-2020-10713_grub2_overflow":     {"vuln_type": "buffer_overflow", "has_vuln": True},
    "CVE-2021-3156_sudo_heapoverflow":   {"vuln_type": "buffer_overflow", "has_vuln": True},
    "CVE-2022-3602_spider_overflow":     {"vuln_type": "buffer_overflow", "has_vuln": True},
    "CVE-2023-38545_curl_heap":          {"vuln_type": "buffer_overflow", "has_vuln": True},
    "CVE-2024-6387_regreSSHion":         {"vuln_type": "use_after_free",   "has_vuln": True},
}


@dataclass
class AggregatedReport:
    total_samples: int
    total_scans: int             # samples * opt_levels
    true_positives: int
    false_positives: int
    false_negatives: int
    true_negatives: int
    detection_rate: float        # TP / (TP + FN) = 召回率
    false_positive_rate: float   # FP / (FP + TN)
    avg_scan_time_ms: float
    avg_peak_memory_kb: int
    by_vuln_type: Dict[str, Dict[str, float]]
    by_opt_level: Dict[str, Dict[str, float]]
    per_sample: List[Dict]


def load_scan_results() -> List[Dict]:
    """加载所有scan_result.json"""
    results = []
    if not BUILD_ROOT.exists():
        return results
    for path in sorted(BUILD_ROOT.rglob("scan_result.json")):
        with open(path) as f:
            results.append(json.load(f))
    return results


def compute_metrics(results: List[Dict]) -> AggregatedReport:
    """计算检出率/误报率等核心指标"""
    tp = fp = fn = tn = 0
    total_time = 0.0
    total_mem = 0
    by_vuln: Dict[str, Dict[str, int]] = defaultdict(lambda: {"tp": 0, "fn": 0, "count": 0})
    by_opt: Dict[str, Dict[str, int]] = defaultdict(lambda: {"tp": 0, "fn": 0, "count": 0})
    per_sample = []

    for r in results:
        sample = r.get("sample_name", "")
        gt = GROUND_TRUTH.get(sample, {"vuln_type": "unknown", "has_vuln": True})
        expected_type = gt["vuln_type"]
        has_vuln = gt["has_vuln"]
        detected = r.get("detected", False)
        detected_type = r.get("detected_type", "")
        opt = r.get("opt_level", "O0")

        by_vuln[expected_type]["count"] += 1
        by_opt[opt]["count"] += 1

        if has_vuln and detected:
            # 类型匹配→TP; 类型不匹配→标记但算FN(检出错误类型)
            if detected_type == expected_type or not detected_type:
                tp += 1
                by_vuln[expected_type]["tp"] += 1
                by_opt[opt]["tp"] += 1
        elif has_vuln and not detected:
            fn += 1
            by_vuln[expected_type]["fn"] += 1
            by_opt[opt]["fn"] += 1
        elif not has_vuln and detected:
            fp += 1
        else:
            tn += 1

        total_time += r.get("scan_time_ms", 0)
        total_mem = max(total_mem, r.get("peak_memory_kb", 0))

        per_sample.append({
            "sample": sample,
            "opt": opt,
            "expected": expected_type,
            "detected": detected,
            "detected_type": detected_type,
            "confidence": r.get("confidence", 0),
            "correct": has_vuln and detected and detected_type == expected_type,
        })

    n = len(results)
    det_rate = tp / max(1, tp + fn)
    fp_rate = fp / max(1, fp + tn)
    avg_time = total_time / max(1, n)

    # 按漏洞类型的指标
    vuln_metrics = {}
    for vtype, counts in by_vuln.items():
        vuln_metrics[vtype] = {
            "detection_rate": counts["tp"] / max(1, counts["count"]),
            "missed": counts["fn"],
            "total": counts["count"],
        }

    # 按优化级别的指标
    opt_metrics = {}
    for opt, counts in by_opt.items():
        opt_metrics[opt] = {
            "detection_rate": counts["tp"] / max(1, counts["count"]),
            "missed": counts["fn"],
            "total": counts["count"],
        }

    return AggregatedReport(
        total_samples=len(GROUND_TRUTH),
        total_scans=n,
        true_positives=tp, false_positives=fp,
        false_negatives=fn, true_negatives=tn,
        detection_rate=det_rate,
        false_positive_rate=fp_rate,
        avg_scan_time_ms=avg_time,
        avg_peak_memory_kb=int(total_mem),
        by_vuln_type=vuln_metrics,
        by_opt_level=opt_metrics,
        per_sample=per_sample)


def print_table(report: AggregatedReport):
    """打印终端汇总表"""
    print()
    print("=" * 72)
    print("  回归测试报告")
    print("=" * 72)
    print(f"  样本数:      {report.total_samples}")
    print(f"  扫描数:      {report.total_scans} (O0+O3各一次)")
    print(f"  检出率:      {report.detection_rate:.1%}  (TP/(TP+FN))")
    print(f"  误报率:      {report.false_positive_rate:.1%}")
    print(f"  真正例(TP):  {report.true_positives}")
    print(f"  假正例(FP):  {report.false_positives}")
    print(f"  假负例(FN):  {report.false_negatives}")
    print(f"  平均耗时:    {report.avg_scan_time_ms:.0f}ms")
    print(f"  峰值内存:    {report.avg_peak_memory_kb // 1024}MB")
    print("-" * 72)
    print(f"  {'漏洞类型':<20} {'检出率':>8} {'漏报':>6}")
    for vtype, m in sorted(report.by_vuln_type.items()):
        print(f"  {vtype:<20} {m['detection_rate']:>7.1%} {m['missed']:>5}")
    print("-" * 72)
    print(f"  {'优化级别':<20} {'检出率':>8} {'漏报':>6}")
    for opt, m in sorted(report.by_opt_level.items()):
        print(f"  {opt:<20} {m['detection_rate']:>7.1%} {m['missed']:>5}")
    print("=" * 72)


def main():
    results = load_scan_results()
    if not results:
        print("无扫描结果——请先运行 scan_runner.py")
        sys.exit(1)

    report = compute_metrics(results)
    print_table(report)

    # 写JSON报告
    report_path = BUILD_ROOT / "report.json"
    with open(report_path, 'w') as f:
        json.dump(asdict(report), f, indent=2)
    print(f"\n完整报告: {report_path}")
    return 0


if __name__ == '__main__':
    sys.exit(main())
