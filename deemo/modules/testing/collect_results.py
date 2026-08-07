"""结果收集与对比模块 — 解析扫描结果, 计算检出率/误报率/漏报率.

每个测试样本有 ground truth 标签 (在 sample_labels.json 中).
对比实际检测结果与标签, 计算:
  - TP (真正例): 检测到且确实存在
  - FP (假正例): 检测到但实际不存在
  - FN (假负例): 未检测到但实际存在
  - Precision = TP / (TP + FP)
  - Recall = TP / (TP + FN)
  - F1 = 2 * P * R / (P + R)
"""

import argparse
import json
import os
import sys
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple


# 每个样本的 ground truth: 是否存在该类型漏洞
# 格式: {sample_name: {vuln_type: True/False}}
SAMPLE_LABELS = {
    "cve_2021_3156_sudo": {
        "heap_overflow": True, "uaf": False,
        "format_string": False, "integer_overflow": False,
        "desc": "size mismatch — confirmed heap overflow",
    },
    "cve_2019_13142_mongoose": {
        "heap_overflow": True, "uaf": False,
        "format_string": False, "integer_overflow": False,
        "desc": "off-by-one in HTTP parser",
    },
    "cve_off_by_one_malloc_001": {
        "heap_overflow": True, "uaf": False,
        "format_string": False, "integer_overflow": False,
        "desc": "malloc(n) + write at buf[n]",
    },
    "cve_size_mismatch_memcpy_002": {
        "heap_overflow": True, "uaf": False,
        "format_string": False, "integer_overflow": False,
        "desc": "malloc(fixed) + memcpy(variable)",
    },
    "cve_unbounded_strcpy_003": {
        "heap_overflow": True, "uaf": False,
        "format_string": False, "integer_overflow": False,
        "desc": "unbounded strcpy into heap buffer",
    },
    "cve_integer_overflow_alloc_004": {
        "heap_overflow": True, "uaf": False,
        "format_string": False, "integer_overflow": True,
        "desc": "integer overflow → tiny allocation",
    },
    "cve_nested_alloc_confusion_005": {
        "heap_overflow": True, "uaf": False,
        "format_string": False, "integer_overflow": False,
        "desc": "nested malloc with size confusion",
    },
    "cve_loop_bound_error_006": {
        "heap_overflow": True, "uaf": False,
        "format_string": False, "integer_overflow": False,
        "desc": "loop writes n ints into n bytes",
    },
    "cve_signed_unsigned_mismatch_007": {
        "heap_overflow": True, "uaf": False,
        "format_string": False, "integer_overflow": True,
        "desc": "negative size bypasses bounds check",
    },
    "cve_tlv_length_override_008": {
        "heap_overflow": True, "uaf": False,
        "format_string": False, "integer_overflow": False,
        "desc": "declared length < actual data",
    },
    "cve_chunk_metadata_corrupt_009": {
        "heap_overflow": True, "uaf": False,
        "format_string": False, "integer_overflow": False,
        "desc": "overflow into adjacent chunk metadata",
    },
    "cve_calloc_type_confusion_010": {
        "heap_overflow": True, "uaf": False,
        "format_string": False, "integer_overflow": False,
        "desc": "calloc(n,4) + memset(n*8)",
    },
    "cve_realloc_use_old_size_011": {
        "heap_overflow": True, "uaf": False,
        "format_string": False, "integer_overflow": False,
        "desc": "realloc shrink + memmove old size",
    },
    "cve_format_string_heap_012": {
        "heap_overflow": False, "uaf": False,
        "format_string": True, "integer_overflow": False,
        "desc": "user-controlled format string",
    },
    "cve_use_after_free_013": {
        "heap_overflow": False, "uaf": True,
        "format_string": False, "integer_overflow": False,
        "desc": "use after free via dangling pointer",
    },
    "cve_alignment_aware_014": {
        "heap_overflow": True, "uaf": False,
        "format_string": False, "integer_overflow": False,
        "desc": "access beyond chunk boundary",
    },
    "cve_double_free_015": {
        "heap_overflow": False, "uaf": True,
        "format_string": False, "integer_overflow": False,
        "desc": "same pointer freed twice",
    },
}


@dataclass
class MetricsByType:
    vuln_type: str
    tp: int = 0
    fp: int = 0
    fn: int = 0
    tn: int = 0

    @property
    def precision(self) -> float:
        denom = self.tp + self.fp
        return self.tp / denom if denom > 0 else 1.0

    @property
    def recall(self) -> float:
        denom = self.tp + self.fn
        return self.tp / denom if denom > 0 else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) > 0 else 0.0

    @property
    def fp_rate(self) -> float:
        denom = self.fp + self.tn
        return self.fp / denom if denom > 0 else 0.0


@dataclass
class FullReport:
    detector_name: str
    total_samples: int
    metrics: List[MetricsByType] = field(default_factory=list)
    per_sample: List[dict] = field(default_factory=list)
    total_elapsed_ms: float = 0.0


def load_labels(labels_path: str = "") -> dict:
    """加载 ground truth 标签."""
    if labels_path and os.path.isfile(labels_path):
        with open(labels_path, "r") as f:
            return json.load(f)
    return SAMPLE_LABELS


def collect_from_json(scan_json_path: str,
                      labels: dict = None) -> FullReport:
    """从 scan_results.json 收集并计算指标."""
    if labels is None:
        labels = SAMPLE_LABELS

    with open(scan_json_path, "r") as f:
        data = json.load(f)

    results = data.get("results", [])
    detector = results[0]["detector"] if results else "unknown"

    # 按样本和漏洞类型汇总
    # detected[sample][vuln_type] = bool
    detected: Dict[str, Dict[str, bool]] = {}
    for r in results:
        sample = r["sample"]
        if sample not in detected:
            detected[sample] = {"heap_overflow": False, "uaf": False,
                                "format_string": False, "integer_overflow": False}
        # 若该检测器报告了任何 heap_overflow → 标记
        if r.get("n_heap_overflow", 0) > 0:
            detected[sample]["heap_overflow"] = True
        if r.get("n_uaf", 0) > 0:
            detected[sample]["uaf"] = True
        if r.get("n_format_string", 0) > 0:
            detected[sample]["format_string"] = True
        if r.get("n_integer_overflow", 0) > 0:
            detected[sample]["integer_overflow"] = True

    # 计算各类型的 TP/FP/FN/TN
    vuln_types = ["heap_overflow", "uaf", "format_string", "integer_overflow"]
    metrics_list = []
    per_sample = []

    for vt in vuln_types:
        m = MetricsByType(vuln_type=vt)
        for sample, expected in labels.items():
            actual = detected.get(sample, {}).get(vt, False)
            is_vuln = expected.get(vt, False)

            if is_vuln and actual:
                m.tp += 1
            elif not is_vuln and actual:
                m.fp += 1
            elif is_vuln and not actual:
                m.fn += 1
            else:
                m.tn += 1

            per_sample.append({
                "sample": sample,
                "vuln_type": vt,
                "expected": is_vuln,
                "detected": actual,
                "status": ("TP" if is_vuln and actual else
                           "FP" if not is_vuln and actual else
                           "FN" if is_vuln and not actual else "TN"),
            })
        metrics_list.append(m)

    total_elapsed = sum(r.get("elapsed_ms", 0) for r in results)
    return FullReport(
        detector_name=detector,
        total_samples=len(data.get("results", [])),
        metrics=metrics_list,
        per_sample=per_sample,
        total_elapsed_ms=total_elapsed,
    )


def print_report(report: FullReport):
    """格式化打印报告."""
    print(f"\n{'='*70}")
    print(f"  Detection Report: {report.detector_name}")
    print(f"  Samples: {report.total_samples}")
    print(f"  Total Scan Time: {report.total_elapsed_ms:.0f}ms")
    print(f"{'='*70}")

    header = f"  {'Type':<22} {'TP':>4} {'FP':>4} {'FN':>4} {'TN':>4} {'Prec':>6} {'Recall':>6} {'F1':>6}"
    print(header)
    print(f"  {'-'*66}")

    for m in report.metrics:
        print(f"  {m.vuln_type:<22} {m.tp:>4} {m.fp:>4} {m.fn:>4} {m.tn:>4} "
              f"{m.precision:>6.2f} {m.recall:>6.2f} {m.f1:>6.2f}")

    print(f"  {'-'*66}")

    # 汇总 (仅 heap_overflow — 主打指标)
    ho = next((m for m in report.metrics
               if m.vuln_type == "heap_overflow"), None)
    if ho:
        print(f"\n  ** Heap Overflow (Primary Metric):")
        print(f"     Precision: {ho.precision:.2%}")
        print(f"     Recall:    {ho.recall:.2%}")
        print(f"     F1:        {ho.f1:.2%}")
        print(f"     FP Rate:   {ho.fp_rate:.2%} "
              f"({ho.fp}/{ho.fp + ho.tn})")


def export_csv(report: FullReport, output_path: str):
    """导出为 CSV."""
    import csv
    with open(output_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["detector", "vuln_type", "tp", "fp", "fn", "tn",
                         "precision", "recall", "f1", "fp_rate"])
        for m in report.metrics:
            writer.writerow([report.detector_name, m.vuln_type,
                            m.tp, m.fp, m.fn, m.tn,
                            round(m.precision, 4), round(m.recall, 4),
                            round(m.f1, 4), round(m.fp_rate, 4)])


def main():
    parser = argparse.ArgumentParser(
        description="Collect and analyze scan results")
    parser.add_argument("--scan-results", default=None,
                        help="Path to scan_results.json")
    parser.add_argument("--labels", default=None,
                        help="Path to sample_labels.json")
    parser.add_argument("--output-csv", default=None,
                        help="Export metrics to CSV")
    parser.add_argument("--output-report", default=None,
                        help="Export full report to JSON")
    args = parser.parse_args()

    scan_path = args.scan_results or os.path.join(
        os.path.dirname(__file__), "scan_results.json")

    if not os.path.isfile(scan_path):
        print(f"[!] scan results not found: {scan_path}")
        print("[*] run 'python run_scanner.py' first to generate results")
        return 1

    labels = load_labels(args.labels)
    report = collect_from_json(scan_path, labels)
    print_report(report)

    if args.output_csv:
        export_csv(report, args.output_csv)
        print(f"[*] CSV exported to {args.output_csv}")

    if args.output_report:
        import json as _json
        report_data = {
            "detector": report.detector_name,
            "total_samples": report.total_samples,
            "total_elapsed_ms": report.total_elapsed_ms,
            "metrics": [
                {"type": m.vuln_type, "tp": m.tp, "fp": m.fp, "fn": m.fn,
                 "tn": m.tn, "precision": round(m.precision, 4),
                 "recall": round(m.recall, 4), "f1": round(m.f1, 4)}
                for m in report.metrics
            ],
        }
        with open(args.output_report, "w") as f:
            _json.dump(report_data, f, indent=2)
        print(f"[*] Report exported to {args.output_report}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
