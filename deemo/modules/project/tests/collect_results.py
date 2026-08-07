# 结果收集与对比模块: 汇总扫描结果, 计算召回率/误报率/漏报率
from __future__ import annotations
import json, csv, time
from pathlib import Path
from dataclasses import dataclass, field
from typing import Dict, List, Optional
from .run_scanner import ScanResult


@dataclass
class TestSummary:
    total_samples: int
    true_positives: int       # 检出且确实有漏洞
    false_positives: int      # 检出但实际安全
    true_negatives: int       # 未检出且实际安全
    false_negatives: int      # 未检出但确实有漏洞
    errors: int               # 扫描失败
    recall: float             # TP / (TP + FN)
    precision: float          # TP / (TP + FP)
    false_positive_rate: float  # FP / (FP + TN)
    total_time_ms: float
    avg_time_ms: float
    per_sample: List[Dict]


class ResultCollector:
    """结果收集器.

    汇总ScanResult列表, 计算统计指标, 生成报告.
    """

    def __init__(self):
        self._results: List[ScanResult] = []

    def collect(self, results: List[ScanResult]):
        self._results = results

    def compute_metrics(self) -> TestSummary:
        """计算召回率/精确率/误报率."""
        tp = fp = tn = fn = errors = 0
        per_sample = []
        total_time = 0.0

        for r in self._results:
            entry = {
                "sample": r.sample_name,
                "expected_vuln": r.expected_vulnerable,
                "detected": r.detected,
                "num_findings": r.num_findings,
                "scan_time_ms": round(r.scan_time_ms, 1),
                "success": r.success,
                "error": r.error_msg[:100] if r.error_msg else "",
            }
            per_sample.append(entry)
            total_time += r.scan_time_ms

            if not r.success:
                errors += 1
                continue
            if r.expected_vulnerable and r.detected and not r.is_false_positive:
                tp += 1
                entry["status"] = "TP"
            elif r.expected_vulnerable and not r.detected:
                fn += 1
                entry["status"] = "FN"
            elif not r.expected_vulnerable and r.detected:
                fp += 1
                entry["status"] = "FP"
            elif not r.expected_vulnerable and not r.detected:
                tn += 1
                entry["status"] = "TN"

        total_valid = tp + fp + tn + fn
        recall = tp / max(tp + fn, 1)
        precision = tp / max(tp + fp, 1)
        fpr = fp / max(fp + tn, 1)

        return TestSummary(
            total_samples=len(self._results),
            true_positives=tp, false_positives=fp,
            true_negatives=tn, false_negatives=fn,
            errors=errors, recall=recall, precision=precision,
            false_positive_rate=fpr,
            total_time_ms=total_time,
            avg_time_ms=total_time / max(len(self._results), 1),
            per_sample=per_sample)

    def print_report(self, summary: TestSummary):
        """打印格式化的测试报告."""
        print("\n" + "=" * 62)
        print("  HEAP OVERFLOW DETECTION — REGRESSION TEST REPORT")
        print("=" * 62)
        print(f"  Samples: {summary.total_samples} | "
              f"Errors: {summary.errors}")
        print(f"  TP={summary.true_positives}  FP={summary.false_positives}  "
              f"TN={summary.true_negatives}  FN={summary.false_negatives}")
        print(f"  Recall (检出率):    {summary.recall:.1%}")
        print(f"  Precision (精确率): {summary.precision:.1%}")
        print(f"  FPR (误报率):       {summary.false_positive_rate:.1%}")
        print(f"  Avg scan time:      {summary.avg_time_ms:.0f}ms")
        print(f"  Total time:         {summary.total_time_ms:.0f}ms")
        print("-" * 62)
        for entry in summary.per_sample:
            emoji = {"TP": "+", "FP": "!", "TN": "-", "FN": "?"}.get(
                entry.get("status", ""), " ")
            print(f"  [{emoji}] {entry['sample']:<35s} "
                  f"{entry['num_findings']} finding(s) "
                  f"({entry['scan_time_ms']:.0f}ms)")
            if entry.get("error"):
                print(f"       Error: {entry['error']}")
        print("=" * 62)

    def export_json(self, summary: TestSummary, path: str):
        """导出JSON格式的完整报告."""
        data = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "metrics": {
                "total": summary.total_samples,
                "TP": summary.true_positives,
                "FP": summary.false_positives,
                "TN": summary.true_negatives,
                "FN": summary.false_negatives,
                "errors": summary.errors,
                "recall": round(summary.recall, 4),
                "precision": round(summary.precision, 4),
                "fpr": round(summary.false_positive_rate, 4),
                "avg_time_ms": round(summary.avg_time_ms, 1),
            },
            "per_sample": summary.per_sample,
        }
        with open(path, 'w') as f:
            json.dump(data, f, indent=2)

    def export_csv(self, summary: TestSummary, path: str):
        """导出CSV格式."""
        with open(path, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=[
                "sample", "expected_vuln", "detected", "status",
                "num_findings", "scan_time_ms", "error"])
            writer.writeheader()
            for entry in summary.per_sample:
                writer.writerow(entry)

    def export_summary_md(self, summary: TestSummary, path: str):
        """导出Markdown格式的总结报告."""
        lines = [
            "# Heap Overflow Detection — Regression Test Report",
            "",
            f"**Date:** {time.strftime('%Y-%m-%d %H:%M:%S')}",
            "",
            "## Summary Metrics",
            "",
            f"| Metric | Value |",
            f"|--------|-------|",
            f"| Total Samples | {summary.total_samples} |",
            f"| True Positives (TP) | {summary.true_positives} |",
            f"| False Positives (FP) | {summary.false_positives} |",
            f"| True Negatives (TN) | {summary.true_negatives} |",
            f"| False Negatives (FN) | {summary.false_negatives} |",
            f"| Errors | {summary.errors} |",
            f"| **Recall** | **{summary.recall:.1%}** |",
            f"| **Precision** | **{summary.precision:.1%}** |",
            f"| **FPR** | **{summary.false_positive_rate:.1%}** |",
            f"| Avg Scan Time | {summary.avg_time_ms:.0f}ms |",
            "",
            "## Per-Sample Results",
            "",
            "| Status | Sample | Findings | Time (ms) |",
            "|--------|--------|----------|-----------|",
        ]
        for entry in summary.per_sample:
            lines.append(
                f"| {entry.get('status','?')} | {entry['sample']} | "
                f"{entry['num_findings']} | {entry['scan_time_ms']:.0f} |")
        with open(path, 'w') as f:
            f.write('\n'.join(lines))


def run_full_pipeline(samples_root: str, output_dir: str = "."):
    """一键运行完整测试管道: 编译→扫描→收集→报告."""
    from .compile_samples import SampleCompiler
    from .run_scanner import SampleScanner

    print("=" * 50)
    print("PHASE 1: Compiling samples...")
    compiler = SampleCompiler(samples_root)
    comp_results = compiler.compile_all()
    print(compiler.summary(comp_results))

    print("\nPHASE 2: Scanning binaries...")
    scanner = SampleScanner()
    binaries = {}
    for cr in comp_results:
        if cr.success:
            # 判断是否为安全样本 (15号)
            is_vuln = "safe_write" not in cr.sample_dir
            binaries[cr.sample_dir] = (cr.binary_path, is_vuln)
    scan_results = scanner.scan_all(binaries)

    print("\nPHASE 3: Collecting results...")
    collector = ResultCollector()
    collector.collect(scan_results)
    summary = collector.compute_metrics()
    collector.print_report(summary)

    # 导出
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    collector.export_json(summary, str(out / "test_results.json"))
    collector.export_csv(summary, str(out / "test_results.csv"))
    collector.export_summary_md(summary, str(out / "test_results.md"))
    print(f"\nReports exported to {output_dir}/")
    return summary
