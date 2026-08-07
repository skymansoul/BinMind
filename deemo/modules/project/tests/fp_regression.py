# FP-Reduction 回归测试编排: 一键 编译→扫描→收集 全流程
# 复用既有模块 (功能只增不减):
#   编译 = tests.compile_samples.SampleCompiler
#   扫描 = tests.run_scanner.SampleScanner
#   收集 = tests.collect_results.ResultCollector
# 本脚本职责: 样本 ground truth 定义 + 双模式 (FP抑制开/关) 扫描调度
#   + 指标对比报告 (Recall/Precision/FPR/FP Reduction)
# 决策: 不复制任何既有逻辑, 只做编排与对比口径
from __future__ import annotations
import sys
import io
import json
import time
import pathlib
from typing import Dict, List, Tuple

if sys.platform == 'win32':
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

_PROJ_ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJ_ROOT))

from tests.compile_samples import SampleCompiler
from tests.run_scanner import SampleScanner, ScanResult
from tests.collect_results import ResultCollector, TestSummary

# fp_samples ground truth: 漏洞样本 vs 安全样本
_HEAP_SAMPLES = [f"fp_heap{i:02d}" for i in range(1, 16)]
_SAFE_SAMPLES = [f"fp_safe{i:02d}" for i in range(1, 11)]


class FpRegressionRunner:
    """FP-Reduction 回归测试编排器."""

    def __init__(self, samples_root: str = "fp_samples",
                 build_dir: str = "fp_samples/build"):
        self._root = pathlib.Path(samples_root)
        self._build = pathlib.Path(build_dir)
        self._build.mkdir(parents=True, exist_ok=True)

    def _expected_vuln(self, name: str) -> bool:
        return name in _HEAP_SAMPLES

    def compile_all(self) -> Dict[str, str]:
        """编译全部样本, 返回 {样本名: 二进制路径}."""
        compiler = SampleCompiler(str(self._root))
        results = compiler.compile_all()
        binaries = {}
        for r in results:
            if r.success:
                binaries[r.sample_dir] = r.binary_path
            else:
                print(f"  [FAIL] {r.sample_dir}: {r.error_msg[:100]}")
        return binaries

    def scan_mode(self, binaries: Dict[str, str],
                  fp_reduction: bool) -> List[ScanResult]:
        """以指定模式扫描全部样本."""
        scanner = SampleScanner(use_advanced_engine=True)
        results = []
        for name, path in sorted(binaries.items()):
            t0 = time.perf_counter()
            scanner._detector = None
            if scanner._use_engine:
                from analysis.heap_overflow_detector import (
                    HeapOverflowDetector)
                det = HeapOverflowDetector()
                det._fp_reduction_enabled = fp_reduction
                scanner._detector = det
            result = scanner.scan_one(name, path, self._expected_vuln(name))
            result.scan_time_ms = (time.perf_counter() - t0) * 1000
            results.append(result)
        return results

    def summarize(self, results: List[ScanResult]) -> TestSummary:
        collector = ResultCollector()
        collector.collect(results)
        return collector.compute_metrics()

    def run(self) -> Dict:
        """完整回归: 编译 → 双模式扫描 → 对比报告."""
        print("=" * 66)
        print("  FP-Reduction 回归测试 (fp_samples)")
        print("=" * 66)

        print("\n[1/4] 编译样本...")
        binaries = self.compile_all()
        print(f"  编译成功: {len(binaries)}/{len(_HEAP_SAMPLES) + len(_SAFE_SAMPLES)}")

        print("\n[2/4] 扫描 (FP 抑制开启)...")
        results_on = self.scan_mode(binaries, fp_reduction=True)
        summary_on = self.summarize(results_on)

        print("\n[3/4] 扫描 (FP 抑制关闭, 基线)...")
        results_off = self.scan_mode(binaries, fp_reduction=False)
        summary_off = self.summarize(results_off)

        print("\n[4/4] 对比报告...")
        report = self._report(summary_on, summary_off, results_on,
                              results_off)
        return report

    def _report(self, on: TestSummary, off: TestSummary,
                results_on: List[ScanResult],
                results_off: List[ScanResult]) -> Dict:
        def f1(tp, fp, fn):
            return 2 * tp / max(2 * tp + fp + fn, 1)
        f1_on = f1(on.true_positives, on.false_positives, on.false_negatives)
        f1_off = f1(off.true_positives, off.false_positives,
                    off.false_negatives)
        print("\n" + "=" * 66)
        print("  指标对比 (FP抑制 ON vs OFF)")
        print("=" * 66)
        rows = [
            ("模式", "Recall", "Precision", "FPR", "F1"),
            ("FP抑制 ON ", f"{on.recall:.1%}", f"{on.precision:.1%}",
             f"{on.false_positive_rate:.1%}", f"{f1_on:.3f}"),
            ("FP抑制 OFF", f"{off.recall:.1%}", f"{off.precision:.1%}",
             f"{off.false_positive_rate:.1%}", f"{f1_off:.3f}"),
        ]
        for r in rows:
            print(f"  {r[0]:<12} {r[1]:>8} {r[2]:>10} {r[3]:>8} {r[4]:>8}")

        fp_reduction = 0.0
        if off.false_positive_rate > 0:
            fp_reduction = 1 - on.false_positive_rate / off.false_positive_rate
        print(f"\n  误报率下降: {fp_reduction:.1%}  "
              f"(绝对误报: {on.false_positives} vs {off.false_positives})")
        print(f"  召回保持: {'是' if on.recall >= off.recall else '否!'} "
              f"({on.true_positives}/{on.true_positives + on.false_negatives})")

        print("\n  逐样本明细 (ON模式):")
        for r in results_on:
            status = ("TP" if (r.expected_vulnerable and r.detected)
                      else "FN" if r.expected_vulnerable else
                      "FP" if r.detected else "TN")
            mark = {}.get(status, "")
            print(f"    [{status}] {r.sample_name:<14} "
                  f"{r.num_findings} finding(s) ({r.scan_time_ms:.0f}ms)")

        per_sample = []
        for r_on, r_off in zip(results_on, results_off):
            per_sample.append({
                "sample": r_on.sample_name,
                "expected_vuln": r_on.expected_vulnerable,
                "detected_on": r_on.detected,
                "num_findings_on": r_on.num_findings,
                "detected_off": r_off.detected,
                "num_findings_off": r_off.num_findings,
                "scan_time_ms": round(r_on.scan_time_ms, 1),
                "success": r_on.success,
                "error": r_on.error_msg[:100] if r_on.error_msg else "",
            })

        report = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "metrics_on": self._metrics(on),
            "metrics_off": self._metrics(off),
            "fp_reduction": round(fp_reduction, 4),
            "recall_preserved": on.recall >= off.recall,
            "per_sample": per_sample,
        }
        out = self._build / "fp_regression_report.json"
        with open(out, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        print(f"\n  报告: {out}")
        return report

    @staticmethod
    def _metrics(s: TestSummary) -> Dict:
        f1 = 2 * s.true_positives / max(
            2 * s.true_positives + s.false_positives + s.false_negatives, 1)
        return {
            "TP": s.true_positives, "FP": s.false_positives,
            "TN": s.true_negatives, "FN": s.false_negatives,
            "recall": round(s.recall, 4),
            "precision": round(s.precision, 4),
            "fpr": round(s.false_positive_rate, 4),
            "f1": round(f1, 4),
            "avg_time_ms": round(s.avg_time_ms, 1),
        }


def main():
    runner = FpRegressionRunner()
    runner.run()
    return 0


if __name__ == '__main__':
    sys.exit(main())
