"""
benchmark 数据类与报告生成.

提供:
  - SampleResult: 单个样本检测结果
  - BenchmarkReport: 完整 benchmark 报告
  - generate_markdown_report: 生成 Markdown 报告
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List


@dataclass
class SampleResult:
    """单个样本的检测结果."""
    sample_id: str = ""
    label: str = ""          # 'tp' or 'tn'
    truth_overflow: bool = False

    # 基线regex检测结果
    regex_detected: bool = False
    regex_candidates: int = 0
    regex_time_ms: float = 0.0
    regex_error: str = ""

    # LPVRA分析结果
    lpvra_verdict: str = ""      # SAFE/OVERFLOW/UNCERTAIN
    lpvra_safe_paths: int = 0
    lpvra_total_paths: int = 0
    lpvra_allocs: int = 0
    lpvra_writes: int = 0
    lpvra_time_ms: float = 0.0
    lpvra_error: str = ""

    # 判定结果
    is_tp: bool = False      # truth=overflow & detected
    is_tn: bool = False      # truth=safe & filtered
    is_fp: bool = False      # truth=safe & flagged
    is_fn: bool = False      # truth=overflow & missed

    @property
    def lpvra_is_safe(self) -> bool:
        return self.lpvra_verdict == 'SAFE'


@dataclass
class BenchmarkReport:
    """完整benchmark报告."""
    samples: List[SampleResult] = field(default_factory=list)
    total_time_ms: float = 0.0

    def compute_metrics(self) -> Dict[str, Any]:
        tp = sum(1 for s in self.samples if s.is_tp)
        tn = sum(1 for s in self.samples if s.is_tn)
        fp = sum(1 for s in self.samples if s.is_fp)
        fn = sum(1 for s in self.samples if s.is_fn)

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
        fp_rate = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        accuracy = (tp + tn) / (tp + tn + fp + fn) if (tp + tn + fp + fn) > 0 else 0.0

        return {
            'tp': tp, 'tn': tn, 'fp': fp, 'fn': fn,
            'precision': round(precision, 4),
            'recall': round(recall, 4),
            'f1': round(f1, 4),
            'fp_rate': round(fp_rate, 4),
            'accuracy': round(accuracy, 4),
            'total_samples': len(self.samples),
            'total_time_ms': round(self.total_time_ms, 1),
        }


def generate_markdown_report(report: BenchmarkReport, output_path: Path):
    """生成可读的Markdown benchmark报告."""
    metrics = report.compute_metrics()

    lines = []
    lines.append("# Heap Overflow FP Reduction Benchmark — LPVRA Pipeline")
    lines.append("")
    lines.append(f"**Date:** {time.strftime('%Y-%m-%d')}")
    lines.append("**Methodology:** LPVRA (Lightweight Path-sensitive Value Range Analysis)")
    lines.append("**Pipeline:** 3-Stage: LPVRA Engine → Boundary Checker → Conservative Classifier")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## Executive Summary")
    lines.append("")
    lines.append("| Metric | Baseline (regex) | LPVRA Pipeline | Reduction |")
    lines.append("|--------|-----------------|----------------|-----------|")

    # 计算regex基线的指标
    regex_tp = sum(1 for s in report.samples if s.truth_overflow and s.regex_detected)
    regex_fp = sum(1 for s in report.samples if not s.truth_overflow and s.regex_detected)
    regex_tn = sum(1 for s in report.samples if not s.truth_overflow and not s.regex_detected)
    regex_fn = sum(1 for s in report.samples if s.truth_overflow and not s.regex_detected)

    regex_precision = regex_tp / (regex_tp + regex_fp) if (regex_tp + regex_fp) > 0 else 0.0
    lpvra_precision = metrics['precision']
    precision_improve = lpvra_precision - regex_precision

    regex_fp_rate = regex_fp / (regex_fp + regex_tn) if (regex_fp + regex_tn) > 0 else 0.0
    lpvra_fp_rate = metrics['fp_rate']
    fp_reduction = (regex_fp_rate - lpvra_fp_rate) / regex_fp_rate * 100 if regex_fp_rate > 0 else 0.0

    lines.append(f"| Samples | {metrics['total_samples']} | {metrics['total_samples']} | — |")
    lines.append(f"| TP | {regex_tp} | {metrics['tp']} | — |")
    lines.append(f"| TN | {regex_tn} | {metrics['tn']} | +{metrics['tn'] - regex_tn} recovered |")
    lines.append(f"| FP | {regex_fp} | {metrics['fp']} | {regex_fp - metrics['fp']} reduced |")
    lines.append(f"| FN | {regex_fn} | {metrics['fn']} | — |")
    lines.append(f"| Precision | {regex_precision:.1%} | {lpvra_precision:.1%} | +{precision_improve:.1%}pp |")
    lines.append(f"| FP Rate | {regex_fp_rate:.1%} | {lpvra_fp_rate:.1%} | **{fp_reduction:.1f}%** ↓ |")
    lines.append(f"| Total Time | — | {report.total_time_ms:.0f}ms | — |")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## Per-Sample Breakdown")
    lines.append("")
    lines.append("### True Positives (correctly detected)")
    lines.append("")

    for s in report.samples:
        if s.is_tp:
            lines.append(f"- {s.sample_id}: LPVRA={s.lpvra_verdict} paths={s.lpvra_safe_paths}/{s.lpvra_total_paths}")

    lines.append("")
    lines.append("### True Negatives (correctly filtered)")
    lines.append("")

    for s in report.samples:
        if s.is_tn:
            lines.append(f"- {s.sample_id}: LPVRA={s.lpvra_verdict}")

    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## Conservative Filtering Guarantee")
    lines.append("")
    lines.append("- **SAFE verdict:** Proven safe on ALL reachable paths → filtered")
    lines.append("- **OVERFLOW verdict:** At least one path definitely overflows → kept")
    lines.append("- **UNCERTAIN verdict:** Cannot prove safety → conservatively kept")
    lines.append("- **Zero新增漏报:** No UNCERTAIN candidate is filtered")

    output_path.write_text('\n'.join(lines), encoding='utf-8')
    print(f"\nBenchmark report written to {output_path}")
