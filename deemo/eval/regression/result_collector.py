"""
回归测试 — 结果收集与对比模块

负责:
  - 汇总所有工具的扫描结果
  - 与 ground truth 对比计算 TP/FP/TN/FN
  - 输出统一 CSV + 统计摘要

创建: 2026-04-27
"""
from __future__ import annotations

import csv
import json
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

# 判决标准化: 各工具输出统一为二分类
OVERFLOW_VERDICTS = frozenset({
    'OVERFLOW', 'overflow', 'OVERFLOW_MAYBE', 'UNCERTAIN',
    'VULN', 'vuln', 'TRUE', 'true', 'POSITIVE', 'DETECTED',
})
SAFE_VERDICTS = frozenset({
    'SAFE', 'safe', 'NO_OVERFLOW', 'CLEAN', 'BENIGN',
    'FALSE', 'false', 'NEGATIVE', 'NOT_DETECTED',
})


@dataclass
class SampleResult:
    """单个样本的汇总结果，对所有工具统一计算."""
    sample_name: str
    cve_id: str
    category: str
    is_fp_sample: bool
    ground_truth: Optional[bool]  # True=应检出, False=应过滤

    # 逐工具
    binmind_verdict: str = ""
    binmind_confidence: float = 0.0
    binmind_ms: float = 0.0
    angr_verdict: str = ""
    angr_confidence: float = 0.0
    angr_ms: float = 0.0
    ghidra_verdict: str = ""
    ghidra_confidence: float = 0.0
    ghidra_ms: float = 0.0

    # 派生
    binmind_correct: Optional[bool] = None
    angr_correct: Optional[bool] = None
    ghidra_correct: Optional[bool] = None

@dataclass
class ToolMetrics:
    """单工具的 TP/FP/TN/FN/Precision/Recall/F1."""
    tool_name: str
    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0
    total_samples: int = 0
    total_time_ms: float = 0.0

    @property
    def precision(self) -> float:
        denom = self.tp + self.fp
        return self.tp / denom if denom > 0 else 0.0

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

    @property
    def accuracy(self) -> float:
        denom = self.tp + self.fp + self.tn + self.fn
        return (self.tp + self.tn) / denom if denom > 0 else 0.0

    @property
    def avg_time_ms(self) -> float:
        return self.total_time_ms / self.total_samples if self.total_samples > 0 else 0.0

    def to_dict(self) -> Dict:
        return {
            'tool': self.tool_name,
            'tp': self.tp, 'fp': self.fp, 'tn': self.tn, 'fn': self.fn,
            'precision': round(self.precision, 4),
            'recall': round(self.recall, 4),
            'f1': round(self.f1, 4),
            'fp_rate': round(self.fp_rate, 4),
            'accuracy': round(self.accuracy, 4),
            'total_samples': self.total_samples,
            'avg_time_ms': round(self.avg_time_ms, 1),
        }


class ResultCollector:
    """结果收集器 — 汇总多工具结果并计算指标."""

    CSV_COLUMNS = [
        'sample_name', 'cve_id', 'category', 'is_fp_sample', 'ground_truth',
        'binmind_verdict', 'binmind_confidence', 'binmind_ms',
        'angr_verdict', 'angr_confidence', 'angr_ms',
        'ghidra_verdict', 'ghidra_confidence', 'ghidra_ms',
        'binmind_correct', 'angr_correct', 'ghidra_correct',
    ]

    def __init__(self, manifest: List[Any], scan_reports: List[Any]):
        self._manifest = {m.name: m for m in manifest}
        self._scan_reports = {r.sample_name: r for r in scan_reports}
        self._results: List[SampleResult] = []
        self._metrics: Dict[str, ToolMetrics] = {}

    def collect(self) -> List[SampleResult]:
        """汇总所有样本的扫描结果."""
        self._results = []
        for name, m in sorted(self._manifest.items()):
            sr = SampleResult(
                sample_name=name,
                cve_id=getattr(m, 'cve_id', ''),
                category=getattr(m, 'category', 'unknown'),
                is_fp_sample=getattr(m, 'is_fp_sample', False),
                ground_truth=getattr(m, 'ground_truth', None),
            )

            report = self._scan_reports.get(name)
            if report:
                self._fill_tool_result(sr, report, 'binmind')
                self._fill_tool_result(sr, report, 'angr')
                self._fill_tool_result(sr, report, 'ghidra')

            # 计算正确性
            if sr.ground_truth is not None:
                sr.binmind_correct = self._check_correct(
                    sr.binmind_verdict, sr.ground_truth)
                sr.angr_correct = self._check_correct(
                    sr.angr_verdict, sr.ground_truth)
                sr.ghidra_correct = self._check_correct(
                    sr.ghidra_verdict, sr.ground_truth)

            self._results.append(sr)

        self._compute_metrics()
        return self._results

    def _fill_tool_result(
        self, sr: SampleResult, report: Any, tool_name: str,
    ) -> None:
        for r in getattr(report, 'results', []):
            if r.tool_name != tool_name:
                continue
            v = r.verdict if r.verdict else 'SKIP'
            setattr(sr, f'{tool_name}_verdict', v)
            setattr(sr, f'{tool_name}_confidence', getattr(r, 'confidence', 0.0))
            setattr(sr, f'{tool_name}_ms', getattr(r, 'elapsed_ms', 0.0))

    @staticmethod
    def _check_correct(verdict: str, ground_truth: bool) -> Optional[bool]:
        """判断工具判决是否正确."""
        if not verdict:
            return None
        predicted = ResultCollector._normalize_verdict(verdict)
        if predicted is None:
            return None
        return predicted == ground_truth

    @staticmethod
    def _normalize_verdict(verdict: str) -> Optional[bool]:
        """标准化判决为 bool."""
        v = verdict.strip().upper()
        if v in OVERFLOW_VERDICTS:
            return True
        if v in SAFE_VERDICTS:
            return False
        return None  # SKIP, ERROR, TIMEOUT

    def _compute_metrics(self) -> None:
        """计算所有工具的 TP/FP/TN/FN."""
        for tool in ('binmind', 'angr', 'ghidra'):
            tm = ToolMetrics(tool_name=tool)
            for sr in self._results:
                if sr.ground_truth is None:
                    continue
                verdict = getattr(sr, f'{tool}_verdict', '')
                predicted = self._normalize_verdict(verdict)
                if predicted is None:
                    continue
                tm.total_samples += 1
                tm.total_time_ms += getattr(sr, f'{tool}_ms', 0.0)

                if sr.ground_truth and predicted:
                    tm.tp += 1
                elif sr.ground_truth and not predicted:
                    tm.fn += 1
                elif not sr.ground_truth and predicted:
                    tm.fp += 1
                elif not sr.ground_truth and not predicted:
                    tm.tn += 1
            self._metrics[tool] = tm

    def write_csv(self, path: str) -> str:
        """输出统一 CSV."""
        with open(path, 'w', newline='', encoding='utf-8') as f:
            w = csv.DictWriter(f, fieldnames=self.CSV_COLUMNS, extrasaction='ignore')
            w.writeheader()
            for sr in self._results:
                row = {c: getattr(sr, c, '') for c in self.CSV_COLUMNS}
                w.writerow(row)
        return path

    def write_summary_json(self, path: str) -> str:
        """输出统计摘要 JSON."""
        TOOLS = ('binmind', 'angr', 'ghidra')
        summary = {
            'generated': time.strftime('%Y-%m-%dT%H:%M:%S'),
            'total_samples': len(self._results),
            'samples_with_ground_truth': sum(1 for s in self._results if s.ground_truth is not None),
            'tools': {n: t.to_dict() for n, t in sorted(self._metrics.items())},
            'per_sample': [{
                'name': s.sample_name, 'cve_id': s.cve_id, 'ground_truth': s.ground_truth,
                **{t: {'verdict': getattr(s, f'{t}_verdict', ''),
                       'correct': getattr(s, f'{t}_correct', None)} for t in TOOLS},
            } for s in self._results],
        }
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(summary, f, indent=2, ensure_ascii=False)
        return path

    @property
    def results(self) -> List[SampleResult]:
        return self._results

    @property
    def metrics(self) -> Dict[str, ToolMetrics]:
        return self._metrics

    def summary(self) -> str:
        """人类可读汇总."""
        lines = [f'{"=" * 70}',
                 f'Regression Test Summary — {time.strftime("%Y-%m-%d %H:%M")}',
                 f'Total samples: {len(self._results)}',
                 f'With ground truth: {sum(1 for sr in self._results if sr.ground_truth is not None)}',
                 f'{"=" * 70}']
        for name, tm in sorted(self._metrics.items()):
            d = tm.to_dict()
            lines.append(
                f'\n{name.upper()}: P={d["precision"]:.4f} R={d["recall"]:.4f} '
                f'F1={d["f1"]:.4f} FPR={d["fp_rate"]:.4f} '
                f'({d["tp"]}TP/{d["fp"]}FP/{d["tn"]}TN/{d["fn"]}FN) '
                f'avg {d["avg_time_ms"]:.0f}ms')
        for name in sorted(self._metrics):
            self._append_error_details(lines, name, False)
            self._append_error_details(lines, name, True)
        return '\n'.join(lines)

    def _append_error_details(
        self, lines: List[str], tool: str, is_fn: bool,
    ) -> None:
        """追加 FP 或 FN 明细."""
        label = 'False Negatives' if is_fn else 'False Positives'
        samples = [
            sr for sr in self._results
            if sr.ground_truth is not None
            and getattr(sr, f'{tool}_correct') is False
            and self._normalize_verdict(getattr(sr, f'{tool}_verdict', '')) is (not is_fn)
        ]
        if samples:
            lines.append(f'\n{tool.upper()} {label} ({len(samples)}):')
            for sr in samples:
                v = getattr(sr, f'{tool}_verdict', '?')
                lines.append(f'  - {sr.sample_name}: {v}')


__all__ = [
    'SampleResult', 'ToolMetrics', 'ResultCollector',
    'OVERFLOW_VERDICTS', 'SAFE_VERDICTS',
]
