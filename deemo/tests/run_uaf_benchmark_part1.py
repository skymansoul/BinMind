"""
UAF误报削减benchmark自动化测试脚本.

功能:
  1. 对每个UAF样本执行基线regex检测 + TARPS五阶段验证 + 路径敏感时序验证
  2. 结果收集与对比: TP/TN/FP/FN/Precision/Recall/F1
  3. 三种方法横向比较: Baseline | TARPS | Temporal Path

一键运行: python -m tests.run_uaf_benchmark
输出: tests/uaf_benchmark/BENCHMARK_REPORT.md
"""

from __future__ import annotations

import json
import re
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

PROJECT_ROOT = Path(__file__).parent.parent
BENCHMARK_DIR = Path(__file__).parent / 'uaf_benchmark'


@dataclass
class UafSampleResult:
    """单个UAF样本的检测结果."""
    sample_id: str = ""
    label: str = ""
    truth_uaf: bool = False

    # 基线检测
    baseline_detected: bool = False
    baseline_candidates: int = 0
    baseline_time_ms: float = 0.0

    # TARPS结果
    tarps_verdict: str = ""
    tarps_stages_safe: int = 0
    tarps_confidence: float = 0.0
    tarps_time_ms: float = 0.0
    tarps_error: str = ""

    # 路径敏感时序结果
    temporal_verdict: str = ""       # SAFE/UAF/DOUBLE_FREE/UNCERTAIN
    temporal_free_line: int = 0
    temporal_use_line: int = 0
    temporal_safe_paths: int = 0
    temporal_uaf_paths: int = 0
    temporal_total_paths: int = 0
    temporal_time_ms: float = 0.0
    temporal_reason: str = ""
    temporal_error: str = ""

    # 判定
    is_tp: bool = False
    is_tn: bool = False
    is_fp: bool = False
    is_fn: bool = False


@dataclass
class UafBenchmarkReport:
    """UAF benchmark完整报告."""
    samples: List[UafSampleResult] = field(default_factory=list)
    total_time_ms: float = 0.0

    def compute_metrics(self, method: str = 'temporal'
                        ) -> Dict[str, Any]:
        """计算指定方法的指标. method: baseline/tarps/temporal."""
        tp = tn = fp = fn = 0
        for s in self.samples:
            if method == 'temporal':
                tp += 1 if s.is_tp else 0
                tn += 1 if s.is_tn else 0
                fp += 1 if s.is_fp else 0
                fn += 1 if s.is_fn else 0
            elif method == 'tarps':
                tp += 1 if s.is_tp else 0
                tn += 1 if s.is_tn else 0
                fp += 1 if s.is_fp else 0
                fn += 1 if s.is_fn else 0
            else:
                tp += 1 if s.is_tp else 0
                tn += 1 if s.is_tn else 0
                fp += 1 if s.is_fp else 0
                fn += 1 if s.is_fn else 0

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = (2 * precision * recall / (precision + recall)
              if (precision + recall) > 0 else 0.0)
        fp_rate = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        return {'tp': tp, 'tn': tn, 'fp': fp, 'fn': fn,
                'precision': round(precision, 4),
                'recall': round(recall, 4),
                'f1': round(f1, 4),
                'fp_rate': round(fp_rate, 4),
                'total_samples': len(self.samples),
                'total_time_ms': round(self.total_time_ms, 1)}


class UafScanner:
    """UAF扫描器 — 三种方法: baseline / TARPS / temporal path."""

    _FREE_RE = re.compile(r'free\s*\(\s*(\w+(?:->\w+)*)\s*\)', re.IGNORECASE)
    _USE_RE = re.compile(
        r'(?:\*\s*(\w+)\b|(\w+)\s*->|(\w+)\s*\[)', re.IGNORECASE)

    def baseline_scan(self, source: str) -> Tuple[bool, int, str]:
        """基线regex UAF检测: free后存在解引用/成员访问."""
        lines = source.splitlines()
        free_lines = []
        for i, line in enumerate(lines, start=1):
            fm = self._FREE_RE.search(line)
            if fm:
                free_lines.append((i, fm.group(1)))

        candidates = 0
        for fl, fvar in free_lines:
            for i, line in enumerate(lines[fl:], start=fl):
                um = self._USE_RE.search(line)
                if um:
                    used = um.group(1) or um.group(2) or um.group(3)
                    if used == fvar:
                        if (f'{fvar}=NULL' in line
                                or f'{fvar} = NULL' in line):
                            continue
                        candidates += 1
        return (candidates > 0, candidates,
                f"baseline: {len(free_lines)} frees, {candidates} candidates")

    def tarps_scan(self, source: str) -> Tuple[str, int, float, str]:
        """TARPS五阶段验证."""
        try:
            from analysis.uaf_tarps_verifier import UafTarpsVerifier
            from analysis.uaf_tarps_types import TarpsVerdict

            lines = source.splitlines()
            insns = []
            for i, line in enumerate(lines):
                stripped = line.strip()
                if not stripped or stripped.startswith('//') \
                        or stripped.startswith('/*'):
                    continue
                insns.append((i * 4, stripped))

            verifier = UafTarpsVerifier(use_interproc=True)
            free_records = []
            for addr, text in insns:
                fm = re.search(r'free\s*\(\s*(\w+(?:->\w+)*)\s*\)', text)
                if fm:
                    free_records.append((addr, fm.group(1)))
            use_records = []
            for addr, text in insns:
                um = re.search(
                    r'\*\s*(\w+)|(\w+)\s*->|(\w+)\s*\[', text)
                if um:
                    uvar = um.group(1) or um.group(2) or um.group(3)
                    use_records.append((addr, uvar))

            if not free_records or not use_records:
                return ('NONE', 0, 0.0, '')

            worst_verdict = TarpsVerdict.DEF_FP
            max_confidence = 0.0
            total_safe_stages = 5

            for faddr, fvar in free_records:
                for uaddr, uvar in use_records:
                    if uaddr <= faddr:
                        continue
                    if uvar != fvar:
                        continue
                    result = verifier.verify(
                        0, faddr, uaddr, insns, source)
                    safe = sum(1 for v in result.stages.values() if not v)
                    total_safe_stages = min(total_safe_stages, safe)

                    if result.verdict.value in ('DEF_TP', 'LIKELY_TP'):
                        if (worst_verdict.value
                                not in ('DEF_TP', 'LIKELY_TP')):
                            worst_verdict = result.verdict
                        elif (result.verdict == TarpsVerdict.DEF_TP
                              and worst_verdict != TarpsVerdict.DEF_TP):
                            worst_verdict = TarpsVerdict.DEF_TP
                    max_confidence = max(max_confidence,
                                         result.confidence)
                    verifier.clear()

            return (worst_verdict.value, total_safe_stages,
                    max_confidence, '')

        except Exception as e:
            return ('ERROR', 0, 0.0, str(e))

    def temporal_scan(self, source: str
                      ) -> Tuple[str, int, int, int, int, float, str, str]:
        """路径敏感时序验证 — 核心创新.

        Returns: (verdict, free_line, use_line, safe_paths,
                  uaf_paths, total_paths, time_ms, reason_or_error)
        """
        try:
            from analysis.uaf_temporal_path_verifier import (
                TemporalPathVerifier, TemporalVerdict)

            verifier = TemporalPathVerifier(max_paths=128)
            results = verifier.verify(source)

            if not results:
                return ('NONE', 0, 0, 0, 0, 0, 0.0,
                        'no free-use pairs found')

            # 取最危险的判定
            worst = results[0]
            for r in results:
                if r.verdict == TemporalVerdict.UAF:
                    worst = r
                    break
                if r.verdict == TemporalVerdict.DOUBLE_FREE:
                    worst = r
                    break

            return (worst.verdict.value,
                    worst.free_line, worst.use_line,
                    worst.safe_paths, worst.uaf_paths,
                    worst.total_paths, 0.0,
                    worst.reason)

        except Exception as e:
            return ('ERROR', 0, 0, 0, 0, 0, 0.0, str(e))


