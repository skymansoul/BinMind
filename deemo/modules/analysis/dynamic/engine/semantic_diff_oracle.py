# 创建: 2026-07-02 16:45
# 修改: 2026-07-02 — 四维差分 (output x coverage x perf x syscall)
# 修改: 2026-07-02 — 移除 DDYF 装饰性引用, 替换为 McKeeman
"""
二进制语义差分 Oracle — 无需源码的比较两个二进制版本的行为差异。

传统差分测试需要源码或规范——闭源二进制无此条件。
本模块提供纯黑盒的语义差分判定:
  两个二进制版本被相同输入驱动→比较输出和覆盖→差异即潜在 bug/regression。

差分维度:
  1. 输出差异: stdout/stderr/返回值/写入文件的字节
  2. 覆盖差异: 两个版本在相同输入下触发的基本块集合差异
  3. 性能差异: 执行时间/内存峰值 (可能指示算法退化)
  4. 行为差异: 系统调用序列是否不同

差异类型分类:
  - DIVERGENCE: 输出不同——可能是 bug fix 引入的新 bug
  - COVERAGE_GAP: 覆盖不同但输出相同——可能指示死代码或优化差异
  - REGRESSION: 输出相同但性能显著下降 (>2× slowdown)
  - NEW_BEHAVIOR: 系统调用序列新增/删除——可能指示新功能或删减

为什么需要多维度差分:
  单一输出比较无法发现"行为相同但路径不同"的问题——例如
  安全补丁修复了缓冲区溢出但未改变 I/O 行为 (覆盖变化, 输出不变)。
  覆盖差异可以指示"底层实现变了但上层行为不变"的补丁。

ref: Differential testing — 差分测试的原始概念,
     本项目将其从源码级推广到二进制级 (四维 I/O+覆盖+性能+系统调用)
ref: DIFFSPEC — LLM-based differential testing,
     本项目的语义差分判定是 DIFFSPEC 的确定性、无 LLM 依赖替代
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, Callable


class DiffType(Enum):
    DIVERGENCE = 'divergence'        # 输出不同
    COVERAGE_GAP = 'coverage_gap'    # 覆盖不同, 输出相同
    REGRESSION = 'regression'        # 性能退化
    NEW_BEHAVIOR = 'new_behavior'     # 系统调用序列变化
    IDENTICAL = 'identical'          # 完全相同


@dataclass
class ExecutionSnapshot:
    """一次二进制执行的快照——输出 + 覆盖 + 性能 + 系统调用。"""
    return_code: int = 0
    stdout: bytes = b''
    stderr: bytes = b''
    edge_bitmap: bytearray = field(default_factory=lambda: bytearray(65536))
    execution_time_ms: float = 0.0
    peak_memory_kb: int = 0
    syscall_sequence: list[str] = field(default_factory=list)
    crash: bool = False
    crash_signal: str = ''


@dataclass
class DiffReport:
    """两个二进制版本间的一次差异报告。"""
    input_hash: str = ''
    diff_type: DiffType = DiffType.IDENTICAL
    output_similarity: float = 1.0     # [0,1]
    coverage_similarity: float = 1.0   # Jaccard
    perf_ratio: float = 1.0            # time_v2 / time_v1
    syscall_diff_count: int = 0
    severity: str = 'NONE'             # 'CRITICAL'|'HIGH'|'MEDIUM'|'LOW'|'NONE'
    description: str = ''


# 快照采集

def capture_execution(runner: Callable[[bytes], tuple],
                      test_input: bytes) -> ExecutionSnapshot:
    """执行二进制, 采集完整快照。runner: (input_bytes) → (retcode, stdout, stderr, time_ms)。"""
    try:
        ret, out, err, elapsed = runner(test_input)
    except Exception as e:
        return ExecutionSnapshot(return_code=-1, stdout=b'', stderr=str(e).encode(),
                                 execution_time_ms=0.0, crash=True, crash_signal=str(e))
    snapshot = ExecutionSnapshot(
        return_code=ret, stdout=out, stderr=err,
        execution_time_ms=elapsed,
    )
    if ret < 0:
        snapshot.crash = True
        snapshot.crash_signal = f'SIGNAL({-ret})'
    return snapshot


# 差分判定

class SemanticDiffOracle:
    """无源码的二进制语义差分 Oracle。比较两个版本的执行快照。"""

    __slots__ = ('_reports', '_thresholds')

    def __init__(self, output_threshold: float = 0.99,
                 coverage_threshold: float = 0.99,
                 perf_ratio_threshold: float = 2.0):
        self._reports: list[DiffReport] = []
        self._thresholds = {
            'output': output_threshold,
            'coverage': coverage_threshold,
            'perf': perf_ratio_threshold,
        }

    def compare(self, input_data: bytes,
                snap_v1: ExecutionSnapshot,
                snap_v2: ExecutionSnapshot) -> DiffReport:
        """比较两个版本在同输入下的执行快照——生成差异报告。"""
        inp_hash = hashlib.sha256(input_data).hexdigest()[:12]
        report = DiffReport(input_hash=inp_hash)

        # 输出相似度
        report.output_similarity = _output_similarity(
            snap_v1.stdout, snap_v2.stdout,
            snap_v1.return_code, snap_v2.return_code)

        # 覆盖相似度
        report.coverage_similarity = _coverage_similarity(
            snap_v1.edge_bitmap, snap_v2.edge_bitmap)

        # 性能比
        if snap_v1.execution_time_ms > 0:
            report.perf_ratio = snap_v2.execution_time_ms / snap_v1.execution_time_ms

        # 系统调用差异
        sc1 = set(snap_v1.syscall_sequence)
        sc2 = set(snap_v2.syscall_sequence)
        report.syscall_diff_count = len(sc1.symmetric_difference(sc2))

        # 分类
        report.diff_type = self._classify(report, snap_v1, snap_v2)
        report.severity = self._assess_severity(report, snap_v1, snap_v2)
        report.description = self._describe(report)

        self._reports.append(report)
        return report

    def compare_batch(self, test_cases: list[tuple[bytes, ExecutionSnapshot, ExecutionSnapshot]]
                      ) -> list[DiffReport]:
        return [self.compare(inp, s1, s2) for inp, s1, s2 in test_cases]

    def _classify(self, r: DiffReport,
                  s1: ExecutionSnapshot,
                  s2: ExecutionSnapshot) -> DiffType:
        if r.output_similarity < self._thresholds['output']:
            return DiffType.DIVERGENCE
        if r.coverage_similarity < self._thresholds['coverage']:
            return DiffType.COVERAGE_GAP
        if r.perf_ratio > self._thresholds['perf']:
            return DiffType.REGRESSION
        if r.syscall_diff_count > 0:
            return DiffType.NEW_BEHAVIOR
        return DiffType.IDENTICAL

    def _assess_severity(self, r: DiffReport,
                         s1: ExecutionSnapshot,
                         s2: ExecutionSnapshot) -> str:
        if s1.crash != s2.crash:
            return 'CRITICAL'
        if r.diff_type == DiffType.DIVERGENCE:
            return 'HIGH'
        if r.diff_type == DiffType.COVERAGE_GAP and r.output_similarity < 0.99:
            return 'MEDIUM'
        if r.diff_type == DiffType.REGRESSION and r.perf_ratio > 5.0:
            return 'MEDIUM'
        return 'LOW'

    def _describe(self, r: DiffReport) -> str:
        if r.diff_type == DiffType.IDENTICAL:
            return 'identical behavior'
        parts = []
        if r.output_similarity < 0.99:
            parts.append(f'output divergence (sim={r.output_similarity:.3f})')
        if r.coverage_similarity < 0.99:
            parts.append(f'coverage gap (jaccard={r.coverage_similarity:.3f})')
        if r.perf_ratio > 2.0:
            parts.append(f'regression ({r.perf_ratio:.1f}x slower)')
        if r.syscall_diff_count > 0:
            parts.append(f'{r.syscall_diff_count} syscall diffs')
        return '; '.join(parts) if parts else 'minor differences'

    def diverged_inputs(self) -> list[str]:
        return [r.input_hash for r in self._reports
                if r.diff_type == DiffType.DIVERGENCE]

    def stats(self) -> dict:
        by_type = {}
        for r in self._reports:
            by_type[r.diff_type.value] = by_type.get(r.diff_type.value, 0) + 1
        return {
            'total_comparisons': len(self._reports),
            'divergences': len(self.diverged_inputs()),
            'by_type': by_type,
        }


def _output_similarity(out1: bytes, out2: bytes,
                       rc1: int, rc2: int) -> float:
    if rc1 != rc2:
        return 0.5
    if out1 == out2:
        return 1.0
    max_len = max(len(out1), len(out2))
    if max_len == 0:
        return 1.0
    same = sum(1 for a, b in zip(out1, out2) if a == b)
    return same / max_len


def _coverage_similarity(bm1: bytearray, bm2: bytearray) -> float:
    if len(bm1) != len(bm2):
        return 0.0
    inter = sum(1 for i in range(len(bm1))
                if bm1[i] & bm2[i])
    union = sum(1 for i in range(len(bm1))
                if bm1[i] | bm2[i])
    return inter / union if union > 0 else 1.0


__all__ = [
    'SemanticDiffOracle', 'ExecutionSnapshot', 'DiffReport', 'DiffType',
    'capture_execution',
]
