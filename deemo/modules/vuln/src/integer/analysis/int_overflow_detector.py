"""向后兼容重导出 — 实际实现已拆分为子模块.

创建: 2026-04-30

子模块:
  _types.py       — OverflowType, IntOverflowFinding, 常量, 正则
  _detector_core  — IntOverflowDetector (框架+栈值收集+辅助)
  _mode_alloc_size — LARGE_IMM64 / TRUNCATION / SUSPICIOUS_SIZE
  _mode_arithmetic — SIGNED_IDX / MUL_OVERFLOW / 16-bit wraparound
"""
# 从子模块重导出, 保持外部 import 路径不变
from ._detector_core import IntOverflowDetector
from ._types import IntOverflowFinding, OverflowType

__all__ = ['IntOverflowDetector', 'IntOverflowFinding', 'OverflowType']
