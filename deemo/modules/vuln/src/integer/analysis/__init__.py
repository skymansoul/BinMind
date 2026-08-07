"""整数溢出分析子模块 — 六模式检测管线.

创建: 2026-07-14

模块结构 (≤300行/文件):
  _types.py: 共享类型/常量/正则
  _detector_core.py: IntOverflowDetector 主类 + 栈值收集
  _mode_alloc_size.py: LARGE_IMM64 / TRUNCATION / SUSPICIOUS_SIZE
  _mode_arithmetic.py: SIGNED_IDX / MUL_OVERFLOW / 16-bit wraparound
"""
from ._detector_core import IntOverflowDetector
from ._types import IntOverflowFinding, OverflowType

__all__ = ['IntOverflowDetector', 'IntOverflowFinding', 'OverflowType']
