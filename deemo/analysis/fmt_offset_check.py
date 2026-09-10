"""
格式化字符串偏移量校验 — 委托到 fmt_stack_offset.py.

文档路径清单引用此文件, 实际功能已统一在 fmt_stack_offset.py 的
FormatStackOffsetAnalyzer 中实现. 本模块重导出核心 API 保持路径有效.
"""

from analysis.fmt_stack_offset import (
    FormatStackOffsetAnalyzer, infer_fmt_offset,
    FmtCallSite, StackOffsetEstimate, CallingConvention,
    FMT_ARG_POSITIONS,
)

__all__ = [
    'FormatStackOffsetAnalyzer', 'infer_fmt_offset',
    'FmtCallSite', 'StackOffsetEstimate', 'CallingConvention',
    'FMT_ARG_POSITIONS',
]
