"""
FP 过滤第5-7阶段: C 源码版 — 委托到 fp_filter_stages.py.

  Stage 5: Slack 空间 (chunk 尾部填充)
  Stage 6: 值域传播 (区间抽象)
  Stage 7: 非堆写入过滤

实际逻辑在 fp_filter_stages.py 各 stage 函数中, 本模块重导出保持路径有效.
"""

from analysis.fp_filter_stages import (
    stage5_slack_space, stage6_value_range, stage7_non_heap,
)

__all__ = ['stage5_slack_space', 'stage6_value_range', 'stage7_non_heap']
