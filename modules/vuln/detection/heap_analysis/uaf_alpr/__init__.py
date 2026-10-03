"""ALPR — Allocation-Lifetime Provenance Rebound 包入口.

UAF 误报削减创新包。模块分工:
  uaf_types        生命周期溯源数据类型与判定枚举
  lifetime_tracker 函数内前向扫描, 提取 free/use 与指针溯源标签
  rebound_filter   溯源等价配对与重绑定滤除判定
  pipeline         顶层 objdump 分析管线
"""

from modules.vuln.detection.heap_analysis.uaf_alpr.uaf_types import (
    UafVerdict, UafVerdictRecord, FreeRecord, UafUse, UseKind)

from modules.vuln.detection.heap_analysis.uaf_alpr.rebound_filter import (
    run_filter, summarize)

from modules.vuln.detection.heap_analysis.uaf_alpr.pipeline import (
    AlprBinaryReport, alpr_analyze_binary)

__all__ = [
    'UafVerdict', 'UafVerdictRecord', 'FreeRecord', 'UafUse', 'UseKind',
    'run_filter', 'summarize',
    'AlprBinaryReport', 'alpr_analyze_binary',
]
