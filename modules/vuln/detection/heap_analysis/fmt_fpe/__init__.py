"""FPE — Format-Provenance Equivalence 包入口.

格式字符串漏洞误报削减创新包。模块分工:
  fmt_types    格式溯源类型与判定枚举
  fmt_tracker  前向扫描, 提取格式参数溯源标签
  fmt_filter   溯源等价分类判定
  pipeline     顶层 objdump 分析管线
"""

from modules.vuln.detection.heap_analysis.fmt_fpe.fmt_types import (
    FmtVerdict, FmtVerdictRecord, FmtCall, FuncFmtResult)

from modules.vuln.detection.heap_analysis.fmt_fpe.fmt_filter import (
    run_filter, summarize)

from modules.vuln.detection.heap_analysis.fmt_fpe.pipeline import (
    FpeBinaryReport, fpe_analyze_binary)

__all__ = [
    'FmtVerdict', 'FmtVerdictRecord', 'FmtCall', 'FuncFmtResult',
    'run_filter', 'summarize',
    'FpeBinaryReport', 'fpe_analyze_binary',
]
