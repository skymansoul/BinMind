"""ACPE — Allocator-Capacity Provenance Equivalence 包入口.

创建: 2025-04-17
堆溢出误报削减核心创新包。模块分工:
  capacity_model     ptmalloc2 可用容量 + 符号容量表达式
  sym_size_tracker   函数内符号 size 追踪 (malloc/memcpy/read)
  guard_dominance    cmp/jcc 守卫支配分析 (早退/钳位/反例)
  equivalence        容量溯源等价分类
  verdict            ACPE 判定引擎与汇总
  pipeline           顶层 objdump 分析管线
"""

from modules.vuln.detection.heap_analysis.acpe.capacity_model import (
    CapExpr, usable_size, slack_bytes, const_relation, arith_relation)

from modules.vuln.detection.heap_analysis.acpe.guard_dominance import (
    GuardRecord, GuardEvidence, analyze_guards_for_write)

from modules.vuln.detection.heap_analysis.acpe.equivalence import (
    EquivResult, classify_pair)

from modules.vuln.detection.heap_analysis.acpe.verdict import (
    AcpeVerdict, evaluate, summarize)

from modules.vuln.detection.heap_analysis.acpe.pipeline import (
    AcpeBinaryReport, acpe_analyze_binary)

__all__ = [
    'CapExpr', 'usable_size', 'slack_bytes', 'const_relation', 'arith_relation',
    'GuardRecord', 'GuardEvidence', 'analyze_guards_for_write',
    'EquivResult', 'classify_pair',
    'AcpeVerdict', 'evaluate', 'summarize',
    'AcpeBinaryReport', 'acpe_analyze_binary',
]
