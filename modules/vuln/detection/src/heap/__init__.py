"""堆漏洞静态检测模块 — 区间抽象域 + Andersen别名分析 + 跨函数UAF评分.

与现有模块的关系:
  - uaf_candidate_scorer.py: 函数内三因素评分 (保留)
  - memory_heap.py: 堆结构体解析 (保留)
  本模块在两者之上增加过程间分析和抽象解释边界推断。
"""

from .heap_bound_infer import HeapBoundInferrer, IntervalDomain, HeapAccess
from .pointer_alias_tracker import PointerAliasTracker, AliasResult
from .uaf_cross_fn_scorer import CrossFunctionUAFScorer, UAFCrossFnResult

__all__ = [
    "HeapBoundInferrer", "IntervalDomain", "HeapAccess",
    "PointerAliasTracker", "AliasResult",
    "CrossFunctionUAFScorer", "UAFCrossFnResult",
]
