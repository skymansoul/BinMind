"""堆漏洞静态检测模块 — 五维路径敏感分析 + 分配器感知过滤.

核心创新: DP-TVRA (Demand-driven Path-sensitive Taint-Value-Range Analysis)
  三阶段管线: 污点追溯 → 路径约束窄化 → 分配器模型验证

新增:
  - taint_propagation: 稀疏需求驱动污点引擎 (Phase 1)
  - path_value_narrowing: 路径条件值域窄化 (Phase 2)
  - heap_fp_filter_v2: 三阶段串行过滤管线 (核心)
  - linear_constraint: 路径敏感的线性约束引擎
  - path_condition: 从分支指令提取守卫条件
  - loop_interval: 循环归纳变量的加宽/收窄分析
  - safety_prover: 多维度联合安全检查
  - interproc_context: 过程间size约束传播
  - enhanced_fp_filter: 五维联合误报过滤管线
  - analysis/: 对齐感知值流推断 + 语义FP过滤 (轻量集成层)

与现有模块的关系:
  - heap_bound_infer: 函数内区间推断 (保留, 与 V2 管线互补)
  - pointer_alias_tracker: Andersen 别名追踪 (保留, UAF 检测)
  - uaf_cross_fn_scorer: 跨函数 UAF 评分 (保留)
  - heap_state_model: CHOS 堆状态机 (保留, 模式检测)
  所有已有检测逻辑保留且不受新管线影响。
"""

# 原有导出 (保留不变)
from .heap_bound_infer import HeapBoundInferrer, IntervalDomain, HeapAccess
from .pointer_alias_tracker import PointerAliasTracker, AliasResult
from .uaf_cross_fn_scorer import CrossFunctionUAFScorer, UAFCrossFnResult

# DP-TVRA 管线核心
from .taint_propagation import (
    SparseTaintEngine, TaintStatus, TaintLabel, TaintSourceType)
from .path_value_narrowing import (
    PathValueNarrower, ValueRange, ComparisonOp)
from .filter_types import (
    FilterPhase, FilterDecision, FilterResult)
from .heap_fp_filter_v2 import (
    HeapFPFilterV2)

# 增强模块
from .linear_constraint import (
    LinearConstraintEngine, LinearConstraint,
    ConstraintSet, ConstraintOp)
from .path_condition import (
    PathConditionCollector, PathContext, BranchGuard)
from .loop_interval import (
    LoopIntervalAnalyzer, LoopSummary,
    InductionVar, LoopClass)
from .safety_prover import (
    SafetyProver, SafetyReport, SafetyVerdict)
from .interproc_context import (
    InterprocContextTracker, FunctionSummary, CallSiteContext)
from .enhanced_fp_filter import (
    EnhancedFPFilter, FilteredFinding, FilterReport, FilterVerdict)

# 轻量集成层
from .analysis import (
    MallocSizeInferrer, MallocSite, SInterval, AllocatorModel,
    ImprovedHeapOverflowDetector, HeapOverflowFinding,
    SemanticFalsePositiveFilter, SemanticFeatures)

__all__ = [
    # 原有
    "HeapBoundInferrer", "IntervalDomain", "HeapAccess",
    "PointerAliasTracker", "AliasResult",
    "CrossFunctionUAFScorer", "UAFCrossFnResult",
    # DP-TVRA 管线
    "SparseTaintEngine", "TaintStatus", "TaintLabel", "TaintSourceType",
    "PathValueNarrower", "ValueRange", "ComparisonOp",
    "HeapFPFilterV2", "FilterPhase", "FilterDecision", "FilterResult",
    # 增强模块
    "LinearConstraintEngine", "LinearConstraint", "ConstraintSet", "ConstraintOp",
    "PathConditionCollector", "PathContext", "BranchGuard",
    "LoopIntervalAnalyzer", "LoopSummary", "InductionVar", "LoopClass",
    "SafetyProver", "SafetyReport", "SafetyVerdict",
    "InterprocContextTracker", "FunctionSummary", "CallSiteContext",
    "EnhancedFPFilter", "FilteredFinding", "FilterReport", "FilterVerdict",
    # 轻量集成层
    "MallocSizeInferrer", "MallocSite", "SInterval", "AllocatorModel",
    "ImprovedHeapOverflowDetector", "HeapOverflowFinding",
    "SemanticFalsePositiveFilter", "SemanticFeatures",
]
