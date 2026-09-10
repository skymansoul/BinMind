"""分析增强模块核心导入: 区间/路径约束/堆布局/统一FP过滤."""


from analysis.strided_interval import (
    StridedInterval, si_singleton, si_interval, si_range,
    si_unbounded, si_from_mul,
)

# 路径约束与堆布局模块
from analysis.path_constraint_collector import (
    BranchConstraint, PathConstraints, PathConstraintCollector,
)
from analysis.heap_layout_oracle import (
    ChunkClass, ChunkLayout, HeapRegion, HeapLayoutOracle,
)
from analysis.heap_bounds_prover import (
    ProofResult, HeapBoundsProver, prove_store_safety,
)
from analysis.unified_fp_filter import (
    FilterStage, FilterReport, UnifiedFPFilter,
)

# C源码级值范围传播引擎
from analysis.value_range import (
    Range, INF, ValueRangeEngine,
)
from analysis.expr_evaluator import (
    eval_expr_impl, _eval_sizeof, _apply_op,
)

# 污点传播 — DEPRECATED旧模块,保留兼容但加降级保护
try:
    from analysis.taint_propagation import (
        detect_heap_overflow, propagate_sizes,
        extract_allocation_sites, extract_write_sites, analyze_heap_risk,
    )
except ImportError:
    detect_heap_overflow = None  # type: ignore
    propagate_sizes = None  # type: ignore
    extract_allocation_sites = None  # type: ignore
    extract_write_sites = None  # type: ignore
    analyze_heap_risk = None  # type: ignore

# 约束简化 — DEPRECATED旧模块,保留兼容但加降级保护
try:
    from analysis.constraint_simplifier import (
        filter_false_positives, extract_constants,
    )
except ImportError:
    filter_false_positives = None  # type: ignore
    extract_constants = None  # type: ignore

# Guard inference
try:
    from analysis.guard_inference import GuardInferenceEngine, GuardVerdict, GuardCondition
except (ImportError, AttributeError):
    GuardInferenceEngine = None  # type: ignore
    GuardVerdict = None  # type: ignore
    GuardCondition = None  # type: ignore

# 路径敏感区间分析 & 多因子评分
from analysis.interval_domain import (
    Interval, IntervalKind, widen_sequence, interval_from_constrained_source,
)
from analysis.heap_path_analyzer import (
    PathSensitiveHeapAnalyzer, HeapPathVerdict, AbstractState,
    BasicBlock, path_sensitive_analyze,
)
from analysis.pointer_alias_tracker import (
    PointerAlias, ResolvedStore, PointerAliasTracker, track_pointer_aliases,
)
from analysis.heap_confidence_scorer import (
    ConfidenceFactors, HeapConfidenceScorer, classify_heap_overflows,
)
from analysis.heap_analysis_pipeline import (
    run_heap_analysis_pipeline, PipelineStats,
)
# 值范围约束过滤 — 直接从core.value_range导入(DEPRECATED shim已移除)
from core.value_range import (
    analyze_heap_bounds, extract_alloc_sites, extract_heap_writes,
    check_bounds, Interval, AllocSite, HeapWrite, BoundsViolation,
)
# 污点简化 — 直接从core模块导入(DEPRECATED shim已移除)
try:
    from core.detection_shared import (
        TaintSource, TaintSink, TaintPath, is_source, is_sink,
    )
    from core.taint_tracker import (
        track_taint_intraprocedural, filter_by_taint,
    )
except ImportError:
    TaintSource = None  # type: ignore
    TaintSink = None  # type: ignore
    TaintPath = None  # type: ignore
    is_source = None  # type: ignore
    is_sink = None  # type: ignore
    track_taint_intraprocedural = None  # type: ignore
    filter_by_taint = None  # type: ignore

# 流敏感值域+守卫+分配器六阶段过滤
try:
    from analysis.enhanced_fp_filter import (
        filter_non_heap_writes, filter_guarded_stores, adjust_for_slack,
        adjust_for_value_range, run_enhanced_filter,
    )
except ImportError:
    run_enhanced_filter = None

try:
    from analysis.value_range_propagator import (
        Interval as VRInterval, VarRange, ValueRangePropagator,
        extract_size_constraints_from_ir,
    )
except ImportError:
    VRInterval = None  # type: ignore

try:
    from analysis.guard_condition_analyzer import (
        GuardCondition, find_guard_for_variable, is_store_safeguarded,
        extract_all_guards,
    )
except ImportError:
    GuardCondition = None  # type: ignore

try:
    from analysis.allocator_chunk_model import (
        ChunkLayout, estimate_chunk_layout, is_within_slack,
        would_overflow, compute_effective_boundary,
    )
except ImportError:
    estimate_chunk_layout = None

try:
    from analysis.heap_disambiguator import (
        MemAccess, MemRegion, is_likely_heap_write,
        classify_memory_access, extract_heap_accesses,
    )
except ImportError:
    MemRegion = None  # type: ignore

try:
    from analysis.flow_sensitive_tracker import (
        AllocRecord, VarsEquivClass, FlowSensitiveTracker,
    )
except ImportError:
    FlowSensitiveTracker = None

# 四层 Tier 管线
from analysis.allocator_model import (
    AllocKind, AllocatorModel, ptmalloc2_usable_size,
    jemalloc_usable_size, tcmalloc_usable_size,
)
from analysis.symbolic_range import (
    AffineInterval, PathCondition, LinearInequality,
    affine_const, affine_var, affine_unbounded,
)
from analysis.cfg_parser import (
    CfgParser, BasicBlock as CfgBasicBlock, ControlFlowGraph,
)
from analysis.heap_expr_parser import (
    HeapExprParser, quick_parse_size,
)
from analysis.heap_ir_matcher import (
    match_assign, match_if, match_alloc, match_write, match_condition,
)
from analysis.path_sensitive_vrf import (
    PathSensitiveVRF, AllocRecord as VrfAllocRecord, VrfVerdict,
)
from analysis.symbolic_arith_matcher import (
    SymExpr, sym_const,
    try_arith_insn, try_load_store_insn,
    try_conditional_insn, refine_range_by_constraints,
)
from analysis.selective_symexec import (
    SelectiveSymExec, SymVerdict,
)
from analysis.infeasible_path_pruner import (
    InfeasiblePathPruner, PruneResult, GuardPatternDetector,
)
from analysis.uaf_tarps_verifier import (
    UafTarpsVerifier, TarpsVerdict, TarpsResult,
)
try:
    from analysis.uaf_tarps_verifier import batch_verify_uaf
except ImportError:
    batch_verify_uaf = None  # type: ignore