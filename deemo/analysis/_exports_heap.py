"""堆溢出分析核心导入 — StridedInterval/Tier管线/值范围/污点传播."""
# Strided interval domain
from analysis.strided_interval import (
    StridedInterval, si_singleton, si_interval, si_range,
    si_unbounded, si_from_mul,
)
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
from analysis.value_range import (
    Range, INF, ValueRangeEngine,
)
from analysis.expr_evaluator import (
    eval_expr_impl, _eval_sizeof, _apply_op,
)
from analysis.taint_propagation import (
    detect_heap_overflow, propagate_sizes,
    extract_allocation_sites, extract_write_sites, analyze_heap_risk,
)
try:
    from analysis.constraint_simplifier import (
        extract_bounds, check_array_write_safe, resolve_base_ptr,
    )
except ImportError:
    extract_bounds = None  # type: ignore
    check_array_write_safe = None  # type: ignore
    resolve_base_ptr = None  # type: ignore
try:
    from analysis.guard_inference import GuardInferenceEngine, GuardVerdict, GuardCondition
except (ImportError, AttributeError):
    GuardInferenceEngine = None  # type: ignore
    GuardVerdict = None  # type: ignore
    GuardCondition = None  # type: ignore
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
from analysis.value_range_filter import (
    analyze_heap_bounds, extract_alloc_sites, extract_heap_writes,
    check_bounds, Interval, AllocSite, HeapWrite, BoundsViolation,
)
try:
    from analysis.taint_simplifier import (
        TaintSource, TaintSink, TaintPath, is_source, is_sink,
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
# Tier 0-3
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
# 深度分析子模块
from analysis.heap_cfg_builder import (
    HeapCFGBuilder, build_heap_cfg,
)
from analysis.fp_filter_phases import (
    phase_allocator_semantics, phase_path_constraints,
)
try:
    from analysis.fp_filter_phases_late import (
        phase_heap_layout, phase_z3_prove, phase_strided_interval,
    )
except ImportError:
    phase_heap_layout = None  # type: ignore
    phase_z3_prove = None  # type: ignore
    phase_strided_interval = None  # type: ignore
from analysis.pipeline_stage_helpers import (
    extract_alloc_write_pairs, apply_interproc_summaries,
    compute_final_verdict,
)
from analysis.alloc_write_extractor import (
    AllocSite, WriteSite, AllocWritePair,
    AllocWriteExtractor, extract_alloc_write_pairs,
)

__all__ = [
    'Range', 'INF', 'ValueRangeEngine',
    'eval_expr_impl', '_eval_sizeof', '_apply_op',
    'StridedInterval', 'si_singleton', 'si_interval', 'si_range',
    'si_unbounded', 'si_from_mul',
    'BranchConstraint', 'PathConstraints', 'PathConstraintCollector',
    'ChunkClass', 'ChunkLayout', 'HeapRegion', 'HeapLayoutOracle',
    'ProofResult', 'HeapBoundsProver', 'prove_store_safety',
    'FilterStage', 'FilterReport', 'UnifiedFPFilter',
    'detect_heap_overflow', 'propagate_sizes',
    'extract_allocation_sites', 'extract_write_sites', 'analyze_heap_risk',
    'GuardInferenceEngine', 'GuardVerdict', 'GuardCondition',
    'analyze_heap_bounds', 'extract_alloc_sites', 'extract_heap_writes',
    'check_bounds', 'Interval', 'AllocSite', 'HeapWrite', 'BoundsViolation',
    'TaintSource', 'TaintSink', 'TaintPath', 'is_source', 'is_sink',
    'track_taint_intraprocedural', 'filter_by_taint',
    'Interval', 'IntervalKind', 'widen_sequence', 'interval_from_constrained_source',
    'PathSensitiveHeapAnalyzer', 'HeapPathVerdict', 'AbstractState',
    'BasicBlock', 'path_sensitive_analyze',
    'PointerAlias', 'ResolvedStore', 'PointerAliasTracker', 'track_pointer_aliases',
    'ConfidenceFactors', 'HeapConfidenceScorer', 'classify_heap_overflows',
    'run_heap_analysis_pipeline', 'PipelineStats',
    'run_enhanced_filter',
    'VRInterval', 'VarRange', 'ValueRangePropagator', 'extract_size_constraints_from_ir',
    'GuardCondition', 'find_guard_for_variable', 'is_store_safeguarded', 'extract_all_guards',
    'ChunkLayout', 'estimate_chunk_layout', 'is_within_slack', 'would_overflow', 'compute_effective_boundary',
    'MemAccess', 'MemRegion', 'is_likely_heap_write', 'classify_memory_access', 'extract_heap_accesses',
    'AllocRecord', 'VarsEquivClass', 'FlowSensitiveTracker',
    'AllocKind', 'AllocatorModel', 'ptmalloc2_usable_size',
    'jemalloc_usable_size', 'tcmalloc_usable_size',
    'AffineInterval', 'PathCondition', 'LinearInequality',
    'affine_const', 'affine_var', 'affine_unbounded',
    'CfgParser', 'CfgBasicBlock', 'ControlFlowGraph',
    'HeapExprParser', 'quick_parse_size',
    'PathSensitiveVRF', 'VrfAllocRecord', 'VrfVerdict',
    'match_assign', 'match_if', 'match_alloc', 'match_write', 'match_condition',
    'SymExpr', 'sym_const',
    'try_arith_insn', 'try_load_store_insn',
    'try_conditional_insn', 'refine_range_by_constraints',
    'SelectiveSymExec', 'SymVerdict',
    'InfeasiblePathPruner', 'PruneResult', 'GuardPatternDetector',
    'HeapCFGBuilder', 'build_heap_cfg',
    'phase_allocator_semantics', 'phase_path_constraints',
    'phase_heap_layout', 'phase_z3_prove', 'phase_strided_interval',
    'extract_alloc_write_pairs', 'apply_interproc_summaries',
    'compute_final_verdict',
    'AllocSite', 'WriteSite', 'AllocWritePair',
    'AllocWriteExtractor', 'extract_alloc_write_pairs',
]
