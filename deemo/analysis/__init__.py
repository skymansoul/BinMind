"""分析增强模块 — 四层 Tier 管线 + 多漏洞类型深度验证.

Tier 0 (分配器语义): allocator_model — ptmalloc2/jemalloc/tcmalloc request2size 转换
Tier 1 (仿射区间+路径条件): symbolic_range, cfg_parser, heap_expr_parser, path_sensitive_vrf
Tier 2 (选择性符号执行): selective_symexec — 仅符号化size参数, ≤8符号≤128路径
Tier 3 (不可行路径剪枝): infeasible_path_pruner — 区间代数约束一致性检测(无SMT)

多漏洞类型深度验证:
  - uaf_tarps_verifier: TARPS 五阶段误报削减
  - format_string_verifier: 三阶段常量折叠+污点传播+路径守卫
  - int_overflow_verifier: 值范围传播+守卫精化
"""

from analysis.strided_interval import (
    StridedInterval, si_singleton, si_interval, si_range,
    si_unbounded, si_from_mul,
)

# 核心创新模块
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

# 格式化字符串三阶段验证
from analysis.format_string_verifier import (
    FormatStringVerifier, FmtStringVerdict,
)

# 整数溢出值范围验证
from analysis.int_overflow_verifier import (
    IntOverflowVerifier, IntOverflowVerdict, ValueRange,
)

# 桥接模块
from analysis.fmt_taint_bridge import refine_fmt_findings
from analysis.int_overflow_bridge import refine_int_overflow_findings
from analysis.value_range_bridge import filter_by_value_range

# 统一管线
try:
    from analysis.unified_pipeline import (
        UnifiedPipeline, PipelineReport, TierStage, VulnType, TierResult,
    )
except (ImportError, AttributeError):
    UnifiedPipeline = None  # type: ignore
    PipelineReport = None  # type: ignore
    TierStage = None  # type: ignore
    VulnType = None  # type: ignore
    TierResult = None  # type: ignore
try:
    from analysis.pipeline_convenience import (
        run_heap_overflow_pipeline, run_uaf_pipeline,
        run_format_string_pipeline, run_int_overflow_pipeline,
    )
except (ImportError, AttributeError):
    run_heap_overflow_pipeline = None  # type: ignore
    run_uaf_pipeline = None  # type: ignore
    run_format_string_pipeline = None  # type: ignore
    run_int_overflow_pipeline = None  # type: ignore

# 深度分析模块
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
from analysis.fmt_stack_offset import (
    CallingConvention, StackOffsetEstimate, FmtCallSite,
    FormatStackOffsetAnalyzer, infer_fmt_offset,
)
from analysis.int_range_constraint import (
    IntWidth, Signedness, IntRange as IntConstraintRange,
    IntOpSite, IntRangeConstraintChecker, check_int_overflow_enhanced,
)
from analysis.uaf_temporal_verifier import (
    TemporalVerdict, TemporalResult, UafTemporalVerifier,
    verify_uaf_temporal, verify_uaf_batch,
)
from analysis.uaf_dominator_verifier import (
    UAFDominatorVerifier, DominatorVerdict, DominatorResult,
    dominator_batch_verify,
)
try:
    from analysis.uaf_interproc_summary import (
        Lifetime, HeapPtrSummary, FuncSummary,
        InterProcLifetimeAnalyzer,
    )
except ImportError:
    Lifetime = None  # type: ignore
    HeapPtrSummary = None  # type: ignore
    FuncSummary = None  # type: ignore
    InterProcLifetimeAnalyzer = None  # type: ignore
try:
    from analysis.fmt_parser_dfa import (
        FmtDanger, FmtSpec, ParsedFmtString,
        FmtStringParser, classify_fmt_danger,
    )
except ImportError:
    FmtDanger = None  # type: ignore
    FmtSpec = None  # type: ignore
    ParsedFmtString = None  # type: ignore
    FmtStringParser = None  # type: ignore
    classify_fmt_danger = None  # type: ignore
try:
    from analysis.uaf_fp_cascade import (
        UafVerdict, EscapeLevel, UafCandidate, CascadeReport,
        extract_uaf_candidates, run_uaf_cascade,
        phase0_pattern_safety, phase1_alias_lifetime,
        phase2_path_dominance, phase3_escape_analysis,
    )
except ImportError:
    UafVerdict = None  # type: ignore
    EscapeLevel = None  # type: ignore
    UafCandidate = None  # type: ignore
    CascadeReport = None  # type: ignore
    extract_uaf_candidates = None  # type: ignore
    run_uaf_cascade = None  # type: ignore
    phase0_pattern_safety = None  # type: ignore
    phase1_alias_lifetime = None  # type: ignore
    phase2_path_dominance = None  # type: ignore
    phase3_escape_analysis = None  # type: ignore
from analysis.format_impact_calculator import (
    compute_exploitability, compute_impact,
    compute_cia_impact, generate_assessment,
)
from analysis.uaf_cfg_builder import (
    UafBasicBlock, UafCFGBuilder,
)
from analysis.bayesian_fusion import (
    BayesianFusionEngine, fuse_scores, risk_classify,
    probability_to_log_odds, log_odds_to_probability,
)
from analysis.pipeline_stage_helpers import (
    extract_alloc_write_pairs, apply_interproc_summaries,
    compute_final_verdict,
)
from analysis.alloc_write_extractor import (
    AllocSite, WriteSite, AllocWritePair,
    AllocWriteExtractor, extract_alloc_write_pairs,
)
from analysis.fmt_semantic_taint import (
    SemClass, FstpVerdict, FmtSemanticTaintPropagator,
)
from analysis.uaf_hoig_types import (
    ObjState, ObjectID, ObjStateAtPoint,
    IdentityEdge, FuncObjSummary, UafHoigVerdict,
)
from analysis.uaf_hoig_builder import HoigBuilder
from analysis.uaf_hoig_propagator import HoigPropagator
from analysis.uaf_hoig_cross_func import HoigCrossFuncVerifier
from analysis.uaf_hoig_verifier import HoigVerifier, HoigReallocTracker

# PTASM UAF检测
from analysis.ptasm_engine import (
    PTASMEngine, PTASMStats, ptasm_analyze,
    ptasm_verify_candidates, ptasm_detect_uaf, ptasm_pipeline_detect,
    PTASM_PROTECTED, PTASM_CONFIRMED, PTASM_UNCERTAIN,
)
from analysis.ptasm_types import (
    PtrState, PtrTransition, PtrInfo, PTASMResult,
    parse_line_operations,
)
from analysis.ptasm_pipeline import (
    PTASM_PROTECTED, PTASM_CONFIRMED, PTASM_UNCERTAIN,
    ptasm_analyze, ptasm_verify_candidates,
    ptasm_detect_uaf, ptasm_pipeline_detect,
)
from analysis.ptasm_ctrl_flow import (
    normalize_single_line_ifs, find_branch_bodies, join_ptr_states,
)

# I-GUARD C源码级整数溢出检测
from analysis.int_overflow_c_source import (
    IntOverflowFinding,
    detect_int_overflow_c_source,
    detect_int_overflow_quick,
)

# GAPSBV端到端检测管道
from analysis.gapsbv_pipeline import (
    GapsbvVerdict, DimensionResult, GapsbvReport,
    detect_heap_overflow_gapsbv, detect_heap_gapsbv_quick,
)
from analysis.gapsbv_dimensions import (
    _resolve_macros,
    dim1_affine_relations, dim2_guard_analysis,
    dim3_strided_interval, dim4_allocator_semantics,
)
from analysis.gapsbv_dimensions_late import (  # noqa: F401
    _extract_size_interval, _estimate_sizeof,
)
from analysis.gapsbv_dimension5 import dim5_completeness_check  # noqa: F401

# MIVR 路径敏感约束传播
from analysis.mivr_constraint_graph import (  # noqa: F401
    VarConstraint, GuardSite, ConstraintEdge, MIVRConstraintGraph,
)
from analysis.mivr_path_propagator import (  # noqa: F401
    PropagatedState, WriteSafetyVerdict, MIVRPathPropagator,
)
from analysis.mivr_pair_prover import PairProof, MIVRPairProver  # noqa: F401
from analysis.mivr_pipeline import (  # noqa: F401
    dim6_mivr_constraint_proof,
    detect_heap_overflow_mivr,
    run_gapsbv_with_mivr,
)

# GAPSBV核心创新: 证明义务引擎 + 约束收集 + FP削减积分器
try:
    from analysis.heap_proof_types import (
        ProofVerdict, ProofObligation, SizeConstraint,
    )
    from analysis.heap_proof_obligation import (
        HeapProofEngine, prove_heap_safety,
    )
except ImportError:
    HeapProofEngine = None  # type: ignore
    ProofVerdict = None  # type: ignore
    ProofObligation = None  # type: ignore
    SizeConstraint = None  # type: ignore
    prove_heap_safety = None  # type: ignore

try:
    from analysis.size_constraint_collector import (
        SizeConstraintCollector, SizeVarSummary, SizeVarConstraint,
        apply_size_constraints_to_findings,
    )
except ImportError:
    SizeConstraintCollector = None  # type: ignore
    SizeVarSummary = None  # type: ignore
    SizeVarConstraint = None  # type: ignore
    apply_size_constraints_to_findings = None  # type: ignore

try:
    from analysis.fp_reduction_integrator import (
        FPReductionIntegrator, AblationReport, StageStats,
    )
except ImportError:
    FPReductionIntegrator = None  # type: ignore
    AblationReport = None  # type: ignore
    StageStats = None  # type: ignore

try:
    from analysis.fp_filter_stages import (
        stage1_allocator_semantics, stage2_guard_aware,
        stage3_size_constraints, stage4_proof_obligations,
        stage5_slack_space, stage6_value_range, stage7_non_heap,
    )
except ImportError:
    stage1_allocator_semantics = None  # type: ignore
    stage2_guard_aware = None  # type: ignore
    stage3_size_constraints = None  # type: ignore
    stage4_proof_obligations = None  # type: ignore
    stage5_slack_space = None  # type: ignore
    stage6_value_range = None  # type: ignore
    stage7_non_heap = None  # type: ignore

# ── HEAD 侧保留项: core 组件再导出 (modules/info/analysis/heap_fp_filter.py 等仍在使用) ──
from core.vsa_lite import analyze_vsa, StrideInterval, HeapObj, MemWrite
from core.interval_filter import classify, apply_filter, filter_stats, Tier, FilterResult
from core.cfg_normalizer import extract_cfg_features, CFGFeatures
