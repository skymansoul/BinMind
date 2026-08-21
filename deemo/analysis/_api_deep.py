"""

包含: CFG构建、FP过滤阶段、格式字符串栈偏移、整数溢出约束、
     UAF时序/dominator验证、分配-写入提取器、FSTP、HOIG、PTASM、
     I-GUARD、GAPSBV、MIVR、贝叶斯融合、桥接模块等。
"""

# 深度分析模块
# CFG构建 (从heap_path_analyzer提取)
from analysis.heap_cfg_builder import (
    HeapCFGBuilder, build_heap_cfg,
)
# FP过滤阶段 (从unified_fp_filter提取)
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
# 格式字符串栈偏移推断
from analysis.fmt_stack_offset import (
    CallingConvention, StackOffsetEstimate, FmtCallSite,
    FormatStackOffsetAnalyzer, infer_fmt_offset,
)
# 整数溢出约束范围检查
from analysis.int_range_constraint import (
    IntWidth, Signedness, IntRange as IntConstraintRange,
    IntOpSite, IntRangeConstraintChecker, check_int_overflow_enhanced,
)
# UAF时序验证
from analysis.uaf_temporal_verifier import (
    TemporalVerdict, TemporalResult, UafTemporalVerifier,
    verify_uaf_temporal, verify_uaf_batch,
)
# UAF Dominator 验证器 — 2024-01-18
from analysis.uaf_dominator_verifier import (
    UAFDominatorVerifier, DominatorVerdict, DominatorResult,
    dominator_batch_verify,
)
# UAF跨过程生命周期摘要 — 2023-11-02
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
# 格式字符串DFA解析器 — 2023-11-02
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
# UAF四阶段FP削减级联 (TARP-E) — 2023-11-02
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
# 格式字符串影响计算 (从format_spec_scorer提取)
from analysis.format_impact_calculator import (
    compute_exploitability, compute_impact,
    compute_cia_impact, generate_assessment,
)
# UAF CFG构建 (从uaf_path_verifier提取)
from analysis.uaf_cfg_builder import (
    UafBasicBlock, UafCFGBuilder,
)
# 贝叶斯置信度融合 (跨管道统一评分引擎)
from analysis.bayesian_fusion import (
    BayesianFusionEngine, fuse_scores, risk_classify,
    probability_to_log_odds, log_odds_to_probability,
)
# 流水线阶段辅助 (从unified_heap_pipeline提取)
from analysis.pipeline_stage_helpers import (
    extract_alloc_write_pairs, apply_interproc_summaries,
    compute_final_verdict,
)

# 2023-11-02 分配-写入关系提取器 (数组写入 buf[idx]=x 模式)
from analysis.alloc_write_extractor import (
    AllocSite, WriteSite, AllocWritePair,
    AllocWriteExtractor, extract_alloc_write_pairs,
)

# 2024-01-18 FSTP (Format Semantic Taint Propagation) 格式说明符语义感知污点传播
from analysis.fmt_semantic_taint import (
    SemClass, FstpVerdict, FmtSemanticTaintPropagator,
)

# 2024-01-18 HOIG (Heap Object Identity Graph) 对象身份追踪 UAF检测
from analysis.uaf_hoig_types import (
    ObjState, ObjectID, ObjStateAtPoint,
    IdentityEdge, FuncObjSummary, UafHoigVerdict,
)
from analysis.uaf_hoig_builder import HoigBuilder
from analysis.uaf_hoig_propagator import HoigPropagator
from analysis.uaf_hoig_cross_func import HoigCrossFuncVerifier
from analysis.uaf_hoig_verifier import HoigVerifier, HoigReallocTracker

# 2024-01-18 PTASM (Pointer Temporal Automaton State Machine) UAF检测
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
# 2024-01-18 I-GUARD C源码级整数溢出检测 (8-pattern CWE分类器)
from analysis.int_overflow_c_source import (
    IntOverflowFinding,
    detect_int_overflow_c_source,
    detect_int_overflow_quick,
)
# 2024-01-18 循环归纳变量追踪
from analysis.int_loop_types import (
    InductionKind, InductionVar, LoopInfo, LoopOverflowRisk,
    integrate_loop_analysis_with_iguard,
)
from analysis.int_loop_induction import LoopInductionTracker

# 2024-01-18 GAPSBV端到端检测管道 (仿射关系+守卫+StridedInterval+分配器语义)
from analysis.gapsbv_pipeline import (
    GapsbvVerdict, DimensionResult, GapsbvReport,
    detect_heap_overflow_gapsbv, detect_heap_gapsbv_quick,
)
# GAPSBV 四维度分析函数
from analysis.gapsbv_dimensions import (
    _resolve_macros,
    dim1_affine_relations, dim2_guard_analysis,
    dim3_strided_interval, dim4_allocator_semantics,
)
# GAPSBV 后期维度 (dim3+dim4 完整实现, 从 gapsbv_dimensions 中拆分)
from analysis.gapsbv_dimensions_late import (  # noqa: F401
    _extract_size_interval, _estimate_sizeof,
)
# GAPSBV 维度5: 完备性检查安全网
from analysis.gapsbv_dimension5 import dim5_completeness_check  # noqa: F401
# 2024-01-18 MIVR: 路径敏感约束传播 (GAPSBV维度6)
from analysis.mivr_constraint_graph import (  # noqa: F401
    VarConstraint, GuardSite, ConstraintEdge, MIVRConstraintGraph,
)
from analysis.mivr_path_propagator import (  # noqa: F401
    PropagatedState, WriteSafetyVerdict, MIVRPathPropagator,
)
from analysis.mivr_proof_layers import (  # noqa: F401
    PairProof, prove_single,
    _shared_vars, _is_complex_expr,
    _extract_var_coef, _extract_const_term,
    _eval_expr_bound, _effective_boundary,
)
from analysis.mivr_pair_prover import MIVRPairProver  # noqa: F401
from analysis.mivr_pipeline import (  # noqa: F401
    dim6_mivr_constraint_proof,
    detect_heap_overflow_mivr,
    run_gapsbv_with_mivr,
)
# 2023-11-02 GAPSBV核心创新: 证明义务引擎 + 约束收集 + FP削减积分器
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
