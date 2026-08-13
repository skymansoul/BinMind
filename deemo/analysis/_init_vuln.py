"""分析增强模块漏洞验证导入: 格式化字符串/整型/栈/跨函数验证."""


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