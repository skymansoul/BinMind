"""分析增强模块高阶导入: 对象身份图 (Object Identity Graph)/PTASM/仿射边界验证 (Affine Bound Verification)/路径敏感约束传播 (Path-Sensitive Constraint Propagation) 管道."""


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

# 仿射边界验证 (Affine Bound Verification) 端到端检测管道
from analysis.affine_bound_pipeline import (
    GapsbvVerdict, DimensionResult, GapsbvReport,
    detect_heap_overflow_gapsbv, detect_heap_gapsbv_quick,
)
from analysis.affine_bound_dimensions import (
    _resolve_macros,
    dim1_affine_relations, dim2_guard_analysis,
    dim3_strided_interval, dim4_allocator_semantics,
)
from analysis.affine_bound_dimensions_late import (  # noqa: F401
    _extract_size_interval, _estimate_sizeof,
)
from analysis.affine_bound_dimension5 import dim5_completeness_check  # noqa: F401

# 路径敏感约束传播 (Path-Sensitive Constraint Propagation)
from analysis.path_proof_constraint_graph import (  # noqa: F401
    VarConstraint, GuardSite, ConstraintEdge, MIVRConstraintGraph,
)
from analysis.path_proof_path_propagator import (  # noqa: F401
    PropagatedState, WriteSafetyVerdict, MIVRPathPropagator,
)
from analysis.path_proof_pair_prover import PairProof, MIVRPairProver  # noqa: F401
from analysis.path_proof_pipeline import (  # noqa: F401
    dim6_mivr_constraint_proof,
    detect_heap_overflow_mivr,
    run_gapsbv_with_mivr,
)

# 仿射边界验证 (Affine Bound Verification): 证明义务引擎 + 约束收集 + FP削减积分器
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