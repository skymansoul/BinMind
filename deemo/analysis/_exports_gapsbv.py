"""GAPSBV/MIVR/Proof/Pipeline 模块导入 — 证明义务+约束+积分器+统一管线."""
from analysis.value_range_bridge import filter_by_value_range
try:
    from analysis.unified_pipeline import (
        UnifiedPipeline, PipelineReport, TierStage, VulnType, TierResult,
    )
except ImportError:
    UnifiedPipeline = None  # type: ignore
    PipelineReport = None  # type: ignore
    TierStage = None  # type: ignore
    VulnType = None  # type: ignore
    TierResult = None  # type: ignore
from analysis.pipeline_convenience import (
    run_heap_overflow_pipeline, run_uaf_pipeline,
    run_format_string_pipeline, run_int_overflow_pipeline,
)
from analysis.bayesian_fusion import (
    BayesianFusionEngine, fuse_scores, risk_classify,
    probability_to_log_odds, log_odds_to_probability,
)
# GAPSBV pipeline
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
# MIVR
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
# Proof obligation + FP reduction
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

__all__ = [
    'filter_by_value_range',
    'UnifiedPipeline', 'PipelineReport', 'TierResult',
    'TierStage', 'VulnType',
    'run_heap_overflow_pipeline', 'run_uaf_pipeline',
    'run_format_string_pipeline', 'run_int_overflow_pipeline',
    'BayesianFusionEngine', 'fuse_scores', 'risk_classify',
    'probability_to_log_odds', 'log_odds_to_probability',
    'GapsbvVerdict', 'DimensionResult', 'GapsbvReport',
    'detect_heap_overflow_gapsbv', 'detect_heap_gapsbv_quick',
    '_resolve_macros',
    'dim1_affine_relations', 'dim2_guard_analysis',
    'dim3_strided_interval', 'dim4_allocator_semantics',
    'dim5_completeness_check',
    '_extract_size_interval', '_estimate_sizeof',
    'VarConstraint', 'GuardSite', 'ConstraintEdge', 'MIVRConstraintGraph',
    'PropagatedState', 'WriteSafetyVerdict', 'MIVRPathPropagator',
    'PairProof', 'MIVRPairProver',
    'dim6_mivr_constraint_proof', 'detect_heap_overflow_mivr',
    'run_gapsbv_with_mivr',
    'HeapProofEngine', 'ProofVerdict', 'ProofObligation',
    'SizeConstraint', 'prove_heap_safety',
    'SizeConstraintCollector', 'SizeVarSummary', 'SizeVarConstraint',
    'apply_size_constraints_to_findings',
    'FPReductionIntegrator', 'AblationReport', 'StageStats',
    'stage1_allocator_semantics', 'stage2_guard_aware',
    'stage3_size_constraints', 'stage4_proof_obligations',
    'stage5_slack_space', 'stage6_value_range', 'stage7_non_heap',
]
