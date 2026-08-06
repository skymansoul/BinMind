"""Fuzzing core submodules -- re-exports for convenience."""

from .core import Seed, FuzzConfig, FuzzResult, CorpusStats
from .coverage import CoverageBitmap, EdgeCoverage, CoverageTracker
from .scheduler import Scheduler, CorpusManager, pick_seed, cull_queue
# 新增时态新颖度调度器
from .decaying_novelty_scheduler import (
    DecayingNoveltyScheduler, NoveltyRecord,
)
# 种子关系图（已有实现）
from .seed_relation_graph import SeedRelationGraph, SeedNode
# 在线结构约束推断变异器
from .constraint_inference_mutator import (
    ConstraintInferenceMutator, ConstraintType, ByteConstraint,
)
# 差分跟踪制导变异器
from .trace_diff_mutator import (
    TraceDiffMutator, TraceDiffResult, BifurcationPoint, TraceEntry,
)
# 跨层模糊测试-分布式调度桥接
from .cross_layer_fuzz_bridge import (
    CrossLayerFuzzBridge, FuzzCampaignConfig, launch_distributed_campaign,
)
# 语义执行新颖度检测器
from .semantic_novelty_detector import (
    SemanticNoveltyDetector, ExecutionSummary, NoveltyGuidedEnergyPolicy,
)
# Thompson 采样多模糊器编排
from .thompson_orchestrator import (
    ThompsonOrchestrator, FuzzerArm, make_crash_signature,
)
# 约束感知 def-use 链引导变异
from .defuse_mutation_guide import (
    ConstraintGuidedMutator, ConditionBranchCollector,
    defuse_guided_mutation_pipeline, BranchCoverageFingerprint,
)
# 2025-08 专利级创新 — 反事实变异优化 (SCM rung-3)
from .counterfactual_mutator import CounterfactualMutator
from .counterfactual_types import (
    CounterfactualEstimate, MutationObservation,
)
# 2025-08 专利级创新 — 对抗遗憾最小化突变集成 (FTRL+Entropy)
from .regret_minimizing_ensemble import RegretMinimizingEnsemble
from .regret_strategies import (
    StrategyState, RegretSnapshot,
)
# 2025-08 专利级创新 — 拓扑覆盖导航 (持久同调)
from .topological_coverage_navigator import (
    TopologicalCoverageNavigator, CoveragePoint, TopologicalFeature,
)
from .persistence_homology import (
    jaccard_distance, maximin_landmarks, single_linkage_persistence,
)
# 2025-08 专利级创新 — 信息几何制导变异 (Fisher 信息度量)
from .fisher_mutation import (
    FisherMutationSelector, FisherByteProfile,
)
# 2025-08 专利级创新 — 最优传输种子分发 (Sinkhorn/Wasserstein)
from .optimal_transport_seed import (
    OptimalTransportSeedDistributor, TransportPlan, SeedRecord,
)
# 2025-08 专利级创新 — 跨输入不变性谱分析 (MCD 离群检测)
from .invariant_spectrum_analyzer import InvariantSpectrumAnalyzer
from .invariant_types import (
    Invariant, InputSpectrum, InvariantType,
)
# 2025-08 专利级创新 — Sinkhorn 最优传输求解器
from .sinkhorn_solver import (
    sinkhorn_ot, jaccard_dist as ot_jaccard, fingerprint as ot_fingerprint,
)
# 2025-08 专利级创新 — 保形预测异常检测 (分布无关有限样本保证)
from .conformal_anomaly import (
    ConformalAnomalyDetector, ExecutionProfile,
)
# 2025-08 专利级创新 — 鞅评估 + 生存分析 (随时有效推断)
from .martingale_tester import (
    TestMartingale, SequentialProbabilityRatioTest, e_value_from_probability,
)
from .martingale_fuzz_assess import (
    MartingaleFuzzingAssessor, FuzzingEvidence,
)
from .survival_fuzz_model import (
    SurvivalFuzzModel, BugDiscoveryEvent,
)
# 2025-08 专利级创新 — 谱图分解/GP代理/Hawkes自激
from .spectral_seed_graph import (
    SpectralSeedGraphDecomposer, SpectralDecomposition,
)
from .gaussian_process_surrogate import (
    GaussianProcessSurrogate, GPObservation,
)
from .hawkes_crash_model import (
    HawkesCrashModel, CrashEvent,
)
# 2025-08 专利级创新 — RMT诊断/MMD检验/ONS二阶
from .rmt_diagnostics import (
    RMTDiagnostics, RMTDiagnostic,
)
from .mmd_seed_test import (
    MMDSeedDistributionTest, MMDResult,
)
from .online_newton_mutate import (
    OnlineNewtonMutationAdaptor, MutationOperator,
)
# 2025-08 专利级创新 — 次模选择/KSD评估/Beta过程
from .submodular_seed_selector import (
    SubmodularSeedSelector, SeedCandidate,
)
from .stein_seed_assess import (
    SteinSeedAssessor, KSDResult,
)
from .beta_process_coverage import (
    BetaProcessCoverageModel, CoverageFeature,
)
# 2025-08 专利级创新 — 经验似然/密度比/RM调参
from .empirical_likelihood import (
    EmpiricalLikelihoodInference, ELCIResult,
)
from .density_ratio_compare import (
    DensityRatioComparator, DRSCResult,
)
from .robbins_monro_tune import (
    RobbinsMonroTuner, ParameterState,
)
# 2025-08 深度创新 — Woodbury在线GP / 异构因果效应 / Mapper拓扑
from .gp_woodbury_online import GPWoodburyOnline, GPOnlineState
from .causal_heterogeneous_effects import (
    CausalHeterogeneousEffects, CausalLeaf, CATEResult,
)
from .mapper_coverage import (
    MapperCoverageAnalyzer, MapperNode, MapperEdge, MapperResult,
)
# 2025-08 专利级创新 — 距离相关/能量距离/PELT变点
from .distance_correlation import (
    DistanceCorrelationAnalyzer, DCorResult,
)
from .energy_distance_seed import (
    EnergyDistanceSeedTest, EnergyDistanceResult,
)
from .pelt_change_point import (
    PELTChangeDetector, ChangePoint, PELTResult,
)
# 2025-08 专利级创新 — 鲁棒M估计/保序回归/函数型PCA
from .robust_m_estimation import (
    RobustMEstimator, RobustEstimate,
)
from .isotonic_coverage import (
    IsotonicCoverageModel, IsotonicFit,
)
from .functional_pca_coverage import (
    FunctionalPCACoverage, FPCAResult,
)
# 2025-08 专利级创新 — MDL选择/D-最优/图信号
from .mdl_strategy_select import (
    MDLStrategySelector, MDLResult,
)
from .doptimal_mutation_plan import (
    DOptimalMutationPlanner, DesignPoint,
)
from .graph_signal_seed import (
    GraphSignalProcessor, GraphSignalResult,
)
# 2025-08 专利级创新 — Copula/FDR/Granger因果
from .copula_coverage_model import CopulaCoverageModel, CopulaResult
from .fdr_crash_classify import FDRController, FDRResult
from .granger_coverage import GrangerCausalityTest, GrangerResult

__all__ = [
    "Seed",
    "FuzzConfig",
    "FuzzResult",
    "CorpusStats",
    "CoverageBitmap",
    "EdgeCoverage",
    "CoverageTracker",
    "Scheduler",
    "CorpusManager",
    "pick_seed",
    "cull_queue",
    "DecayingNoveltyScheduler",
    "NoveltyRecord",
    "SeedRelationGraph",
    "SeedNode",
    "ConstraintInferenceMutator",
    "ConstraintType",
    "ByteConstraint",
    "TraceDiffMutator",
    "TraceDiffResult",
    "BifurcationPoint",
    "TraceEntry",
    # 2025-07/08 跨层桥接
    "CrossLayerFuzzBridge",
    "FuzzCampaignConfig",
    "launch_distributed_campaign",
    # Q3 2025 语义/编排/变异创新
    "SemanticNoveltyDetector",
    "ExecutionSummary",
    "NoveltyGuidedEnergyPolicy",
    "ThompsonOrchestrator",
    "FuzzerArm",
    "make_crash_signature",
    "ConstraintGuidedMutator",
    "ConditionBranchCollector",
    "defuse_guided_mutation_pipeline",
    "BranchCoverageFingerprint",
    # 2025-08 反事实/遗憾最小化/拓扑导航
    "CounterfactualMutator",
    "CounterfactualEstimate",
    "MutationObservation",
    "RegretMinimizingEnsemble",
    "StrategyState",
    "RegretSnapshot",
    "TopologicalCoverageNavigator",
    "CoveragePoint",
    "TopologicalFeature",
    # 2025-08 信息几何/最优传输/不变性谱
    "FisherMutationSelector",
    "FisherByteProfile",
    "OptimalTransportSeedDistributor",
    "TransportPlan",
    "SeedRecord",
    "InvariantSpectrumAnalyzer",
    "Invariant",
    "InputSpectrum",
    # 2025-08 保形预测/鞅评估/生存分析
    "ConformalAnomalyDetector",
    "ExecutionProfile",
    "TestMartingale",
    "SequentialProbabilityRatioTest",
    "MartingaleFuzzingAssessor",
    "FuzzingEvidence",
    "SurvivalFuzzModel",
    "BugDiscoveryEvent",
    # 2025-08 谱图/GP代理/Hawkes
    "SpectralSeedGraphDecomposer",
    "SpectralDecomposition",
    "GaussianProcessSurrogate",
    "GPObservation",
    "HawkesCrashModel",
    "CrashEvent",
    # 2025-08 RMT/MMD/ONS
    "RMTDiagnostics",
    "RMTDiagnostic",
    "MMDSeedDistributionTest",
    "MMDResult",
    "OnlineNewtonMutationAdaptor",
    "MutationOperator",
    # 2025-08 次模选择/KSD/Beta过程
    "SubmodularSeedSelector",
    "SeedCandidate",
    "SteinSeedAssessor",
    "KSDResult",
    "BetaProcessCoverageModel",
    "CoverageFeature",
    # 2025-08 经验似然/密度比/RM调参
    "EmpiricalLikelihoodInference",
    "ELCIResult",
    "DensityRatioComparator",
    "DRSCResult",
    "RobbinsMonroTuner",
    "ParameterState",
]
