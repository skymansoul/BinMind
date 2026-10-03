"""Fuzzing module -- lazy-loads submodules on demand."""

_LAZY_IMPORTS: dict[str, tuple[str, str]] = {
    "Seed": ("fuzzing.src.core", "Seed"),
    "FuzzConfig": ("fuzzing.src.core", "FuzzConfig"),
    "FuzzResult": ("fuzzing.src.core", "FuzzResult"),
    "CorpusStats": ("fuzzing.src.core", "CorpusStats"),
    "CoverageBitmap": ("fuzzing.src.coverage", "CoverageBitmap"),
    "EdgeCoverage": ("fuzzing.src.coverage", "EdgeCoverage"),
    "CoverageTracker": ("fuzzing.src.coverage", "CoverageTracker"),
    "Scheduler": ("fuzzing.src.scheduler", "Scheduler"),
    "CorpusManager": ("fuzzing.src.scheduler", "CorpusManager"),
    "pick_seed": ("fuzzing.src.scheduler", "pick_seed"),
    "cull_queue": ("fuzzing.src.scheduler", "cull_queue"),
    # 延迟加载 -- 仅在显式引用时导入
    "FaultInjectionFuzzer": ("fuzzing.fault_injection_fuzzer", "FaultInjectionFuzzer"),
    "FaultInjectionResult": ("fuzzing.fault_injection_fuzzer", "FaultInjectionResult"),
    "ClusterAutoscaler": ("fuzzing.fuzz_cluster_autoscaler", "ClusterAutoscaler"),
    "TaskQueue": ("fuzzing.fuzz_cluster_autoscaler", "TaskQueue"),
    "NodeRegistry": ("fuzzing.fuzz_cluster_autoscaler", "NodeRegistry"),
    "SeedEvolution": ("fuzzing.fuzz_seed_evolution", "SeedEvolution"),
    "FuzzDictionaryGenerator": ("fuzzing.fuzz_dictionary_generator", "FuzzDictionaryGenerator"),
    "ConstantExtractor": ("fuzzing.fuzz_dictionary_generator", "ConstantExtractor"),
    # 2026-07 扩展模块 -- MAB调度/崩溃去重/结构感知变异/输入最小化/活动追踪/差分测试/符号桥接/能量策略
    "BanditScheduler": ("fuzzing.fuzz_bandit_scheduler", "BanditScheduler"),
    "CrashClusteringEngine": ("fuzzing.fuzz_crash_triage", "CrashClusteringEngine"),
    "StructureAwareMutator": ("fuzzing.fuzz_structure_mutator", "StructureAwareMutator"),
    "InputMinimizer": ("fuzzing.fuzz_input_minimizer", "InputMinimizer"),
    "CampaignTracker": ("fuzzing.fuzz_campaign_tracker", "CampaignTracker"),
    "DiffFuzzer": ("fuzzing.fuzz_diff_testing", "DiffFuzzer"),
    "SymbolicBridge": ("fuzzing.fuzz_symbolic_bridge", "SymbolicBridge"),
    "EnergyComputer": ("fuzzing.fuzz_energy_policy", "EnergyComputer"),
    # 2026-08 扩展 -- 污点引导/文法推断/语料优化/渐进式流水线/对比评估/覆盖异常/定向模糊测试
    "TaintGuidedMutator": ("fuzzing.fuzz_taint_guide", "TaintGuidedMutator"),
    "GrammarInferrer": ("fuzzing.fuzz_grammar_infer", "GrammarInferrer"),
    "CorpusOptimizer": ("fuzzing.fuzz_corpus_optimizer", "CorpusOptimizer"),
    "ProgressivePipeline": ("fuzzing.fuzz_progressive", "ProgressivePipeline"),
    "FuzzerComparator": ("fuzzing.fuzz_compare", "FuzzerComparator"),
    "CoverageAnomalyDetector": ("fuzzing.fuzz_coverage_anomaly", "CoverageAnomalyDetector"),
    "DirectedFuzzer": ("fuzzing.fuzz_directed", "DirectedFuzzer"),
    # 2026-08 扩展 -- 种子关系图/多目标Pareto归档 (跨代非支配保留)
    "SeedRelationGraph": ("fuzzing.src.seed_relation_graph", "SeedRelationGraph"),
    "SeedNode": ("fuzzing.src.seed_relation_graph", "SeedNode"),
    "ParetoArchive": ("fuzzing.src.pareto_archive", "ParetoArchive"),
    "ParetoEntry": ("fuzzing.src.pareto_archive", "ParetoEntry"),
    # 2026-08 扩展 -- 路径聚类(MinHash LSH)/突变策略集成(指数梯度)
    "PathCluster": ("fuzzing.src.path_trace_cluster", "PathCluster"),
    "PathSignature": ("fuzzing.src.path_trace_cluster", "PathSignature"),
    "MutationEnsemble": ("fuzzing.src.mutation_ensemble", "MutationEnsemble"),
    "MutationStrategy": ("fuzzing.src.mutation_ensemble", "MutationStrategy"),
    # 2026-08 扩展 -- 覆盖感知拼接(CASS)/执行开销预测器(ECF分位数回归)
    "CoverageAwareSplicer": ("fuzzing.src.coverage_splicer", "CoverageAwareSplicer"),
    "CoverageRegion": ("fuzzing.src.coverage_splicer", "CoverageRegion"),
    "SpliceCandidate": ("fuzzing.src.coverage_splicer", "SpliceCandidate"),
    "ExecutionCostForecaster": ("fuzzing.src.exec_cost_forecaster", "ExecutionCostForecaster"),
    "CostEstimate": ("fuzzing.src.exec_cost_forecaster", "CostEstimate"),
    # 2025-08 专利级创新 — 反事实变异/对抗遗憾/拓扑导航
    "CounterfactualMutator": ("fuzzing.src.counterfactual_mutator", "CounterfactualMutator"),
    "CounterfactualEstimate": ("fuzzing.src.counterfactual_types", "CounterfactualEstimate"),
    "RegretMinimizingEnsemble": ("fuzzing.src.regret_minimizing_ensemble", "RegretMinimizingEnsemble"),
    "TopologicalCoverageNavigator": ("fuzzing.src.topological_coverage_navigator", "TopologicalCoverageNavigator"),
    "TopologicalFeature": ("fuzzing.src.topological_coverage_navigator", "TopologicalFeature"),
    # 2025-08 信息几何/最优传输/不变性谱
    "FisherMutationSelector": ("fuzzing.src.fisher_mutation", "FisherMutationSelector"),
    "OptimalTransportSeedDistributor": ("fuzzing.src.optimal_transport_seed", "OptimalTransportSeedDistributor"),
    "InvariantSpectrumAnalyzer": ("fuzzing.src.invariant_spectrum_analyzer", "InvariantSpectrumAnalyzer"),
    # 2025-08 保形预测/鞅评估/生存分析
    "ConformalAnomalyDetector": ("fuzzing.src.conformal_anomaly", "ConformalAnomalyDetector"),
    "MartingaleFuzzingAssessor": ("fuzzing.src.martingale_fuzz_assess", "MartingaleFuzzingAssessor"),
    "SurvivalFuzzModel": ("fuzzing.src.survival_fuzz_model", "SurvivalFuzzModel"),
    # 跨战役元学习 / 对抗覆盖突破 / 平台期因果分析
    "CrossCampaignMetaLearner": ("fuzzing.fuzz_meta_learner", "CrossCampaignMetaLearner"),
    "CampaignFingerprint": ("fuzzing.fuzz_meta_learner", "CampaignFingerprint"),
    "AdversarialCoverageBreaker": ("fuzzing.fuzz_adversarial_breaker", "AdversarialCoverageBreaker"),
    "CoverageFrontierTracker": ("fuzzing.fuzz_adversarial_breaker", "CoverageFrontierTracker"),
    "PlateauBottleneckAnalyzer": ("fuzzing.fuzz_plateau_analyzer", "PlateauBottleneckAnalyzer"),
    # 2025-08 谱图分解/GP代理/Hawkes自激
    "SpectralSeedGraphDecomposer": ("fuzzing.src.spectral_seed_graph", "SpectralSeedGraphDecomposer"),
    "GaussianProcessSurrogate": ("fuzzing.src.gaussian_process_surrogate", "GaussianProcessSurrogate"),
    "HawkesCrashModel": ("fuzzing.src.hawkes_crash_model", "HawkesCrashModel"),
    # 2025-08 RMT诊断/MMD检验/ONS二阶
    "RMTDiagnostics": ("fuzzing.src.rmt_diagnostics", "RMTDiagnostics"),
    "MMDSeedDistributionTest": ("fuzzing.src.mmd_seed_test", "MMDSeedDistributionTest"),
    "OnlineNewtonMutationAdaptor": ("fuzzing.src.online_newton_mutate", "OnlineNewtonMutationAdaptor"),
    # 2025-08 次模选择/KSD评估/Beta过程
    "SubmodularSeedSelector": ("fuzzing.src.submodular_seed_selector", "SubmodularSeedSelector"),
    "SteinSeedAssessor": ("fuzzing.src.stein_seed_assess", "SteinSeedAssessor"),
    "BetaProcessCoverageModel": ("fuzzing.src.beta_process_coverage", "BetaProcessCoverageModel"),
    # 2025-08 经验似然/密度比/RM调参
    "EmpiricalLikelihoodInference": ("fuzzing.src.empirical_likelihood", "EmpiricalLikelihoodInference"),
    "DensityRatioComparator": ("fuzzing.src.density_ratio_compare", "DensityRatioComparator"),
    "RobbinsMonroTuner": ("fuzzing.src.robbins_monro_tune", "RobbinsMonroTuner"),
    # 2025-08 距离相关/能量距离/PELT变点
    "DistanceCorrelationAnalyzer": ("fuzzing.src.distance_correlation", "DistanceCorrelationAnalyzer"),
    "EnergyDistanceSeedTest": ("fuzzing.src.energy_distance_seed", "EnergyDistanceSeedTest"),
    "PELTChangeDetector": ("fuzzing.src.pelt_change_point", "PELTChangeDetector"),
    # 2025-08 鲁棒M估计/保序回归/函数型PCA
    "RobustMEstimator": ("fuzzing.src.robust_m_estimation", "RobustMEstimator"),
    "IsotonicCoverageModel": ("fuzzing.src.isotonic_coverage", "IsotonicCoverageModel"),
    "FunctionalPCACoverage": ("fuzzing.src.functional_pca_coverage", "FunctionalPCACoverage"),
}

_IMPORT_CACHE: dict[str, object] = {}


def __getattr__(name: str) -> object:
    if name in _IMPORT_CACHE:
        return _IMPORT_CACHE[name]
    _entry = _LAZY_IMPORTS.get(name)
    if _entry is None:
        raise AttributeError(f"module 'fuzzing' has no attribute {name!r}")
    _mod_name, _attr_name = _entry
    _mod = __import__(_mod_name, fromlist=[_attr_name])
    _obj = getattr(_mod, _attr_name)
    _IMPORT_CACHE[name] = _obj
    return _obj


__all__ = sorted(_LAZY_IMPORTS.keys())
