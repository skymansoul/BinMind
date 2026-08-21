# platform/ 平台专项：固件、内核、硬件、移动端、恶意软件、智能合约
# 导出符号整合，保持与 modules/__init__.py _FlatFinder 兼容
# 懒加载入口 — 与 firmware/kernel/hardware 子包采用相同的 __getattr__ 模式。
# 模块首次访问时才 import，避免冷启动加载所有平台分析器。
# 注意：此文件不承担子包内部的懒加载，子包 __init__.py 各自管理符号表。

__all__ = [
    # 跨平台关联
    'PropagationGraph', 'PlatformLayer', 'VulnNode', 'PropagationEdge',
    'CrossPlatformCorrelator',
    # 版本演化
    'VersionLattice', 'VersionNode', 'VulnIntroductionWitness',
    # 来源追踪
    'ProvenanceGraph', 'ProvenanceNode', 'DependencyEdge',
    'ProvenanceLatticeIntegrator',
    # 风险评分与协调
    'RiskScorer', 'PlatformOrchestrator', 'OrchestratorReport',
    # 差分-格桥接
    'DiffLatticeBridge', 'ClassifiedDiff', 'DiffClassification',
    # 跨层污点追踪
    'TaintBridge', 'TaintHop', 'TaintPath', 'TaintHopDirection',
    'MMIOToRegisterMapper', 'TaintHopInferrer',
    # 传播生存分析
    'PropagationSurvivalAnalyzer', 'KaplanMeierEstimator', 'SurvivalEvent',
    'CoxPHModel',
    # 反事实因果引擎
    'StructuralCausalPropagator', 'CounterfactualQuery',
    'CounterfactualResult', 'CounterfactualBatchAnalyzer',
    # 最小见证集——子模优化选择（专利级创新）
    'SubmodularCoverageFunction', 'LazyGreedyWitnessSelector',
    'WitnessSetManager', 'WitnessCandidate',
    # 传播图对抗鲁棒强化
    'AdversarialHardeningEngine', 'EdgeDistribution',
    # 持续同调拓扑指纹
    'PropagationHomologyAnalyzer', 'PersistenceDiagram',
    'PersistencePoint', 'bottleneck_distance',
    # 跨层迁移风险模型
    'LayerInvariantEncoder', 'NodeFeature',
    # 传播图变点检测
    'PropagationChangeDetector', 'GraphSnapshot', 'ChangePoint',
    # 共形风险预测
    'StratifiedConformalCalibrator', 'ConformalRiskAnalyzer',
    'ConformalInterval',
    # 帕累托补丁优化
    'NSGA2PatchOptimizer', 'PatchCandidate', 'PatchSolution',
    'layer_specific_cost', 'layer_specific_impact',
    # 时序因果发现
    'TemporalCausalDiscoverer', 'CausalEdge', 'CausalGraph',
    # 最优传输图对齐
    'SinkhornPropagationAligner', 'TransportPlan',
    # 差分隐私传播图
    'DifferentialPrivacyGraph', 'PrivacyBudget', 'LaplaceMechanism',
    'privacy_preserving_share',
    # 集成卡尔曼风险估计
    'EnsembleKalmanRiskFilter', 'RiskMeasurement', 'EnKFState',
    # 稀有级联模拟
    'RareCascadeSimulator', 'CascadePath', 'CascadeEstimate',
    # 对比传播路径嵌入
    'ContrastivePathEncoder', 'PathSample',
    # 鞅校准检验
    'MartingaleCalibrationTester', 'CalibrationReport',
    # 主动学习边选择
    'ActiveEdgeSelector', 'EdgeQueryCandidate',
    # Bootstrap传播置信区间
    'PropagationBootstrap', 'BootstrapResult',
    # 高斯过程风险曲面
    'GaussianProcessRisk', 'GPPrediction',
    # 谱聚类漏洞家族识别
    'SpectralVulnClusterer', 'VulnCluster',
    # 赌博机边调查优化
    'LinUCBEdgeInvestigator', 'ArmContext', 'InvestigationResult',
    # DAG消息传递风险预测
    'DAGMessagePassingRisk',
]


def __getattr__(name):
    _LAZY = {
        'PropagationGraph': ('.propagation_graph', 'PropagationGraph'),
        'PlatformLayer': ('.propagation_graph', 'PlatformLayer'),
        'VulnNode': ('.propagation_graph', 'VulnNode'),
        'PropagationEdge': ('.propagation_graph', 'PropagationEdge'),
        'CrossPlatformCorrelator': ('.cross_platform_correlator', 'CrossPlatformCorrelator'),
        'VersionLattice': ('.version_lattice', 'VersionLattice'),
        'VersionNode': ('.version_lattice', 'VersionNode'),
        'VulnIntroductionWitness': ('.version_lattice', 'VulnIntroductionWitness'),
        'ProvenanceGraph': ('.binary_provenance', 'ProvenanceGraph'),
        'ProvenanceNode': ('.binary_provenance', 'ProvenanceNode'),
        'DependencyEdge': ('.binary_provenance', 'DependencyEdge'),
        'ProvenanceLatticeIntegrator': ('.binary_provenance', 'ProvenanceLatticeIntegrator'),
        'RiskScorer': ('.risk_scorer', 'RiskScorer'),
        'PlatformOrchestrator': ('.platform_orchestrator', 'PlatformOrchestrator'),
        'OrchestratorReport': ('.platform_orchestrator', 'OrchestratorReport'),
        'DiffLatticeBridge': ('.diff_lattice_bridge', 'DiffLatticeBridge'),
        'ClassifiedDiff': ('.diff_lattice_bridge', 'ClassifiedDiff'),
        'DiffClassification': ('.diff_lattice_bridge', 'DiffClassification'),
        'TaintBridge': ('.taint_bridge', 'TaintBridge'),
        'TaintHop': ('.taint_bridge', 'TaintHop'),
        'TaintPath': ('.taint_bridge', 'TaintPath'),
        'TaintHopDirection': ('.taint_bridge', 'TaintHopDirection'),
        'MMIOToRegisterMapper': ('.taint_bridge', 'MMIOToRegisterMapper'),
        'TaintHopInferrer': ('.taint_hop_inferrer', 'TaintHopInferrer'),
        'PropagationSurvivalAnalyzer': ('.propagation_survival', 'PropagationSurvivalAnalyzer'),
        'KaplanMeierEstimator': ('.propagation_survival', 'KaplanMeierEstimator'),
        'SurvivalEvent': ('.propagation_survival', 'SurvivalEvent'),
        'CoxPHModel': ('.survival_cox', 'CoxPHModel'),
        'StructuralCausalPropagator': ('.counterfactual_engine', 'StructuralCausalPropagator'),
        'CounterfactualQuery': ('.counterfactual_engine', 'CounterfactualQuery'),
        'CounterfactualResult': ('.counterfactual_engine', 'CounterfactualResult'),
        'CounterfactualBatchAnalyzer': ('.counterfactual_engine', 'CounterfactualBatchAnalyzer'),
        'SubmodularCoverageFunction': ('.minimal_witness_set', 'SubmodularCoverageFunction'),
        'LazyGreedyWitnessSelector': ('.minimal_witness_set', 'LazyGreedyWitnessSelector'),
        'WitnessSetManager': ('.minimal_witness_set', 'WitnessSetManager'),
        'WitnessCandidate': ('.minimal_witness_set', 'WitnessCandidate'),
        'AdversarialHardeningEngine': ('.adversarial_hardening', 'AdversarialHardeningEngine'),
        'EdgeDistribution': ('.adversarial_hardening', 'EdgeDistribution'),
        'PropagationHomologyAnalyzer': ('.propagation_homology', 'PropagationHomologyAnalyzer'),
        'PersistenceDiagram': ('.propagation_homology', 'PersistenceDiagram'),
        'PersistencePoint': ('.propagation_homology', 'PersistencePoint'),
        'bottleneck_distance': ('.propagation_homology', 'bottleneck_distance'),
        'LayerInvariantEncoder': ('.cross_layer_transfer', 'LayerInvariantEncoder'),
        'NodeFeature': ('.cross_layer_transfer', 'NodeFeature'),
        'PropagationChangeDetector': ('.propagation_change_point', 'PropagationChangeDetector'),
        'GraphSnapshot': ('.propagation_change_point', 'GraphSnapshot'),
        'ChangePoint': ('.propagation_change_point', 'ChangePoint'),
        'StratifiedConformalCalibrator': ('.conformal_risk', 'StratifiedConformalCalibrator'),
        'ConformalRiskAnalyzer': ('.conformal_risk', 'ConformalRiskAnalyzer'),
        'ConformalInterval': ('.conformal_risk', 'ConformalInterval'),
        'NSGA2PatchOptimizer': ('.pareto_patch_optimizer', 'NSGA2PatchOptimizer'),
        'PatchCandidate': ('.pareto_patch_optimizer', 'PatchCandidate'),
        'PatchSolution': ('.pareto_patch_optimizer', 'PatchSolution'),
        'layer_specific_cost': ('.pareto_patch_optimizer', 'layer_specific_cost'),
        'layer_specific_impact': ('.pareto_patch_optimizer', 'layer_specific_impact'),
        'TemporalCausalDiscoverer': ('.temporal_causal_discovery', 'TemporalCausalDiscoverer'),
        'CausalEdge': ('.temporal_causal_discovery', 'CausalEdge'),
        'CausalGraph': ('.temporal_causal_discovery', 'CausalGraph'),
        'SinkhornPropagationAligner': ('.optimal_transport_align', 'SinkhornPropagationAligner'),
        'TransportPlan': ('.optimal_transport_align', 'TransportPlan'),
        'DifferentialPrivacyGraph': ('.differential_privacy_graph', 'DifferentialPrivacyGraph'),
        'PrivacyBudget': ('.differential_privacy_graph', 'PrivacyBudget'),
        'LaplaceMechanism': ('.differential_privacy_graph', 'LaplaceMechanism'),
        'privacy_preserving_share': ('.differential_privacy_graph', 'privacy_preserving_share'),
        'LinUCBEdgeInvestigator': ('.bandit_edge_investigator', 'LinUCBEdgeInvestigator'),
        'ArmContext': ('.bandit_edge_investigator', 'ArmContext'),
        'InvestigationResult': ('.bandit_edge_investigator', 'InvestigationResult'),
        'DAGMessagePassingRisk': ('.graph_neural_risk', 'DAGMessagePassingRisk'),
        'EnsembleKalmanRiskFilter': ('.ensemble_kalman_risk', 'EnsembleKalmanRiskFilter'),
        'RiskMeasurement': ('.ensemble_kalman_risk', 'RiskMeasurement'),
        'EnKFState': ('.ensemble_kalman_risk', 'EnKFState'),
        'RareCascadeSimulator': ('.rare_cascade_simulator', 'RareCascadeSimulator'),
        'CascadePath': ('.rare_cascade_simulator', 'CascadePath'),
        'CascadeEstimate': ('.rare_cascade_simulator', 'CascadeEstimate'),
        'ContrastivePathEncoder': ('.contrastive_path_embedding', 'ContrastivePathEncoder'),
        'PathSample': ('.contrastive_path_embedding', 'PathSample'),
        'MartingaleCalibrationTester': ('.martingale_calibration', 'MartingaleCalibrationTester'),
        'CalibrationReport': ('.martingale_calibration', 'CalibrationReport'),
        'ActiveEdgeSelector': ('.active_learning_edges', 'ActiveEdgeSelector'),
        'EdgeQueryCandidate': ('.active_learning_edges', 'EdgeQueryCandidate'),
        'PropagationBootstrap': ('.bootstrap_propagation', 'PropagationBootstrap'),
        'BootstrapResult': ('.bootstrap_propagation', 'BootstrapResult'),
        'GaussianProcessRisk': ('.gaussian_process_risk', 'GaussianProcessRisk'),
        'GPPrediction': ('.gaussian_process_risk', 'GPPrediction'),
        'SpectralVulnClusterer': ('.spectral_vuln_clustering', 'SpectralVulnClusterer'),
        'VulnCluster': ('.spectral_vuln_clustering', 'VulnCluster'),
    }
    if name in _LAZY:
        import importlib
        mod_path, attr = _LAZY[name]
        mod = importlib.import_module(mod_path, __package__)
        obj = getattr(mod, attr)
        # 缓存到模块全局，第二次访问走标准属性查找
        globals()[name] = obj
        return obj
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
