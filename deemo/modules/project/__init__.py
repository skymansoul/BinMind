# 懒加载门面，2026-08重构
__version__ = "1.8.0"
import sys as _sys, importlib as _il

__all__ = ['CIIntegration', 'CollaborationManager', 'ConfigManager', 'PluginManager', 'ProjectManager', 'RemoteAgent', 'ReportLocalizationEngine', 'ReportTemplateEngine', 'ResourceControl', 'SIEMIntegrator', 'TaskScheduler', 'WebAPI', 'AssetRegistry', 'ScanOrchestrator', 'EventBus', 'AuditTrail', 'CacheManager', 'MetricsRegistry', 'Counter', 'Gauge', 'Histogram', 'Summary', 'count_calls', 'track_inprogress',
           'BinaryDiffEngine', 'get_diff_engine', 'diff_binaries',
           'VulnerabilityGraphBuilder', 'CascadePredictor', 'CWECorrelationFinder',
           'build_vuln_graph_from_findings', 'assess_supply_chain_risk',
           'IncrementalAnalysisCache', 'IncrementalAnalysisScheduler',
           'AdaptiveThresholdDetector', 'MultiScaleResidualDetector',
           'MetricsAnomalyPipeline', 'BatchMetricAnalyzer',
           'EvidenceMapper', 'CrossStandardMapper', 'StandardLibrary',
           'assess_compliance',
           'AdaptiveScheduler', 'TaskProfiler', 'AdaptivePriorityLearner',
           'DataLineageTracker', 'PipelineLineageHook',
           'FindingEnrichmentPipeline', 'CVSSInferrer', 'CWERefiner', 'MITREAttackMapper',
           'ExploitabilityScorer', 'EPSSEstimator', 'TemporalDecayScorer']

_lazy = {
    'CIIntegration': ('ci_integration', 'CIIntegrator'), 'CollaborationManager': ('collaboration', 'CollaborationManager'),
    'ConfigManager': ('config_manager', 'ConfigManager'), 'PluginManager': ('plugin_manager', 'PluginManager'),
    'ProjectManager': ('project_manager', 'ProjectManager'), 'RemoteAgent': ('remote_agent', 'RemoteAgent'),
    'ReportLocalizationEngine': ('report_localization_engine', 'ReportLocalizationEngine'),
    'ReportTemplateEngine': ('report_template_engine', 'ReportTemplateEngine'),
    'ResourceControl': ('resource_control', 'ResourceController'), 'SIEMIntegrator': ('siem_integrator', 'SIEMIntegrator'),
    'TaskScheduler': ('task_scheduler', 'TaskScheduler'), 'WebAPI': ('web_api', 'start_server'),
    'AssetRegistry': ('asset_registry', 'AssetRegistry'), 'ScanOrchestrator': ('scan_orchestrator', 'ScanOrchestrator'),
    'EventBus': ('event_bus', 'EventBus'), 'AuditTrail': ('audit_trail', 'AuditTrail'),
    'CacheManager': ('cache_manager', 'CacheManager'),
    'MetricsRegistry': ('metrics_collector', 'MetricsRegistry'), 'Counter': ('metrics_collector', 'Counter'),
    'Gauge': ('metrics_collector', 'Gauge'), 'Histogram': ('metrics_collector', 'Histogram'),
    'Summary': ('metrics_collector', 'Summary'), 'count_calls': ('metrics_collector', 'count_calls'),
    'track_inprogress': ('metrics_collector', 'track_inprogress'),
    'BinaryDiffEngine': ('binary_diff_engine', 'BinaryDiffEngine'), 'get_diff_engine': ('binary_diff_engine', 'get_diff_engine'), 'diff_binaries': ('binary_diff_engine', 'diff_binaries'),
    'VulnerabilityGraphBuilder': ('vuln_knowledge_graph', 'VulnerabilityGraphBuilder'), 'CascadePredictor': ('vuln_knowledge_graph', 'CascadePredictor'), 'CWECorrelationFinder': ('vuln_knowledge_graph', 'CWECorrelationFinder'), 'build_vuln_graph_from_findings': ('vuln_knowledge_graph', 'build_vuln_graph_from_findings'), 'assess_supply_chain_risk': ('vuln_knowledge_graph', 'assess_supply_chain_risk'),
    'IncrementalAnalysisCache': ('incremental_cache', 'IncrementalAnalysisCache'), 'IncrementalAnalysisScheduler': ('incremental_cache', 'IncrementalAnalysisScheduler'),
    'AdaptiveThresholdDetector': ('metrics_anomaly', 'AdaptiveThresholdDetector'), 'MultiScaleResidualDetector': ('metrics_anomaly', 'MultiScaleResidualDetector'), 'MetricsAnomalyPipeline': ('metrics_anomaly', 'MetricsAnomalyPipeline'), 'BatchMetricAnalyzer': ('metrics_anomaly', 'BatchMetricAnalyzer'),
    'EvidenceMapper': ('compliance_mapper', 'EvidenceMapper'), 'CrossStandardMapper': ('compliance_mapper', 'CrossStandardMapper'), 'StandardLibrary': ('compliance_mapper', 'StandardLibrary'), 'assess_compliance': ('compliance_mapper', 'assess_compliance'),
    'AdaptiveScheduler': ('adaptive_scheduler', 'AdaptiveScheduler'), 'TaskProfiler': ('adaptive_scheduler', 'TaskProfiler'), 'AdaptivePriorityLearner': ('adaptive_scheduler', 'AdaptivePriorityLearner'),
    'DataLineageTracker': ('data_lineage', 'DataLineageTracker'), 'PipelineLineageHook': ('data_lineage', 'PipelineLineageHook'),
    'FindingEnrichmentPipeline': ('finding_enricher', 'FindingEnrichmentPipeline'), 'CVSSInferrer': ('finding_enricher', 'CVSSInferrer'), 'CWERefiner': ('finding_enricher', 'CWERefiner'), 'MITREAttackMapper': ('finding_enricher', 'MITREAttackMapper'),
    'ExploitabilityScorer': ('exploitability_scorer', 'ExploitabilityScorer'), 'EPSSEstimator': ('exploitability_scorer', 'EPSSEstimator'), 'TemporalDecayScorer': ('exploitability_scorer', 'TemporalDecayScorer'),
}

def __getattr__(name: str):
    if name in _lazy:
        mn, an = _lazy[name]; m = _il.import_module('.' + mn, package=__name__); a = getattr(m, an); setattr(_sys.modules[__name__], name, a); return a
    raise AttributeError(f"module '{__name__}' has no attribute '{name}'")


# DAG-DRL调度扩展接入，仅末尾追加
# dag_drl_scheduler: 图编码+RL的DAG任务调度与在线动态重排
# dag_partition_scheduler: 异构资源感知DAG图分区+调度
# 参考: GraphEdge "Dynamic Graph Partition and Task Scheduling for GNNs
#       Computing in Edge Network" (arXiv:2504.15905 [待验证])
for _name, _mod in (
        ('DAGTask', ('dag_drl_scheduler', 'DAGTask')),
        ('TaskDAG', ('dag_drl_scheduler', 'TaskDAG')),
        ('DagGraphEncoder', ('dag_drl_scheduler', 'DagGraphEncoder')),
        ('PolicyGradientScheduler', ('dag_drl_scheduler', 'PolicyGradientScheduler')),
        ('SimulatedAnnealingScheduler', ('dag_drl_scheduler', 'SimulatedAnnealingScheduler')),
        ('DAGDRLScheduler', ('dag_drl_scheduler', 'DAGDRLScheduler')),
        ('DAGDRLSchedulerPlugin', ('dag_drl_scheduler', 'DAGDRLSchedulerPlugin')),
        ('create_dag_drl_scheduler', ('dag_drl_scheduler', 'create_dag_drl_scheduler')),
        ('WorkerProfile', ('dag_partition_scheduler', 'WorkerProfile')),
        ('DAGPartitioner', ('dag_partition_scheduler', 'DAGPartitioner')),
        ('hetero_makespan', ('dag_partition_scheduler', 'hetero_makespan')),
        ('SimulatedAnnealingPartition', ('dag_partition_scheduler', 'SimulatedAnnealingPartition')),
        ('PartitionPolicyGradient', ('dag_partition_scheduler', 'PartitionPolicyGradient')),
        ('DAGPartitionScheduler', ('dag_partition_scheduler', 'DAGPartitionScheduler')),
        ('DAGPartitionSchedulerPlugin', ('dag_partition_scheduler', 'DAGPartitionSchedulerPlugin')),
        ('create_dag_partition_scheduler', ('dag_partition_scheduler', 'create_dag_partition_scheduler')),
):
    if _name not in _lazy:
        _lazy[_name] = _mod
    if _name not in __all__:
        __all__.append(_name)

# 共形预测+时间感知KG扩展，2025-07追加，仅末尾
# dag_conformal_predictor: 任务时延的共形预测区间+风险感知优先级
#   ref: Angelopoulos & Bates "Conformal Prediction" (arXiv:2107.07511)
# vuln_graph_temporal: 漏洞KG时间衰减+对抗鲁棒消息传递
#   ref: ATPF (IEEE TKDE 2025), APT-ST-AN (ScienceDirect 2025)
for _name, _mod in (
        ('ConformalInterval', ('dag_conformal_predictor', 'ConformalInterval')),
        ('SlidingCalibrationSet', ('dag_conformal_predictor', 'SlidingCalibrationSet')),
        ('ConformalPredictor', ('dag_conformal_predictor', 'ConformalPredictor')),
        ('get_shared_conformal_predictor', ('dag_conformal_predictor', 'get_shared_conformal_predictor')),
        ('reset_shared_conformal_predictor', ('dag_conformal_predictor', 'reset_shared_conformal_predictor')),
        ('TemporalEdgeWeight', ('vuln_graph_temporal', 'TemporalEdgeWeight')),
        ('TemporalVulnerabilityGraphBuilder', ('vuln_graph_temporal', 'TemporalVulnerabilityGraphBuilder')),
        ('TemporalCascadePredictor', ('vuln_graph_temporal', 'TemporalCascadePredictor')),
        ('TemporalRelevanceRanker', ('vuln_graph_temporal', 'TemporalRelevanceRanker')),
        ('weibull_decay', ('vuln_graph_temporal', 'weibull_decay')),
):
    if _name not in _lazy:
        _lazy[_name] = _mod
    if _name not in __all__:
        __all__.append(_name)

# 状态感知异常检测+因果推断图，2025-07~08追加，仅末尾
# metrics_regime_detector: BOCPD状态切换检测+按状态统计基线
#   ref: Adams & MacKay (arXiv:0710.3742), Youssef (arXiv:2510.09619 [待验证])
# finding_causal_graph: PC算法因果发现+根因排序
#   ref: Pearl (2016), CausalVulGNN (2025), CDT (arXiv:2510.09616 [待验证])
for _name, _mod in (
        ('RegimeProfile', ('metrics_regime_detector', 'RegimeProfile')),
        ('BOCPDDetector', ('metrics_regime_detector', 'BOCPDDetector')),
        ('RegimeAwareDetector', ('metrics_regime_detector', 'RegimeAwareDetector')),
        ('create_regime_aware_detector', ('metrics_regime_detector', 'create_regime_aware_detector')),
        ('regime_aware_detect_fn', ('metrics_regime_detector', 'regime_aware_detect_fn')),
        ('CausalEdge', ('finding_causal_graph', 'CausalEdge')),
        ('CausalGraph', ('finding_causal_graph', 'CausalGraph')),
        ('FindingCausalDiscoverer', ('finding_causal_graph', 'FindingCausalDiscoverer')),
        ('RootCauseRanker', ('finding_causal_graph', 'RootCauseRanker')),
):
    if _name not in _lazy:
        _lazy[_name] = _mod
    if _name not in __all__:
        __all__.append(_name)

# 二进制规范化+Merkle溯源，2025-07~08追加，仅末尾
# binary_normalizer: NOP消除+寄存器正则化+数据流重排→跨优化级diff
#   ref: KHAos (ACM TACO 2025), QBinDiff (Quarkslab 2024)
# lineage_provenance: 增量Merkle树+包含证明→管道防篡改审计
#   ref: Merkle (CRYPTO 1987), Kest (2025-2026), Context Lineage (arXiv:2509.18415 [待验证])
for _name, _mod in (
        ('NormalizedSegment', ('binary_normalizer', 'NormalizedSegment')),
        ('BinaryNormalizer', ('binary_normalizer', 'BinaryNormalizer')),
        ('elide_nops', ('binary_normalizer', 'elide_nops')),
        ('PipelineLeaf', ('lineage_provenance', 'PipelineLeaf')),
        ('InclusionProof', ('lineage_provenance', 'InclusionProof')),
        ('IncrementalMerkleTree', ('lineage_provenance', 'IncrementalMerkleTree')),
        ('PipelineProvenanceTracker', ('lineage_provenance', 'PipelineProvenanceTracker')),
        ('verify_audit_bundle', ('lineage_provenance', 'verify_audit_bundle')),
):
    if _name not in _lazy:
        _lazy[_name] = _mod
    if _name not in __all__:
        __all__.append(_name)

# 跨模态补丁→CVE推断，2025-08-01追加，仅末尾
# cross_modal_binary_cve_inference: 二进制patch签名×漏洞KG跨注意力对齐
for _name, _mod in (
        ('PatchSignature', ('cross_modal_binary_cve_inference', 'PatchSignature')),
        ('CVEProjectionIndex', ('cross_modal_binary_cve_inference', 'CVEProjectionIndex')),
        ('CrossModalAttention', ('cross_modal_binary_cve_inference', 'CrossModalAttention')),
        ('CrossModalBinaryCVEInference', ('cross_modal_binary_cve_inference', 'CrossModalBinaryCVEInference')),
        ('get_cross_modal_engine', ('cross_modal_binary_cve_inference', 'get_cross_modal_engine')),
):
    if _name not in _lazy:
        _lazy[_name] = _mod
    if _name not in __all__:
        __all__.append(_name)

# 多视角对抗验证+保形漏洞评分+因果利用链预测，2025-08-02~03追加，仅末尾
for _name, _mod in (
        ('AdversarialFindingValidator', ('adversarial_finding_validator', 'AdversarialFindingValidator')),
        ('ValidatorResult', ('adversarial_finding_validator', 'ValidatorResult')),
        ('ExploitPrimitive', ('causal_exploit_chain_predictor', 'ExploitPrimitive')),
        ('ExploitStep', ('causal_exploit_chain_predictor', 'ExploitStep')),
        ('ExploitChain', ('causal_exploit_chain_predictor', 'ExploitChain')),
        ('ExploitChainPredictor', ('causal_exploit_chain_predictor', 'ExploitChainPredictor')),
        ('create_exploit_chain_predictor', ('causal_exploit_chain_predictor', 'create_exploit_chain_predictor')),
        ('ConformalScore', ('conformal_vuln_scorer', 'ConformalScore')),
        ('ConformalVulnScorer', ('conformal_vuln_scorer', 'ConformalVulnScorer')),
        ('get_conformal_scorer', ('conformal_vuln_scorer', 'get_conformal_scorer')),
):
    if _name not in _lazy:
        _lazy[_name] = _mod
    if _name not in __all__:
        __all__.append(_name)

# 行为利用检测+联邦情报+自主补丁+博弈调度，2025-08-02~03追加，仅末尾
for _name, _mod in (
        ('BehavioralExploitDetector', ('behavioral_exploit_detector', 'BehavioralExploitDetector')),
        ('BehaviorProfile', ('behavioral_exploit_detector', 'BehaviorProfile')),
        ('ExploitAlert', ('behavioral_exploit_detector', 'ExploitAlert')),
        ('LDPReport', ('federated_vuln_intel', 'LDPReport')),
        ('PrivacyBudget', ('federated_vuln_intel', 'PrivacyBudget')),
        ('FederatedVulnIntelligence', ('federated_vuln_intel', 'FederatedVulnIntelligence')),
        ('PatchTemplate', ('autonomous_patch_synth', 'PatchTemplate')),
        ('PatchCandidate', ('autonomous_patch_synth', 'PatchCandidate')),
        ('AutonomousPatchSynthesizer', ('autonomous_patch_synth', 'AutonomousPatchSynthesizer')),
        ('Asset', ('stackelberg_remediation_game', 'Asset')),
        ('AttackAction', ('stackelberg_remediation_game', 'AttackAction')),
        ('DefenseStrategy', ('stackelberg_remediation_game', 'DefenseStrategy')),
        ('StackelbergRemediationScheduler', ('stackelberg_remediation_game', 'StackelbergRemediationScheduler')),
):
    if _name not in _lazy:
        _lazy[_name] = _mod
    if _name not in __all__:
        __all__.append(_name)

# 自动威胁建模+贝叶斯SBOM风险+混合二进制指纹，2025-08-04追加，仅末尾
for _name, _mod in (
        ('TrustBoundary', ('auto_threat_modeler', 'TrustBoundary')),
        ('DataFlow', ('auto_threat_modeler', 'DataFlow')),
        ('ThreatCard', ('auto_threat_modeler', 'ThreatCard')),
        ('AutoThreatModeler', ('auto_threat_modeler', 'AutoThreatModeler')),
        ('BetaBelief', ('bayesian_sbom_risk', 'BetaBelief')),
        ('BayesianDependencyGraph', ('bayesian_sbom_risk', 'BayesianDependencyGraph')),
        ('BayesianSBOMRiskEngine', ('bayesian_sbom_risk', 'BayesianSBOMRiskEngine')),
        ('BinaryFingerprint', ('hybrid_binary_fingerprint', 'BinaryFingerprint')),
        ('HybridBinaryFingerprinter', ('hybrid_binary_fingerprint', 'HybridBinaryFingerprinter')),
):
    if _name not in _lazy:
        _lazy[_name] = _mod
    if _name not in __all__:
        __all__.append(_name)

# 崩溃语义去重+利用原语分类+种子Bandit调度，2025-08-05追加，仅末尾
for _name, _mod in (
        ('CrashRecord', ('crash_semantic_dedup', 'CrashRecord')),
        ('CrashSignature', ('crash_semantic_dedup', 'CrashSignature')),
        ('CrashSemanticDeduplicator', ('crash_semantic_dedup', 'CrashSemanticDeduplicator')),
        ('ExploitPrimitiveAssessment', ('exploit_primitive_classifier', 'ExploitPrimitiveAssessment')),
        ('ExploitPrimitiveClassifier', ('exploit_primitive_classifier', 'ExploitPrimitiveClassifier')),
        ('SeedRecord', ('fuzzing_seed_bandit', 'SeedRecord')),
        ('ThompsonSamplingBandit', ('fuzzing_seed_bandit', 'ThompsonSamplingBandit')),
        ('FuzzingSeedBanditScheduler', ('fuzzing_seed_bandit', 'FuzzingSeedBanditScheduler')),
):
    if _name not in _lazy:
        _lazy[_name] = _mod
    if _name not in __all__:
        __all__.append(_name)

# ROP质量评分+竞态检测+补丁差分分析，2025-08-06追加，仅末尾
for _name, _mod in (
        ('Gadget', ('rop_gadget_quality_scorer', 'Gadget')),
        ('ChainEdge', ('rop_gadget_quality_scorer', 'ChainEdge')),
        ('ROPGadgetQualityScorer', ('rop_gadget_quality_scorer', 'ROPGadgetQualityScorer')),
        ('RaceConditionFinding', ('race_condition_detector', 'RaceConditionFinding')),
        ('TOCTOUPatternDetector', ('race_condition_detector', 'TOCTOUPatternDetector')),
        ('PatchChange', ('differential_patch_analyzer', 'PatchChange')),
        ('PatchAnalysis', ('differential_patch_analyzer', 'PatchAnalysis')),
        ('DifferentialPatchAnalyzer', ('differential_patch_analyzer', 'DifferentialPatchAnalyzer')),
):
    if _name not in _lazy:
        _lazy[_name] = _mod
    if _name not in __all__:
        __all__.append(_name)

# 反fuzzing检测+堆布局规划+编译器优化审计，2025-08-07追加，仅末尾
for _name, _mod in (
        ('AntiFuzzGuard', ('anti_fuzzing_detector', 'AntiFuzzGuard')),
        ('AntiFuzzingDetector', ('anti_fuzzing_detector', 'AntiFuzzingDetector')),
        ('HeapOperation', ('heap_layout_planner', 'HeapOperation')),
        ('HeapLayoutPlan', ('heap_layout_planner', 'HeapLayoutPlan')),
        ('HeapLayoutPlanner', ('heap_layout_planner', 'HeapLayoutPlanner')),
        ('OptVulnFinding', ('compiler_opt_vuln_auditor', 'OptVulnFinding')),
        ('CompilerOptVulnAuditor', ('compiler_opt_vuln_auditor', 'CompilerOptVulnAuditor')),
):
    if _name not in _lazy:
        _lazy[_name] = _mod
    if _name not in __all__:
        __all__.append(_name)

# 类型推断+传播映射+战役模拟，2025-08-08追加，仅末尾
for _name, _mod in (
        ('InferredStruct', ('binary_type_inference', 'InferredStruct')),
        ('VTableInfo', ('binary_type_inference', 'VTableInfo')),
        ('BinaryTypeInference', ('binary_type_inference', 'BinaryTypeInference')),
        ('ComponentNode', ('vuln_propagation_mapper', 'ComponentNode')),
        ('PropagationPath', ('vuln_propagation_mapper', 'PropagationPath')),
        ('VulnPropagationMapper', ('vuln_propagation_mapper', 'VulnPropagationMapper')),
        ('ExploitStep', ('exploit_campaign_sim', 'ExploitStep')),
        ('DefenseModel', ('exploit_campaign_sim', 'DefenseModel')),
        ('SimulationResult', ('exploit_campaign_sim', 'SimulationResult')),
        ('ExploitCampaignSimulator', ('exploit_campaign_sim', 'ExploitCampaignSimulator')),
):
    if _name not in _lazy:
        _lazy[_name] = _mod
    if _name not in __all__:
        __all__.append(_name)

# 格式串策略+污点追踪+可靠性评估，2025-08-09追加，仅末尾
for _name, _mod in (
        ('BinaryDefenses', ('fmtstr_exploit_strategist', 'BinaryDefenses')),
        ('LeakInfo', ('fmtstr_exploit_strategist', 'LeakInfo')),
        ('ExploitStrategy', ('fmtstr_exploit_strategist', 'ExploitStrategy')),
        ('FmtStrExploitStrategist', ('fmtstr_exploit_strategist', 'FmtStrExploitStrategist')),
        ('TaintFlow', ('binary_taint_tracer', 'TaintFlow')),
        ('BinaryTaintTracer', ('binary_taint_tracer', 'BinaryTaintTracer')),
        ('ExploitParameters', ('exploit_reliability_estimator', 'ExploitParameters')),
        ('ReliabilityResult', ('exploit_reliability_estimator', 'ReliabilityResult')),
        ('ExploitReliabilityEstimator', ('exploit_reliability_estimator', 'ExploitReliabilityEstimator')),
):
    if _name not in _lazy:
        _lazy[_name] = _mod
    if _name not in __all__:
        __all__.append(_name)

# Seccomp绕过+内核利用+内存写入规划，2025-08-10追加，仅末尾
for _name, _mod in (
        ('SeccompAnalysis', ('seccomp_bypass_finder', 'SeccompAnalysis')),
        ('SeccompBypassFinder', ('seccomp_bypass_finder', 'SeccompBypassFinder')),
        ('KernelConfig', ('kernel_exploit_mapper', 'KernelConfig')),
        ('ExploitTechnique', ('kernel_exploit_mapper', 'ExploitTechnique')),
        ('KernelExploitMapper', ('kernel_exploit_mapper', 'KernelExploitMapper')),
        ('WriteConstraint', ('memory_write_planner', 'WriteConstraint')),
        ('WriteStep', ('memory_write_planner', 'WriteStep')),
        ('WritePlan', ('memory_write_planner', 'WritePlan')),
        ('MemoryWritePlanner', ('memory_write_planner', 'MemoryWritePlanner')),
):
    if _name not in _lazy:
        _lazy[_name] = _mod
    if _name not in __all__:
        __all__.append(_name)

# ASLR熵分析+攻击面枚举+加固审计，2025-08-11追加，仅末尾
for _name, _mod in (
        ('RegionEntropy', ('aslr_entropy_analyzer', 'RegionEntropy')),
        ('ASLRAnalysis', ('aslr_entropy_analyzer', 'ASLRAnalysis')),
        ('ASLREntropyAnalyzer', ('aslr_entropy_analyzer', 'ASLREntropyAnalyzer')),
        ('AttackSurface', ('attack_surface_enumerator', 'AttackSurface')),
        ('SurfaceReport', ('attack_surface_enumerator', 'SurfaceReport')),
        ('AttackSurfaceEnumerator', ('attack_surface_enumerator', 'AttackSurfaceEnumerator')),
        ('HardeningCheck', ('binary_hardening_auditor', 'HardeningCheck')),
        ('HardeningReport', ('binary_hardening_auditor', 'HardeningReport')),
        ('BinaryHardeningAuditor', ('binary_hardening_auditor', 'BinaryHardeningAuditor')),
):
    if _name not in _lazy:
        _lazy[_name] = _mod
    if _name not in __all__:
        __all__.append(_name)

# ELF加载器滥用+权限边界+信号帧利用，2025-08-12追加，仅末尾
for _name, _mod in (
        ('LoaderAbuse', ('elf_loader_abuse_detector', 'LoaderAbuse')),
        ('ELFLoaderAbuseDetector', ('elf_loader_abuse_detector', 'ELFLoaderAbuseDetector')),
        ('PrivilegeContext', ('privilege_boundary_mapper', 'PrivilegeContext')),
        ('PrivilegeEscalationPath', ('privilege_boundary_mapper', 'PrivilegeEscalationPath')),
        ('PrivilegeBoundaryMapper', ('privilege_boundary_mapper', 'PrivilegeBoundaryMapper')),
        ('SignalHandler', ('signal_frame_analyzer', 'SignalHandler')),
        ('SigFrameAnalysis', ('signal_frame_analyzer', 'SigFrameAnalysis')),
        ('SignalFrameAnalyzer', ('signal_frame_analyzer', 'SignalFrameAnalyzer')),
):
    if _name not in _lazy:
        _lazy[_name] = _mod
    if _name not in __all__:
        __all__.append(_name)

# 持久化检测+eBPF分析+侧信道评估，2025-08-13追加，仅末尾
for _name, _mod in (
        ('PersistencePath', ('persistence_detector', 'PersistencePath')),
        ('PersistenceDetector', ('persistence_detector', 'PersistenceDetector')),
        ('EBPPFinding', ('ebpf_security_analyzer', 'EBPPFinding')),
        ('EBPFSecurityAnalyzer', ('ebpf_security_analyzer', 'EBPFSecurityAnalyzer')),
        ('SideChannelFinding', ('side_channel_assessor', 'SideChannelFinding')),
        ('SideChannelAssessor', ('side_channel_assessor', 'SideChannelAssessor')),
):
    if _name not in _lazy:
        _lazy[_name] = _mod
    if _name not in __all__:
        __all__.append(_name)

# JIT spray检测+Harness生成+崩溃最小化，2025-08-14追加，仅末尾
for _name, _mod in (
        ('JITSprayFinding', ('jit_spray_detector', 'JITSprayFinding')),
        ('JITSprayDetector', ('jit_spray_detector', 'JITSprayDetector')),
        ('FunctionParam', ('fuzz_harness_generator', 'FunctionParam')),
        ('FuzzHarnessGenerator', ('fuzz_harness_generator', 'FuzzHarnessGenerator')),
        ('CrashProperty', ('crash_input_minimizer', 'CrashProperty')),
        ('MinimizeResult', ('crash_input_minimizer', 'MinimizeResult')),
        ('CrashInputMinimizer', ('crash_input_minimizer', 'CrashInputMinimizer')),
):
    if _name not in _lazy:
        _lazy[_name] = _mod
    if _name not in __all__:
        __all__.append(_name)
