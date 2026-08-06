# 二进制补丁分析·自动修复链
# v2 重构，懒加载消除循环导入
# 旧版 import 兼容垫片
# v3：补丁安全、栈完整性、gadget 链、CVE 库

__version__ = "2.2.0"

import sys as _sys
import os as _os

# patching/src 入 path，供子模块相对导入
_cur = _os.path.dirname(_os.path.abspath(__file__))
_src = _os.path.join(_cur, 'src')
if _src not in _sys.path:
    _sys.path.insert(0, _src)

# ── __getattr__ 懒加载 ──────────────────────────────────────

__all__ = [
    # auto patcher
    'AutoPatcher', 'VulnerabilityType', 'PatchStrategy', 'HardeningType',
    'VulnerabilityInfo', 'PatchInfo', 'HardeningInfo', 'PatchResult', 'patch_binary',
    # patch spec
    'AutoPatchSpecAnalyzer', 'LLMPatchSpecGenerator', 'PatchSpecGenerator',
    'PatchSpecification', 'VulnerabilityContext', 'PatchType', 'PatchLocation',
    # root cause
    'AutoRootCauseAnalyzer', 'AnalysisReport', 'format_root_cause_report',
    'analyze_root_cause', 'VulnerabilitySeverity', 'CWEDatabase',
    # diff locator
    'PatchDiffLocator', 'analyze_patch_diff', 'locate_patch_diff',
    'FunctionDiff', 'PatchAnalysisResult',
    # impact
    'PatchImpactAnalyzer', 'analyze_patch_impact',
    'FunctionFingerprint', 'PatchChange', 'PatchImpactReport',
    # quality
    'PatchQualityEvaluator', 'PatchStatus', 'BypassRisk', 'evaluate_patch',
    # suggestion
    'PatchSuggester', 'PatchSuggestion',
    # recompiler
    'RecompilerVerifier', 'CompilationStatus', 'EquivalenceLevel',
    'verify_decompilation', 'verify_single_function',
    # reliability
    'ReliabilityPredictor', 'create_reliability_predictor',
    # rule engine
    'RuleEngine', 'RuleCondition', 'RuleAction', 'VulnerabilityRule',
    # self healing
    'SelfHealingRewriter', 'apply_self_healing_protection',
    'ProtectionType', 'InstrumentationFramework',
    # infrastructure
    'config',
    # src 子包
    'PatchConfig',
    'BackupManager', 'InstrumentationManager', 'PatchVerifier',
    'PatchError', 'PatchApplyError', 'PatchVerifyError', 'BackupError',
    # v3 扩展
    'PatchSafetyVerifier', 'SafetyVerdict', 'SafetyReport', 'verify_patch_safety', 'batch_safety_check',
    'verify_hybrid',
    'StackIntegrityChecker', 'StackIntegrityReport', 'check_stack_integrity',
    'GadgetChainAnalyzer', 'GadgetChainAnalysis', 'analyze_gadget_chains',
    'DistortionDetector', 'DistortionReport', 'detect_distortions', 'auto_fix_distortions',
    'CVEKnowledgeBase', 'CVEEntry', 'create_cve_kb', 'import_nvd_to_kb',
    'PatchTestGenerator', 'TestSuite', 'generate_patch_tests',
    'BoundedModelChecker', 'ModelCheckingReport', 'bounded_model_check',
    'DiffMinimizer', 'minimize_patch_diff',
    'PatchReportComposer', 'compose_patch_report',
]

_lazy_map = {
    'AutoPatcher': ('auto_patcher', 'AutoPatcher'),
    'VulnerabilityType': ('auto_patcher', 'VulnerabilityType'),
    'PatchStrategy': ('auto_patcher', 'PatchStrategy'),
    'HardeningType': ('auto_patcher', 'HardeningType'),
    'VulnerabilityInfo': ('auto_patcher', 'VulnerabilityInfo'),
    'PatchInfo': ('auto_patcher', 'PatchInfo'),
    'HardeningInfo': ('auto_patcher', 'HardeningInfo'),
    'PatchResult': ('auto_patcher', 'PatchResult'),
    'patch_binary': ('auto_patcher', 'patch_binary'),
    'AutoPatchSpecAnalyzer': ('auto_patch_spec', 'AutoPatchSpecAnalyzer'),
    'LLMPatchSpecGenerator': ('auto_patch_spec', 'LLMPatchSpecGenerator'),
    'PatchSpecGenerator': ('auto_patch_spec', 'PatchSpecGenerator'),
    'PatchSpecification': ('auto_patch_spec', 'PatchSpecification'),
    'VulnerabilityContext': ('auto_patch_spec', 'VulnerabilityContext'),
    'PatchType': ('auto_patch_spec', 'PatchType'),
    'PatchLocation': ('auto_patch_spec', 'PatchLocation'),
    'AutoRootCauseAnalyzer': ('auto_root_cause', 'AutoRootCauseAnalyzer'),
    'AnalysisReport': ('auto_root_cause', 'AnalysisReport'),
    'RootCauseAnalysis': ('auto_root_cause', 'RootCauseAnalysis'),
    'format_root_cause_report': ('auto_root_cause', 'format_root_cause_report'),
    'analyze_root_cause': ('auto_root_cause', 'analyze_root_cause'),
    'VulnerabilitySeverity': ('auto_root_cause', 'VulnerabilitySeverity'),
    'CWEDatabase': ('auto_root_cause', 'CWEDatabase'),
    'PatchDiffLocator': ('patch_diff_locator', 'PatchDiffLocator'),
    'analyze_patch_diff': ('patch_diff_locator', 'analyze_patch_diff'),
    'locate_patch_diff': ('patch_diff_locator', 'locate_patch_diff'),
    'FunctionDiff': ('patch_diff_locator', 'FunctionDiff'),
    'PatchAnalysisResult': ('patch_diff_locator', 'PatchAnalysisResult'),
    'PatchImpactAnalyzer': ('patch_impact_analyzer', 'PatchImpactAnalyzer'),
    'analyze_patch_impact': ('patch_impact_analyzer', 'analyze_patch_impact'),
    'FunctionFingerprint': ('patch_impact_analyzer', 'FunctionFingerprint'),
    'PatchChange': ('patch_impact_analyzer', 'PatchChange'),
    'PatchImpactReport': ('patch_impact_analyzer', 'PatchImpactReport'),
    'PatchQualityEvaluator': ('patch_quality_evaluator', 'PatchQualityEvaluator'),
    'PatchStatus': ('patch_quality_evaluator', 'PatchStatus'),
    'BypassRisk': ('patch_quality_evaluator', 'BypassRisk'),
    'evaluate_patch': ('patch_quality_evaluator', 'evaluate_patch'),
    'PatchSuggester': ('patch_suggestion', 'PatchSuggester'),
    'PatchSuggestion': ('patch_suggestion', 'PatchSuggestion'),
    'RecompilerVerifier': ('recompiler_check', 'RecompilerVerifier'),
    'CompilationStatus': ('recompiler_check', 'CompilationStatus'),
    'EquivalenceLevel': ('recompiler_check', 'EquivalenceLevel'),
    'verify_decompilation': ('recompiler_check', 'verify_decompilation'),
    'verify_single_function': ('recompiler_check', 'verify_single_function'),
    'ReliabilityPredictor': ('reliability_predictor', 'ReliabilityPredictor'),
    'create_reliability_predictor': ('reliability_predictor', 'create_reliability_predictor'),
    'RuleEngine': ('rule_engine', 'RuleEngine'),
    'RuleCondition': ('rule_engine', 'RuleCondition'),
    'RuleAction': ('rule_engine', 'RuleAction'),
    'VulnerabilityRule': ('rule_engine', 'VulnerabilityRule'),
    'SelfHealingRewriter': ('self_healing_rewriter', 'SelfHealingRewriter'),
    'apply_self_healing_protection': ('self_healing_rewriter', 'apply_self_healing_protection'),
    'ProtectionType': ('self_healing_rewriter', 'ProtectionType'),
    'InstrumentationFramework': ('self_healing_rewriter', 'InstrumentationFramework'),
    # src 子包入口
    'PatchConfig': ('src.config', 'PatchConfig'),
    'BackupManager': ('src.backup_manager', 'BackupManager'),
    'InstrumentationManager': ('src.instr_manager', 'InstrumentationManager'),
    'PatchVerifier': ('src.patch_verifier', 'PatchVerifier'),
    'PatchError': ('src.exceptions', 'PatchError'),
    'PatchApplyError': ('src.exceptions', 'PatchApplyError'),
    'PatchVerifyError': ('src.exceptions', 'PatchVerifyError'),
    'BackupError': ('src.exceptions', 'BackupError'),
    # v3 扩展
    'PatchSafetyVerifier': ('patch_safety_verifier', 'PatchSafetyVerifier'),
    'SafetyVerdict': ('patch_safety_verifier', 'SafetyVerdict'),
    'SafetyReport': ('patch_safety_verifier', 'SafetyReport'),
    'verify_patch_safety': ('patch_safety_verifier', 'verify_patch_safety'),
    'batch_safety_check': ('patch_safety_verifier', 'batch_safety_check'),
    'verify_hybrid': ('patch_safety_verifier', 'verify_hybrid'),
    'StackIntegrityChecker': ('stack_integrity_checker', 'StackIntegrityChecker'),
    'StackIntegrityReport': ('stack_integrity_checker', 'StackIntegrityReport'),
    'check_stack_integrity': ('stack_integrity_checker', 'check_stack_integrity'),
    'GadgetChainAnalyzer': ('gadget_chain_analyzer', 'GadgetChainAnalyzer'),
    'GadgetChainAnalysis': ('gadget_chain_analyzer', 'GadgetChainAnalysis'),
    'analyze_gadget_chains': ('gadget_chain_analyzer', 'analyze_gadget_chains'),
    'DistortionDetector': ('decomp_distortion_detector', 'DistortionDetector'),
    'DistortionReport': ('decomp_distortion_detector', 'DistortionReport'),
    'detect_distortions': ('decomp_distortion_detector', 'detect_distortions'),
    'auto_fix_distortions': ('decomp_distortion_detector', 'auto_fix_distortions'),
    'CVEKnowledgeBase': ('cve_knowledge_base', 'CVEKnowledgeBase'),
    'CVEEntry': ('cve_knowledge_base', 'CVEEntry'),
    'create_cve_kb': ('cve_knowledge_base', 'create_cve_kb'),
    'import_nvd_to_kb': ('cve_knowledge_base', 'import_nvd_to_kb'),
    'PatchTestGenerator': ('patch_test_generator', 'PatchTestGenerator'),
    'TestSuite': ('patch_test_generator', 'TestSuite'),
    'generate_patch_tests': ('patch_test_generator', 'generate_patch_tests'),
    'BoundedModelChecker': ('bounded_model_checker', 'BoundedModelChecker'),
    'ModelCheckingReport': ('bounded_model_checker', 'ModelCheckingReport'),
    'bounded_model_check': ('bounded_model_checker', 'bounded_model_check'),
    'DiffMinimizer': ('diff_minimizer', 'DiffMinimizer'),
    'minimize_patch_diff': ('diff_minimizer', 'minimize_patch_diff'),
    'PatchReportComposer': ('patch_report_composer', 'PatchReportComposer'),
    'compose_patch_report': ('patch_report_composer', 'compose_patch_report'),
}


def __getattr__(name):
    """按需导入——首次属性引用时触发。"""
    if name in _lazy_map:
        mod_name, attr = _lazy_map[name]
        import importlib
        mod = importlib.import_module(f'.{mod_name}', package=__name__)
        obj = getattr(mod, attr)
        # 缓存至模块命名空间，免重复 importlib
        globals()[name] = obj
        return obj
    raise AttributeError(f"module '{__name__}' has no attribute '{name}'")


# ── AgentRepair (2026-08-03) — 符号+静态/测试反馈闭环修复 ──
# 多轮修复引擎 / 漏洞类型路由 / 候选排序 / 安全校验
__all__.extend([
    'AgentRepairEngine', 'RepairRound', 'RepairTrajectory', 'RepairOutcome',
    'RepairCandidate', 'agent_repair', 'repair_to_dict',
    'PatchTypeRouter', 'VulnClassifier', 'RouteDecision', 'RepairFamily', 'RepairRoute',
    'CandidatePatchRanker', 'RankedCandidate', 'rank_candidates',
    'SafeRepairValidator', 'ValidationResult', 'ValidationStatus',
])

_lazy_map.update({
    'AgentRepairEngine': ('agent_repair', 'AgentRepairEngine'),
    'RepairRound': ('agent_repair', 'RepairRound'),
    'RepairTrajectory': ('agent_repair', 'RepairTrajectory'),
    'RepairOutcome': ('agent_repair', 'RepairOutcome'),
    'RepairCandidate': ('agent_repair', 'RepairCandidate'),
    'agent_repair': ('agent_repair', 'agent_repair'),
    'repair_to_dict': ('agent_repair', 'repair_to_dict'),
    'PatchTypeRouter': ('patch_type_router', 'PatchTypeRouter'),
    'VulnClassifier': ('patch_type_router', 'VulnClassifier'),
    'RouteDecision': ('patch_type_router', 'RouteDecision'),
    'RepairFamily': ('patch_type_router', 'RepairFamily'),
    'RepairRoute': ('patch_type_router', 'RepairRoute'),
    'CandidatePatchRanker': ('candidate_patch_ranker', 'CandidatePatchRanker'),
    'RankedCandidate': ('candidate_patch_ranker', 'RankedCandidate'),
    'rank_candidates': ('candidate_patch_ranker', 'rank_candidates'),
    'SafeRepairValidator': ('safe_repair_validator', 'SafeRepairValidator'),
    'ValidationResult': ('safe_repair_validator', 'ValidationResult'),
    'ValidationStatus': ('safe_repair_validator', 'ValidationStatus'),
})

# ── 补丁存在性检测 + 差分执行验证 (2026-08-03) ──────────────────
# PPT：语义签名提取与匹配，不依赖源码。
# DiffExec：轻量 concrete execution oracle，与 VeriBin 互补。
__all__.extend([
    'SemanticSignatureExtractor', 'PatchPresenceTester', 'SemanticSignature',
    'SigKind', 'FunctionSignatureProfile', 'MatchResult', 'build_reference_profiles',
    'DifferentialExecutor', 'DiffExecutionReport', 'DiffVerdict', 'DiffTestCase',
    'SeedGenerator', 'InputMutator', 'diff_exec_verify',
])

_lazy_map.update({
    # PPT
    'SemanticSignatureExtractor': ('src.patch_presence_tester', 'SemanticSignatureExtractor'),
    'PatchPresenceTester': ('src.patch_presence_tester', 'PatchPresenceTester'),
    'SemanticSignature': ('src.patch_presence_tester', 'SemanticSignature'),
    'SigKind': ('src.patch_presence_tester', 'SigKind'),
    'FunctionSignatureProfile': ('src.patch_presence_tester', 'FunctionSignatureProfile'),
    'MatchResult': ('src.patch_presence_tester', 'MatchResult'),
    'build_reference_profiles': ('src.patch_presence_tester', 'build_reference_profiles'),
    # DiffExec
    'DifferentialExecutor': ('src.differential_executor', 'DifferentialExecutor'),
    'DiffExecutionReport': ('src.differential_executor', 'DiffExecutionReport'),
    'DiffVerdict': ('src.differential_executor', 'DiffVerdict'),
    'DiffTestCase': ('src.differential_executor', 'DiffTestCase'),
    'SeedGenerator': ('src.differential_executor', 'SeedGenerator'),
    'InputMutator': ('src.differential_executor', 'InputMutator'),
    'diff_exec_verify': ('src.differential_executor', 'diff_exec_verify'),
})

# ── Concolic 执行 + IR 等值缓存 (2026-08-14) ──────────────────
# Concolic：符号+具体混合测试合成，精确定位补丁新路径。
# IR Cache：语义指纹归一化 + LFU-DA 淘汰，免重复重编译。
__all__.extend([
    'SymExpr', 'ExprKind', 'SymbolicState', 'Constraint', 'ConstraintKind',
    'PathCondition', 'ConcolicTestGenerator', 'ConcolicTestCase',
    'IREquivalenceCache', 'SemanticFingerprint', 'EquivCacheEntry',
    'normalize_function', 'compute_fingerprint', 'create_equiv_cache', 'LFUDACache',
])

_lazy_map.update({
    # Concolic
    'SymExpr': ('src.symbolic_state', 'SymExpr'),
    'ExprKind': ('src.symbolic_state', 'ExprKind'),
    'SymbolicState': ('src.symbolic_state', 'SymbolicState'),
    'Constraint': ('src.symbolic_state', 'Constraint'),
    'ConstraintKind': ('src.symbolic_state', 'ConstraintKind'),
    'PathCondition': ('src.symbolic_state', 'PathCondition'),
    'ConcolicTestGenerator': ('src.concolic_test_gen', 'ConcolicTestGenerator'),
    'ConcolicTestCase': ('src.concolic_test_gen', 'ConcolicTestCase'),
    # IR Cache
    'IREquivalenceCache': ('src.ir_equiv_cache', 'IREquivalenceCache'),
    'SemanticFingerprint': ('src.ir_equiv_cache', 'SemanticFingerprint'),
    'EquivCacheEntry': ('src.ir_equiv_cache', 'EquivCacheEntry'),
    'normalize_function': ('src.ir_equiv_cache', 'normalize_function'),
    'compute_fingerprint': ('src.ir_equiv_cache', 'compute_fingerprint'),
    'create_equiv_cache': ('src.ir_equiv_cache', 'create_equiv_cache'),
    'LFUDACache': ('src.ir_equiv_cache', 'LFUDACache'),
})

# ── 多补丁交互图 + 时间衰减可靠性 (2026-09-05) ──────────────────
# InteractionGraph：补丁冲突/依赖检测 + 安全应用拓扑序。
# TemporalReliability：可靠性时间衰减建模 + 环境漂移告警。
__all__.extend([
    'PatchInteractionGraph', 'PatchNode', 'InteractionEdge', 'EdgeType',
    'InteractionReport', 'patch_node_from_spec', 'analyze_patch_set',
    'TemporalReliabilityModel', 'TemporalReliabilityReport',
    'EnvironmentFingerprint', 'EnvironmentDriftDetector', 'RefreshUrgency',
    'capture_environment', 'predict_patch_longevity', 'estimate_decay_constant',
])

_lazy_map.update({
    # Patch Interaction Graph
    'PatchInteractionGraph': ('src.patch_interaction_graph', 'PatchInteractionGraph'),
    'PatchNode': ('src.patch_interaction_graph', 'PatchNode'),
    'InteractionEdge': ('src.patch_interaction_graph', 'InteractionEdge'),
    'EdgeType': ('src.patch_interaction_graph', 'EdgeType'),
    'InteractionReport': ('src.patch_interaction_graph', 'InteractionReport'),
    'patch_node_from_spec': ('src.patch_interaction_graph', 'patch_node_from_spec'),
    'analyze_patch_set': ('src.patch_interaction_graph', 'analyze_patch_set'),
    # Temporal Reliability
    'TemporalReliabilityModel': ('src.temporal_reliability', 'TemporalReliabilityModel'),
    'TemporalReliabilityReport': ('src.temporal_reliability', 'TemporalReliabilityReport'),
    'EnvironmentFingerprint': ('src.temporal_reliability', 'EnvironmentFingerprint'),
    'EnvironmentDriftDetector': ('src.temporal_reliability', 'EnvironmentDriftDetector'),
    'RefreshUrgency': ('src.temporal_reliability', 'RefreshUrgency'),
    'capture_environment': ('src.temporal_reliability', 'capture_environment'),
    'predict_patch_longevity': ('src.temporal_reliability', 'predict_patch_longevity'),
    'estimate_decay_constant': ('src.temporal_reliability', 'estimate_decay_constant'),
})

# ── Patch Provenance Chain (2025-08-11) ───────────────────────────
# Merkle-DAG 内容寻址补丁来源、Ed25519 证明链、独立可验证性。
__all__.extend([
    'ProvenanceNode', 'ProvenanceStore', 'EdgeKind', 'AttestationPayload',
    'ProvenanceAttestor', 'AttestationPolicy', 'Ed25519Signer',
    'ProvenanceVerifier', 'VerificationSummary', 'VerificationStatus',
    'content_id', 'produce_transparency_log_entry',
])

_lazy_map.update({
    'ProvenanceNode': ('src.patch_provenance', 'ProvenanceNode'),
    'ProvenanceStore': ('src.patch_provenance', 'ProvenanceStore'),
    'EdgeKind': ('src.patch_provenance', 'EdgeKind'),
    'AttestationPayload': ('src.patch_provenance', 'AttestationPayload'),
    'content_id': ('src.patch_provenance', 'content_id'),
    'ProvenanceAttestor': ('src.provenance_attestor', 'ProvenanceAttestor'),
    'AttestationPolicy': ('src.provenance_attestor', 'AttestationPolicy'),
    'Ed25519Signer': ('src.provenance_attestor', 'Ed25519Signer'),
    'ProvenanceVerifier': ('src.provenance_verifier', 'ProvenanceVerifier'),
    'VerificationSummary': ('src.provenance_verifier', 'VerificationSummary'),
    'VerificationStatus': ('src.provenance_verifier', 'VerificationStatus'),
    'produce_transparency_log_entry': ('src.provenance_verifier', 'produce_transparency_log_entry'),
})

# ── Adversarial Bypass Discovery (2025-08-12) ─────────────────────
# 基于适应度导向搜索的补丁边界漏洞发现。
__all__.extend([
    'PatchSite', 'ExecutionTrace', 'BypassFitness', 'BypassFitnessEvaluator',
    'ConstraintHint', 'ConstraintExtractor', 'ConstraintGuidedMutator',
    'MutationLevel', 'BypassCandidate', 'BypassDiscoveryReport',
    'AdversarialBypassFinder', 'find_patch_bypasses',
])

_lazy_map.update({
    'PatchSite': ('src.bypass_fitness', 'PatchSite'),
    'ExecutionTrace': ('src.bypass_fitness', 'ExecutionTrace'),
    'BypassFitness': ('src.bypass_fitness', 'BypassFitness'),
    'BypassFitnessEvaluator': ('src.bypass_fitness', 'BypassFitnessEvaluator'),
    'ConstraintHint': ('src.constraint_guided_mutator', 'ConstraintHint'),
    'ConstraintExtractor': ('src.constraint_guided_mutator', 'ConstraintExtractor'),
    'ConstraintGuidedMutator': ('src.constraint_guided_mutator', 'ConstraintGuidedMutator'),
    'MutationLevel': ('src.constraint_guided_mutator', 'MutationLevel'),
    'BypassCandidate': ('src.adversarial_bypass_finder', 'BypassCandidate'),
    'BypassDiscoveryReport': ('src.adversarial_bypass_finder', 'BypassDiscoveryReport'),
    'AdversarialBypassFinder': ('src.adversarial_bypass_finder', 'AdversarialBypassFinder'),
    'find_patch_bypasses': ('src.adversarial_bypass_finder', 'find_patch_bypasses'),
})

# ── Patch Spectrum Analyzer (2025-08-13) ─────────────────────────
# 基于频域分析的补丁异常/后门检测。
__all__.extend([
    'PatchDiffVector', 'PatchDiffExtractor', 'SpectralFeatures',
    'SpectrumFeatureExtractor', 'MultiResolutionSpectrum',
    'MultiResolutionAnalyzer', 'AnomalyScore', 'SpectralAnomalyReport',
    'ReferenceDistribution', 'ReferenceDistributionBuilder',
    'SpectralAnomalyDetector', 'build_reference_from_patches',
    'detect_spectral_anomaly',
])

_lazy_map.update({
    'PatchDiffVector': ('src.patch_spectrum', 'PatchDiffVector'),
    'PatchDiffExtractor': ('src.patch_spectrum', 'PatchDiffExtractor'),
    'SpectralFeatures': ('src.patch_spectrum', 'SpectralFeatures'),
    'SpectrumFeatureExtractor': ('src.patch_spectrum', 'SpectrumFeatureExtractor'),
    'MultiResolutionSpectrum': ('src.patch_spectrum', 'MultiResolutionSpectrum'),
    'MultiResolutionAnalyzer': ('src.patch_spectrum', 'MultiResolutionAnalyzer'),
    'AnomalyScore': ('src.spectral_anomaly', 'AnomalyScore'),
    'SpectralAnomalyReport': ('src.spectral_anomaly', 'SpectralAnomalyReport'),
    'ReferenceDistribution': ('src.spectral_anomaly', 'ReferenceDistribution'),
    'ReferenceDistributionBuilder': ('src.spectral_anomaly', 'ReferenceDistributionBuilder'),
    'SpectralAnomalyDetector': ('src.spectral_anomaly', 'SpectralAnomalyDetector'),
    'build_reference_from_patches': ('src.spectral_anomaly', 'build_reference_from_patches'),
    'detect_spectral_anomaly': ('src.spectral_anomaly', 'detect_spectral_anomaly'),
})

# ── Patch Amortization Engine (2025-08-14) ────────────────────────
# 补丁子sumption图 + 最小集覆盖优化，消除冗余补丁。
__all__.extend([
    'PatchCoverage', 'SubsumptionEdge', 'SubsumptionGraph',
    'MinimalSetCoverSolver', 'AmortizationResult', 'amortize_patches',
])

_lazy_map.update({
    'PatchCoverage': ('src.patch_amortization', 'PatchCoverage'),
    'SubsumptionEdge': ('src.patch_amortization', 'SubsumptionEdge'),
    'SubsumptionGraph': ('src.patch_amortization', 'SubsumptionGraph'),
    'MinimalSetCoverSolver': ('src.patch_amortization', 'MinimalSetCoverSolver'),
    'AmortizationResult': ('src.patch_amortization', 'AmortizationResult'),
    'amortize_patches': ('src.patch_amortization', 'amortize_patches'),
})

# ── Live Patch Efficacy Watchdog (2025-08-15) ─────────────────────
# 运行时效力衰减监控，Bayesian 更新 + CUSUM 漂移检测。
__all__.extend([
    'EfficacyState', 'WatchdogSignal', 'EfficacyReport',
    'CUSUMDetector', 'BayesianEfficacyUpdater', 'EfficacyWatchdog',
])

_lazy_map.update({
    'EfficacyState': ('src.efficacy_watchdog', 'EfficacyState'),
    'WatchdogSignal': ('src.efficacy_watchdog', 'WatchdogSignal'),
    'EfficacyReport': ('src.efficacy_watchdog', 'EfficacyReport'),
    'CUSUMDetector': ('src.efficacy_watchdog', 'CUSUMDetector'),
    'BayesianEfficacyUpdater': ('src.efficacy_watchdog', 'BayesianEfficacyUpdater'),
    'EfficacyWatchdog': ('src.efficacy_watchdog', 'EfficacyWatchdog'),
})

# ── Micro-Arch Leakage Detector (2025-08-16) ─────────────────────
# 补丁引入的时序侧信道检测，KS + Welch + Cohen's d。
__all__.extend([
    'LeakageVerdict', 'TimingSample', 'LeakageReport',
    'TimingStatsEngine', 'UArchLeakageDetector', 'detect_uarch_leakage',
])

_lazy_map.update({
    'LeakageVerdict': ('src.uarch_leakage', 'LeakageVerdict'),
    'TimingSample': ('src.uarch_leakage', 'TimingSample'),
    'LeakageReport': ('src.uarch_leakage', 'LeakageReport'),
    'TimingStatsEngine': ('src.uarch_leakage', 'TimingStatsEngine'),
    'UArchLeakageDetector': ('src.uarch_leakage', 'UArchLeakageDetector'),
    'detect_uarch_leakage': ('src.uarch_leakage', 'detect_uarch_leakage'),
})

# ── Patch Obfuscation Hardening (2025-08-20) ─────────────────────
# 补丁抗逆向工程：寄存器重分配/等价指令替换/NOP雪崩。
__all__.extend([
    'PatchObfuscator', 'PatchObfuscationResult', 'ObfuscationRecipe',
    'LivenessAnalyzer',
])

_lazy_map.update({
    'PatchObfuscator': ('src.patch_obfuscator', 'PatchObfuscator'),
    'PatchObfuscationResult': ('src.patch_obfuscator', 'PatchObfuscationResult'),
    'ObfuscationRecipe': ('src.patch_obfuscator', 'ObfuscationRecipe'),
    'LivenessAnalyzer': ('src.patch_obfuscator', 'LivenessAnalyzer'),
})

# ── Patch Applicability Resolver (2025-08-21) ────────────────────
# 异构 fleet 补丁适用性矩阵 + Hungarian 最优匹配。
__all__.extend([
    'ApplicabilityTier', 'FleetBinary', 'PatchCandidate',
    'ApplicabilityScore', 'ApplicabilityMatrix',
    'ApplicabilityCalculator', 'HungarianSolver',
    'resolve_applicability',
])

_lazy_map.update({
    'ApplicabilityTier': ('src.patch_applicability', 'ApplicabilityTier'),
    'FleetBinary': ('src.patch_applicability', 'FleetBinary'),
    'PatchCandidate': ('src.patch_applicability', 'PatchCandidate'),
    'ApplicabilityScore': ('src.patch_applicability', 'ApplicabilityScore'),
    'ApplicabilityMatrix': ('src.patch_applicability', 'ApplicabilityMatrix'),
    'ApplicabilityCalculator': ('src.patch_applicability', 'ApplicabilityCalculator'),
    'HungarianSolver': ('src.patch_applicability', 'HungarianSolver'),
    'resolve_applicability': ('src.patch_applicability', 'resolve_applicability'),
})

# ── Patch Debt Quantifier (2025-08-22) ───────────────────────────
# 补丁技术债务四维量化：gadget/熵/膨胀/优化偏离 + 偿还计划。
__all__.extend([
    'DebtSeverity', 'DebtDimensions', 'DebtReport',
    'GadgetScanner', 'EntropyCalculator',
    'OptimizationDivergenceDetector', 'PatchDebtQuantifier',
])

_lazy_map.update({
    'DebtSeverity': ('src.patch_debt', 'DebtSeverity'),
    'DebtDimensions': ('src.patch_debt', 'DebtDimensions'),
    'DebtReport': ('src.patch_debt', 'DebtReport'),
    'GadgetScanner': ('src.patch_debt', 'GadgetScanner'),
    'EntropyCalculator': ('src.patch_debt', 'EntropyCalculator'),
    'OptimizationDivergenceDetector': ('src.patch_debt', 'OptimizationDivergenceDetector'),
    'PatchDebtQuantifier': ('src.patch_debt', 'PatchDebtQuantifier'),
})

# ── Guaranteed Atomic Rollback (2025-08-25) ───────────────────────
# 三阶段原子回滚 + 密码学完整性证明 + Provenance DAG 集成。
__all__.extend([
    'RollbackStatus', 'ByteRegion', 'RollbackProof',
    'AtomicRollbackEngine',
])

_lazy_map.update({
    'RollbackStatus': ('src.atomic_rollback', 'RollbackStatus'),
    'ByteRegion': ('src.atomic_rollback', 'ByteRegion'),
    'RollbackProof': ('src.atomic_rollback', 'RollbackProof'),
    'AtomicRollbackEngine': ('src.atomic_rollback', 'AtomicRollbackEngine'),
})

# ── Concurrency Hazard Detector (2025-08-26) ──────────────────────
# 补丁引入的并发风险：锁序/原子性/屏障/共享访问/调用约定。
__all__.extend([
    'HazardSeverity', 'ConcurrencyHazard', 'HazardReport',
    'ConcurrencyHazardDetector',
])

_lazy_map.update({
    'HazardSeverity': ('src.concurrency_hazard', 'HazardSeverity'),
    'ConcurrencyHazard': ('src.concurrency_hazard', 'ConcurrencyHazard'),
    'HazardReport': ('src.concurrency_hazard', 'HazardReport'),
    'ConcurrencyHazardDetector': ('src.concurrency_hazard', 'ConcurrencyHazardDetector'),
})

# ── Performance Impact Predictor (2025-08-27) ─────────────────────
# 补丁性能回归静态预测：指令成本 + 访存模式 + 分支预测影响。
__all__.extend([
    'ImpactCategory', 'InstructionCost', 'PerfDelta', 'PerfImpactReport',
    'InstructionCostEstimator', 'PerfImpactPredictor',
])

_lazy_map.update({
    'ImpactCategory': ('src.perf_impact', 'ImpactCategory'),
    'InstructionCost': ('src.perf_impact', 'InstructionCost'),
    'PerfDelta': ('src.perf_impact', 'PerfDelta'),
    'PerfImpactReport': ('src.perf_impact', 'PerfImpactReport'),
    'InstructionCostEstimator': ('src.perf_impact', 'InstructionCostEstimator'),
    'PerfImpactPredictor': ('src.perf_impact', 'PerfImpactPredictor'),
})

# ── Patch Semantic Explainer (2025-08-30) ─────────────────────────
# 汇编变更分类 + 结构化语义解释：边界检查/NULL检查/函数替换/净化。
__all__.extend([
    'ChangeCategory', 'SemanticExplanation', 'PatchExplanation',
    'PatchPatternMatcher', 'PatchExplainer',
])

_lazy_map.update({
    'ChangeCategory': ('src.patch_explainer', 'ChangeCategory'),
    'SemanticExplanation': ('src.patch_explainer', 'SemanticExplanation'),
    'PatchExplanation': ('src.patch_explainer', 'PatchExplanation'),
    'PatchPatternMatcher': ('src.patch_explainer', 'PatchPatternMatcher'),
    'PatchExplainer': ('src.patch_explainer', 'PatchExplainer'),
})

# ── Binary ABI Integrity Checker (2025-08-31) ─────────────────────
# 补丁的二进制接口完整性：栈帧/callee-saved/返回值/参数。
__all__.extend([
    'ABIImpact', 'ABIViolation', 'ABIReport', 'ABIIntegrityChecker',
])

_lazy_map.update({
    'ABIImpact': ('src.abi_integrity', 'ABIImpact'),
    'ABIViolation': ('src.abi_integrity', 'ABIViolation'),
    'ABIReport': ('src.abi_integrity', 'ABIReport'),
    'ABIIntegrityChecker': ('src.abi_integrity', 'ABIIntegrityChecker'),
})

# ── Call Site Impact Analyzer (2025-09-01) ────────────────────────
# 补丁对调用点的连锁影响：clobber传播 + 栈偏移 + 参数适配。
__all__.extend([
    'ImpactLevel', 'CallSite', 'CallSiteImpact', 'ImpactReport',
    'CallSiteScanner', 'CallSiteImpactAnalyzer',
])

_lazy_map.update({
    'ImpactLevel': ('src.callsite_impact', 'ImpactLevel'),
    'CallSite': ('src.callsite_impact', 'CallSite'),
    'CallSiteImpact': ('src.callsite_impact', 'CallSiteImpact'),
    'ImpactReport': ('src.callsite_impact', 'ImpactReport'),
    'CallSiteScanner': ('src.callsite_impact', 'CallSiteScanner'),
    'CallSiteImpactAnalyzer': ('src.callsite_impact', 'CallSiteImpactAnalyzer'),
})

# ── Memory-Safety Certifier (2025-09-03) ──────────────────────────
# 补丁差分的内存安全认证：UAF/双重释放/缓冲区溢出/内存泄漏。
__all__.extend([
    'MemorySafetyIssue', 'SafetyFinding', 'MemorySafetyReport',
    'MemoryOperationAnalyzer', 'MemorySafetyCertifier',
])

_lazy_map.update({
    'MemorySafetyIssue': ('src.memory_safety_cert', 'MemorySafetyIssue'),
    'SafetyFinding': ('src.memory_safety_cert', 'SafetyFinding'),
    'MemorySafetyReport': ('src.memory_safety_cert', 'MemorySafetyReport'),
    'MemoryOperationAnalyzer': ('src.memory_safety_cert', 'MemoryOperationAnalyzer'),
    'MemorySafetyCertifier': ('src.memory_safety_cert', 'MemorySafetyCertifier'),
})

# ── Diff Taint Tracker (2025-09-04) ──────────────────────────────
# 补丁前后的污点流差分：source→sink 路径 + 净化验证。
__all__.extend([
    'TaintNodeType', 'TaintNode', 'TaintFlow', 'DiffTaintReport',
    'TaintTracker', 'DiffTaintAnalyzer',
])

_lazy_map.update({
    'TaintNodeType': ('src.diff_taint', 'TaintNodeType'),
    'TaintNode': ('src.diff_taint', 'TaintNode'),
    'TaintFlow': ('src.diff_taint', 'TaintFlow'),
    'DiffTaintReport': ('src.diff_taint', 'DiffTaintReport'),
    'TaintTracker': ('src.diff_taint', 'TaintTracker'),
    'DiffTaintAnalyzer': ('src.diff_taint', 'DiffTaintAnalyzer'),
})

# ── Patch Evolutionary Lineage (2025-09-05) ───────────────────────
# 补丁演化谱系重建：特征距离矩阵 + UPGMA 系统树 + merge 检测。
__all__.extend([
    'LineageEvent', 'PatchRecord', 'LineageNode', 'LineageTree',
    'PatchFeatureExtractor', 'PatchDistanceMatrix', 'UPGMATreeBuilder',
    'reconstruct_lineage',
])

_lazy_map.update({
    'LineageEvent': ('src.patch_lineage', 'LineageEvent'),
    'PatchRecord': ('src.patch_lineage', 'PatchRecord'),
    'LineageNode': ('src.patch_lineage', 'LineageNode'),
    'LineageTree': ('src.patch_lineage', 'LineageTree'),
    'PatchFeatureExtractor': ('src.patch_lineage', 'PatchFeatureExtractor'),
    'PatchDistanceMatrix': ('src.patch_lineage', 'PatchDistanceMatrix'),
    'UPGMATreeBuilder': ('src.patch_lineage', 'UPGMATreeBuilder'),
    'reconstruct_lineage': ('src.patch_lineage', 'reconstruct_lineage'),
})

# ── Patch Forensics Timeline (2025-09-07) ─────────────────────────
# 补丁取证时间线：时序异常检测 + 三方交叉验证 + 篡改置信度。
__all__.extend([
    'AnomalyKind', 'PatchEvent', 'ForensicAnomaly', 'ForensicTimeline',
    'ForensicTimelineBuilder',
])

_lazy_map.update({
    'AnomalyKind': ('src.patch_forensics', 'AnomalyKind'),
    'PatchEvent': ('src.patch_forensics', 'PatchEvent'),
    'ForensicAnomaly': ('src.patch_forensics', 'ForensicAnomaly'),
    'ForensicTimeline': ('src.patch_forensics', 'ForensicTimeline'),
    'ForensicTimelineBuilder': ('src.patch_forensics', 'ForensicTimelineBuilder'),
})

# ── Cross-Patch Fix Distiller (2025-09-08) ────────────────────────
# 修复本质提取 + 跨二进制匹配 + 修复建议生成。
__all__.extend([
    'FixCategory', 'FixEssence', 'FixCandidate', 'DistillationReport',
    'FixEssenceExtractor', 'CrossBinaryFixMatcher', 'FixDistiller',
])

_lazy_map.update({
    'FixCategory': ('src.fix_distiller', 'FixCategory'),
    'FixEssence': ('src.fix_distiller', 'FixEssence'),
    'FixCandidate': ('src.fix_distiller', 'FixCandidate'),
    'DistillationReport': ('src.fix_distiller', 'DistillationReport'),
    'FixEssenceExtractor': ('src.fix_distiller', 'FixEssenceExtractor'),
    'CrossBinaryFixMatcher': ('src.fix_distiller', 'CrossBinaryFixMatcher'),
    'FixDistiller': ('src.fix_distiller', 'FixDistiller'),
})

# ── Patch Metamorphic Tester (2025-09-09) ─────────────────────────
# 补丁蜕变测试：5 条蜕变关系 + 语义等价变体验证。
__all__.extend([
    'MRStatus', 'MetamorphicRelation', 'MRResult', 'MetamorphicReport',
    'MetamorphicRelations', 'MetamorphicTester',
])

_lazy_map.update({
    'MRStatus': ('src.metamorphic_test', 'MRStatus'),
    'MetamorphicRelation': ('src.metamorphic_test', 'MetamorphicRelation'),
    'MRResult': ('src.metamorphic_test', 'MRResult'),
    'MetamorphicReport': ('src.metamorphic_test', 'MetamorphicReport'),
    'MetamorphicRelations': ('src.metamorphic_test', 'MetamorphicRelations'),
    'MetamorphicTester': ('src.metamorphic_test', 'MetamorphicTester'),
})

# ── Patch Minimality Certifier (2025-09-11) ───────────────────────
# 二分消去法字节级最小化 + 语义保持验证。
__all__.extend([
    'MinimalityStatus', 'ByteChunk', 'MinimalityReport',
    'ChunkExtractor', 'BinaryReductionEngine',
    'SemanticsPreservingVerifier', 'certify_minimality',
])

_lazy_map.update({
    'MinimalityStatus': ('src.patch_minimality', 'MinimalityStatus'),
    'ByteChunk': ('src.patch_minimality', 'ByteChunk'),
    'MinimalityReport': ('src.patch_minimality', 'MinimalityReport'),
    'ChunkExtractor': ('src.patch_minimality', 'ChunkExtractor'),
    'BinaryReductionEngine': ('src.patch_minimality', 'BinaryReductionEngine'),
    'SemanticsPreservingVerifier': ('src.patch_minimality', 'SemanticsPreservingVerifier'),
    'certify_minimality': ('src.patch_minimality', 'certify_minimality'),
})

# ── Anti-Detection Patch Hardener (2025-09-12) ────────────────────
# 多态字节/时序归一化/完整性检查抵抗——对抗恶意软件补丁检测。
__all__.extend([
    'StealthTechnique', 'StealthModification', 'StealthReport',
    'PolymorphicByteSelector', 'TimingNormalizer',
    'IntegrityCheckResistor', 'PatchStealthHardener',
])

_lazy_map.update({
    'StealthTechnique': ('src.patch_stealth', 'StealthTechnique'),
    'StealthModification': ('src.patch_stealth', 'StealthModification'),
    'StealthReport': ('src.patch_stealth', 'StealthReport'),
    'PolymorphicByteSelector': ('src.patch_stealth', 'PolymorphicByteSelector'),
    'TimingNormalizer': ('src.patch_stealth', 'TimingNormalizer'),
    'IntegrityCheckResistor': ('src.patch_stealth', 'IntegrityCheckResistor'),
    'PatchStealthHardener': ('src.patch_stealth', 'PatchStealthHardener'),
})

# ── Optimization Compatibility Analyzer (2025-09-13) ──────────────
# 补丁对编译器优化假设的兼容性：内联/循环展开/常量传播/DCE/PGO。
__all__.extend([
    'OptimIssueType', 'OptimIssue', 'OptimCompatReport',
    'OptimizationAssumptionDetector', 'OptimCompatAnalyzer',
])

_lazy_map.update({
    'OptimIssueType': ('src.optim_compat', 'OptimIssueType'),
    'OptimIssue': ('src.optim_compat', 'OptimIssue'),
    'OptimCompatReport': ('src.optim_compat', 'OptimCompatReport'),
    'OptimizationAssumptionDetector': ('src.optim_compat', 'OptimizationAssumptionDetector'),
    'OptimCompatAnalyzer': ('src.optim_compat', 'OptimCompatAnalyzer'),
})

# ── Self-Verifying Patch Injector (2025-09-15) ────────────────────
# 嵌入运行时自校验的补丁：字节完整性/语义健全性/运行时行为。
__all__.extend([
    'VerifyLevel', 'VerifyCheckpoint', 'SelfVerifyReport',
    'SelfVerifyGenerator',
])

_lazy_map.update({
    'VerifyLevel': ('src.self_verify', 'VerifyLevel'),
    'VerifyCheckpoint': ('src.self_verify', 'VerifyCheckpoint'),
    'SelfVerifyReport': ('src.self_verify', 'SelfVerifyReport'),
    'SelfVerifyGenerator': ('src.self_verify', 'SelfVerifyGenerator'),
})

# ── Patch-to-PoC Generator (2025-09-16) ───────────────────────────
# 从二进制补丁反向推导漏洞触发条件 + PoC 输入合成。
__all__.extend([
    'PoCStrategy', 'VulnTrigger', 'PoCReport',
    'VulnTriggerDeriver', 'PoCGenerator',
])

_lazy_map.update({
    'PoCStrategy': ('src.patch_to_poc', 'PoCStrategy'),
    'VulnTrigger': ('src.patch_to_poc', 'VulnTrigger'),
    'PoCReport': ('src.patch_to_poc', 'PoCReport'),
    'VulnTriggerDeriver': ('src.patch_to_poc', 'VulnTriggerDeriver'),
    'PoCGenerator': ('src.patch_to_poc', 'PoCGenerator'),
})

# ── Cross-Version Patch Transplant (2025-09-17) ───────────────────
# 补丁跨版本移植：函数匹配 + 偏移自适应 + 语义保持验证。
__all__.extend([
    'TransplantStatus', 'PatchSite', 'TransplantResult',
    'TransplantReport', 'VersionFunctionMatcher',
    'OffsetAdapter', 'PatchTransplanter',
])

_lazy_map.update({
    'TransplantStatus': ('src.patch_transplant', 'TransplantStatus'),
    'PatchSite': ('src.patch_transplant', 'PatchSite'),
    'TransplantResult': ('src.patch_transplant', 'TransplantResult'),
    'TransplantReport': ('src.patch_transplant', 'TransplantReport'),
    'VersionFunctionMatcher': ('src.patch_transplant', 'VersionFunctionMatcher'),
    'OffsetAdapter': ('src.patch_transplant', 'OffsetAdapter'),
    'PatchTransplanter': ('src.patch_transplant', 'PatchTransplanter'),
})

# ── Patch Survival Analyzer (2025-09-19) ──────────────────────────
# Kaplan-Meier 生存曲线 + 对数秩检验 + Nelson-Aalen 累积风险。
__all__.extend([
    'SurvivalRecord', 'KMEstimate', 'SurvivalReport',
    'KaplanMeierEstimator', 'PatchSurvivalAnalyzer',
])

_lazy_map.update({
    'SurvivalRecord': ('src.patch_survival', 'SurvivalRecord'),
    'KMEstimate': ('src.patch_survival', 'KMEstimate'),
    'SurvivalReport': ('src.patch_survival', 'SurvivalReport'),
    'KaplanMeierEstimator': ('src.patch_survival', 'KaplanMeierEstimator'),
    'PatchSurvivalAnalyzer': ('src.patch_survival', 'PatchSurvivalAnalyzer'),
})

# ── Deployment Risk Scorer (2025-09-20) ───────────────────────────
# 多信号 Bayesian 风险融合 + 硬约束 + ROC 阈值校准。
__all__.extend([
    'DeployDecision', 'RiskSignals', 'RiskReport',
    'BayesianRiskFuser',
])

_lazy_map.update({
    'DeployDecision': ('src.deploy_risk', 'DeployDecision'),
    'RiskSignals': ('src.deploy_risk', 'RiskSignals'),
    'RiskReport': ('src.deploy_risk', 'RiskReport'),
    'BayesianRiskFuser': ('src.deploy_risk', 'BayesianRiskFuser'),
})

# ── Info-Theoretic Patch Distance (2025-09-21) ────────────────────
# JSD/NCD/MI 三种信息论距离 + permutation test 显著性。
__all__.extend([
    'InfoDistance', 'InfoDistReport',
    'jensen_shannon_divergence', 'normalized_compression_distance',
    'mutual_information', 'permutation_test', 'InfoDistanceCalculator',
])

_lazy_map.update({
    'InfoDistance': ('src.info_distance', 'InfoDistance'),
    'InfoDistReport': ('src.info_distance', 'InfoDistReport'),
    'jensen_shannon_divergence': ('src.info_distance', 'jensen_shannon_divergence'),
    'normalized_compression_distance': ('src.info_distance', 'normalized_compression_distance'),
    'mutual_information': ('src.info_distance', 'mutual_information'),
    'permutation_test': ('src.info_distance', 'permutation_test'),
    'InfoDistanceCalculator': ('src.info_distance', 'InfoDistanceCalculator'),
})

# ── Patch Differential Slicing (2025-09-23) ───────────────────────
# 汇编级前后向程序切片：数据/控制依赖 + 影响半径分析。
__all__.extend([
    'SliceResult', 'SliceReport', 'DefUseAnalyzer', 'AssemblySlicer',
])

_lazy_map.update({
    'SliceResult': ('src.patch_slice', 'SliceResult'),
    'SliceReport': ('src.patch_slice', 'SliceReport'),
    'DefUseAnalyzer': ('src.patch_slice', 'DefUseAnalyzer'),
    'AssemblySlicer': ('src.patch_slice', 'AssemblySlicer'),
})

# ── Patch Equivalence Clustering (2025-09-24) ─────────────────────
# 补丁无监督等价类聚类：多特征 DBSCAN + medoid + 自动标注。
__all__.extend([
    'PatchFeatures', 'PatchCluster', 'ClusterReport',
    'PatchFeatureExtractor', 'DensityClusterer',
])

_lazy_map.update({
    'PatchFeatures': ('src.patch_cluster', 'PatchFeatures'),
    'PatchCluster': ('src.patch_cluster', 'PatchCluster'),
    'ClusterReport': ('src.patch_cluster', 'ClusterReport'),
    'PatchFeatureExtractor': ('src.patch_cluster', 'PatchFeatureExtractor'),
    'DensityClusterer': ('src.patch_cluster', 'DensityClusterer'),
})

# ── Trust Propagation Network (2025-09-25) ────────────────────────
# 补丁信任沿依赖图传播：PageRank 式迭代 + 信任瓶颈检测。
__all__.extend([
    'TrustNode', 'TrustReport', 'TrustPropagator', 'build_trust_network',
    # semantic versioning
    'SemVerBump', 'SemVerInfo', 'SemVerReport', 'SemVerInferenceEngine',
    # patch composition / CFI impact / protocol delta
    'PatchOp', 'ComposeResult', 'ComposeReport', 'PatchOpParser', 'PatchCompositionEngine',
    'CFICompatibility', 'CFIIssue', 'CFIReport', 'CFIImpactAnalyzer',
    'ProtoChangeType', 'ProtoDelta', 'ProtoDeltaReport', 'ProtoDeltaExtractor', 'ProtocolDeltaAnalyzer',
    'RegPressure', 'PortPressure', 'RegPressureReport', 'LivenessTracker', 'PortPressureModel', 'RegPressureAnalyzer',
    'EntropySource', 'EntropyFinding', 'EntropyReport', 'EntropySourceIdentifier', 'NISTSimplifiedTests', 'EntropyQualityAnalyzer',
    # Deep value-flow analyzers (8 vuln classes)
    'HeapFPFilter', 'AllocSiteScanner', 'DemandDrivenTaintTracker',
    'OverflowSatisfiabilitySolver', 'IntervalAbstractor',
    'PointerLifecycleTracker', 'FmtSiteScanner', 'IntOverflowDetector',
    'StackFrameAnalyzer', 'SharedAccessScanner',
])

_lazy_map.update({
    'TrustNode': ('src.trust_network', 'TrustNode'),
    'TrustReport': ('src.trust_network', 'TrustReport'),
    'TrustPropagator': ('src.trust_network', 'TrustPropagator'),
    'build_trust_network': ('src.trust_network', 'build_trust_network'),
    # 语义版本号
    'SemVerBump': ('src.semantic_version', 'SemVerBump'),
    'SemVerInfo': ('src.semantic_version', 'SemVerInfo'),
    'SemVerReport': ('src.semantic_version', 'SemVerReport'),
    'SemVerInferenceEngine': ('src.semantic_version', 'SemVerInferenceEngine'),
    # 补丁组合/CFI影响/协议变更
    'PatchOp': ('src.patch_compose', 'PatchOp'),
    'ComposeResult': ('src.patch_compose', 'ComposeResult'),
    'ComposeReport': ('src.patch_compose', 'ComposeReport'),
    'PatchOpParser': ('src.patch_compose', 'PatchOpParser'),
    'PatchCompositionEngine': ('src.patch_compose', 'PatchCompositionEngine'),
    'CFICompatibility': ('src.cfi_impact', 'CFICompatibility'),
    'CFIIssue': ('src.cfi_impact', 'CFIIssue'),
    'CFIReport': ('src.cfi_impact', 'CFIReport'),
    'CFIImpactAnalyzer': ('src.cfi_impact', 'CFIImpactAnalyzer'),
    'ProtoChangeType': ('src.protocol_delta', 'ProtoChangeType'),
    'ProtoDelta': ('src.protocol_delta', 'ProtoDelta'),
    'ProtoDeltaReport': ('src.protocol_delta', 'ProtoDeltaReport'),
    'ProtoDeltaExtractor': ('src.protocol_delta', 'ProtoDeltaExtractor'),
    'ProtocolDeltaAnalyzer': ('src.protocol_delta', 'ProtocolDeltaAnalyzer'),
    # 寄存器压力分析
    'RegPressure': ('src.reg_pressure', 'RegPressure'),
    'PortPressure': ('src.reg_pressure', 'PortPressure'),
    'RegPressureReport': ('src.reg_pressure', 'RegPressureReport'),
    'LivenessTracker': ('src.reg_pressure', 'LivenessTracker'),
    'PortPressureModel': ('src.reg_pressure', 'PortPressureModel'),
    'RegPressureAnalyzer': ('src.reg_pressure', 'RegPressureAnalyzer'),
    # 熵质量分析
    'EntropySource': ('src.entropy_quality', 'EntropySource'),
    'EntropyFinding': ('src.entropy_quality', 'EntropyFinding'),
    'EntropyReport': ('src.entropy_quality', 'EntropyReport'),
    'EntropySourceIdentifier': ('src.entropy_quality', 'EntropySourceIdentifier'),
    'NISTSimplifiedTests': ('src.entropy_quality', 'NISTSimplifiedTests'),
    'EntropyQualityAnalyzer': ('src.entropy_quality', 'EntropyQualityAnalyzer'),
    # Deep analyzers (value-flow based, 8 vuln classes)
    'HeapFPFilter': ('src.heap_fp_filter', 'HeapFPFilter'),
    'AllocSiteScanner': ('src.alloc_size_tracker', 'AllocSiteScanner'),
    'DemandDrivenTaintTracker': ('src.alloc_size_tracker', 'DemandDrivenTaintTracker'),
    'OverflowSatisfiabilitySolver': ('src.heap_constraint_solver', 'OverflowSatisfiabilitySolver'),
    'IntervalAbstractor': ('src.heap_constraint_solver', 'IntervalAbstractor'),
    'PointerLifecycleTracker': ('src.uaf_analyzer', 'PointerLifecycleTracker'),
    'FmtSiteScanner': ('src.fmtstr_analyzer', 'FmtSiteScanner'),
    'IntOverflowDetector': ('src.int_overflow_analyzer', 'IntOverflowDetector'),
    'StackFrameAnalyzer': ('src.stack_overflow_analyzer', 'StackFrameAnalyzer'),
    'SharedAccessScanner': ('src.race_detector', 'SharedAccessScanner'),
})
