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
