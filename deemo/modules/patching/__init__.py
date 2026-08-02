# patching module — binary patch analysis & auto-fix toolchain
# v2 refactor Aug 2026, 懒加载以避免循环导入问题
# this file also serves as compat shim for older direct imports
# v3 expansion: patch safety, stack integrity, gadget analysis, CVE kb, etc.

__version__ = "2.2.0"

import sys as _sys
import os as _os

# Ensure patching/src is on the path for relative imports
_cur = _os.path.dirname(_os.path.abspath(__file__))
_src = _os.path.join(_cur, 'src')
if _src not in _sys.path:
    _sys.path.insert(0, _src)

# ── lazy imports via __getattr__ ──────────────────────────────────────

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
    # src subpackage
    'PatchConfig',
    'BackupManager', 'InstrumentationManager', 'PatchVerifier',
    'PatchError', 'PatchApplyError', 'PatchVerifyError', 'BackupError',
    # v3 expansions (2026-08)
    'PatchSafetyVerifier', 'SafetyVerdict', 'SafetyReport', 'verify_patch_safety', 'batch_safety_check',
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
    # src subpackage
    'PatchConfig': ('src.config', 'PatchConfig'),
    'BackupManager': ('src.backup_manager', 'BackupManager'),
    'InstrumentationManager': ('src.instr_manager', 'InstrumentationManager'),
    'PatchVerifier': ('src.patch_verifier', 'PatchVerifier'),
    'PatchError': ('src.exceptions', 'PatchError'),
    'PatchApplyError': ('src.exceptions', 'PatchApplyError'),
    'PatchVerifyError': ('src.exceptions', 'PatchVerifyError'),
    'BackupError': ('src.exceptions', 'BackupError'),
    # v3 expansions (2026-08)
    'PatchSafetyVerifier': ('patch_safety_verifier', 'PatchSafetyVerifier'),
    'SafetyVerdict': ('patch_safety_verifier', 'SafetyVerdict'),
    'SafetyReport': ('patch_safety_verifier', 'SafetyReport'),
    'verify_patch_safety': ('patch_safety_verifier', 'verify_patch_safety'),
    'batch_safety_check': ('patch_safety_verifier', 'batch_safety_check'),
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
    """Lazy import shim — defer loading until attribute access."""
    if name in _lazy_map:
        mod_name, attr = _lazy_map[name]
        # remap to parent module (files live in patching/ not patching/src/)
        import importlib
        mod = importlib.import_module(f'.{mod_name}', package=__name__)
        obj = getattr(mod, attr)
        # cache onto module so we don't importlib again
        globals()[name] = obj
        return obj
    raise AttributeError(f"module '{__name__}' has no attribute '{name}'")
