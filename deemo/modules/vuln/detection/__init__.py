# 漏洞检测包入口——惰性导入机制
# 按需加载子模块，消解启动阶段全量导入的冷启动延迟。
# 对外暴露核心类与工厂函数，内部实现细节隐藏。
# HACK: _sys别名兼容Python 3.10以下版本importlib行为差异，3.12+可移除此workaround。

import sys as _sys
import importlib as _importlib
from typing import Any as _Any

# 公开符号映射——IDE自动补全依据
__all__ = [
    # vuln_management
    "VulnerabilityContext", "DataFlowPath", "CVEFootprint", "DataTag",
    "VulnerabilityKnowledgeNode", "InferenceRule",
    "VulnerabilitySlicer", "VulnerabilityReporter", "VulnerabilityReasoner",
    "ExposureAnalyzer", "CodeLocator", "ThreatIntelClient",
    "VersionExtractor", "VersionedVulnChecker", "SBOMGenerator",
    "VulnerabilityKnowledgeGraphBuilder", "VulnerabilityRuleEngine",
    "SensitiveDataLeakageChecker", "AutomatedRootCauseAnalyzer",
    "SecurityConfigAuditor", "CrossProjectVulnerabilityCorrelationAnalyzer",
    "GitDiffAnalysisTrigger", "DynamicAnalysisEnvironmentManager",
    "analyze_supply_chain",
    # supply_chain
    "LibraryComponent", "VulnerabilityMatch", "SoftwareBillOfMaterials",
    "SupplyChainAnalyzer",
    # sbom_exporter
    "SBOMComponent", "SBOMDocument", "SBOMExporter", "export_sbom_from_analysis",
    # vuln_deduplicator
    "ClusterSimilarity", "DeduplicationStrategy", "VulnerabilitySignature",
    "VulnerabilityCluster", "DeduplicationResult", "VulnDeduplicator",
    "deduplicate_vulnerabilities",
    # vuln_dedup_merger
    "VulnDedupMerger", "MergeResult",
    # vuln_lifecycle_api
    "VulnStatus", "VulnSeverity", "VulnLifecycleAPI",
    # security_isolation
    "SandboxType", "CodeSanitizer", "BinarySanitizer",
    "SandboxExecutor", "GvisorExecutor", "FirecrackerExecutor",
    "DockerExecutor", "SubprocessExecutor", "SandboxManager",
    "LLMDataSanitizer", "get_sandbox_manager", "get_llm_sanitizer",
    # attack_to_exploit
    "ExploitabilityPrediction", "predict_exploitability", "rank_by_exploitability",
    # supply_chain_reachability
    "ReachabilityResult", "CallGraphBuilder", "analyze_reachability",
    # vuln_verification_sandbox
    "SandboxBackend", "PoCGenerator", "VerificationResult", "analyze_crash",
    # vuln_propagation
    "VulnerabilityNode", "PropagationEdge", "PropagationResult",
    "VulnPropagationAnalyzer", "analyze_vuln_propagation",
    "build_program_dependency_graph", "find_affected_functions",
    # vuln_rewriter
    "VulnerabilityType", "RewriteStrategy", "FunctionSummary",
    "VulnerabilityInfo", "RewriteResult", "IRNode", "IRBuilder",
    "ConstraintSolver", "CodeSynthesizer", "VulnerabilityRewriter",
    "VulnerabilityRewriterTask", "rewrite_vulnerable_function",
    # yara_auto_gen
    "FeatureType", "RulePriority", "YaraFeature", "YaraRule",
    "ValidationResult", "GenerationResult", "YaraAutoGenerator",
    "generate_yara_rules",
    # yara_manager
    "YaraRuleMeta", "YaraMatchResult", "YaraRuleGenerator", "YaraScanner",
    "generate_yara_from_analysis", "yara_scan_target",
    # attack_mapper
    "map_vulnerability", "CWE_ATTACK_MAP",
    # anomaly_zeroday
    "AnomalyLevel", "AnomalyReport", "NormalModel",
    "ZScoreAnomalyDetector", "IsolationForestAnomalyDetector",
    "AnomalyZerodayAnalyzer",
    # ids_rule_generator
    "RuleProtocol", "RuleAction", "AttackSignature", "IDSRuleContent",
    "IDSRuleGenerator", "NetworkFunctionInfo", "generate_ids_rules",
    # sandbox_escape_detector
    "EscapeAttemptType", "EscapeSeverity", "EscapeAttempt",
    "SandboxMonitoringResult", "SandboxEscapeDetector", "detect_sandbox_escape",
    # sandbox_policy_gen
    "BPFInstruction", "SyscallInfo", "PolicyType", "SandboxPolicy",
    "SandboxPolicyGenerator", "generate_sandbox_policy",
    # vulnerability_reporter
    "ReportPlatform", "ReportSeverity", "VulnerabilityReport",
    "SubmissionResult", "create_vulnerability_report", "export_report_to_file",
    # false_positive_filter
    "BenignPatternLearner", "FalsePositiveFilter", "create_false_positive_filter",
    # llm_vuln_detector
    "VulnSignalType", "VulnSignal", "LLMVulnReport", "LLMVulnerabilityDetector",
    "HybridVulnDetector", "detect_vulnerability_llm", "batch_detect_llm",
    # graph_binary_embedder
    "ArchFamily", "BasicBlockNode", "FunctionGraph", "GraphEmbedding",
    "GraphBinaryEmbedder", "CrossArchAligner", "build_graph_from_disasm",
    "compute_similarity_matrix",
    # fuzzing_orchestrator
    "FuzzerType", "FuzzerStatus", "CrashSeverity", "FuzzerConfig", "CrashInfo",
    "FuzzingCampaign", "FuzzingOrchestrator", "CrashTriager",
    "fuzz_target", "triage_crash_directory",
    # exploit_generation_pipeline
    "ExploitStrategy", "PayloadArch", "VulnDescriptor", "ROPGadget",
    "ExploitPlan", "ExploitResult", "generate_exploit",
    # multimodal_vuln_fusion
    "ModalEvidence", "FusionResult", "MultiModalVulnFuser",
    "fuse_vulnerability_scores", "compute_evidence_discord",
    # runtime_vuln_verifier
    "VerificationStatus", "RuntimeState", "VerificationResult", "GDBRunner",
    "ASANRunner", "RuntimeVulnVerifier", "verify_finding", "batch_verify_findings",
    # binary_diff_analyzer
    "ChangeCategory", "SecurityImpact", "BinaryChange", "DiffReport",
    "BinaryDiffAnalyzer", "diff_binaries", "compare_function_lists",
    # vuln_chain_analyzer
    "VulnNode", "ChainEdge", "VulnChain", "ChainAnalysisResult",
    "VulnChainAnalyzer", "analyze_vulnerability_chains", "build_vuln_node",
    # patch_quality_evaluator
    "PatchQuality", "DimensionScore", "PatchEvaluation",
    "PatchQualityEvaluator", "evaluate_patch",
    # binary_entropy_analyzer
    "PackingStatus", "SectionType", "SectionEntropy", "EntropyReport",
    "BinaryEntropyAnalyzer", "analyze_entropy", "quick_entropy_check",
    # anvil_v2 (2026-08-02)
    "CalibrationSample", "ConformalThreshold", "ANVILResult", "ANVILDetector",
    "calibrate_from_dataset",
    # five_modal_fusion (2026-08-02)
    "FiveModalFuser", "make_evidence", "fuse_five_modals",
]

# 惰性加载映射——首次属性访问时按需import
_LAZY_MAP: dict = {
    # vuln_management（优先加载，其余模块依赖其基类）
    "VulnerabilityContext": "vuln.detection.vuln_management",
    "DataFlowPath": "vuln.detection.vuln_management",
    "CVEFootprint": "vuln.detection.vuln_management",
    "DataTag": "vuln.detection.vuln_management",
    "VulnerabilityKnowledgeNode": "vuln.detection.vuln_management",
    "InferenceRule": "vuln.detection.vuln_management",
    "VulnerabilitySlicer": "vuln.detection.vuln_management",
    "VulnerabilityReporter": "vuln.detection.vuln_management",
    "VulnerabilityReasoner": "vuln.detection.vuln_management",
    "ExposureAnalyzer": "vuln.detection.vuln_management",
    "CodeLocator": "vuln.detection.vuln_management",
    "ThreatIntelClient": "vuln.detection.vuln_management",
    "VersionExtractor": "vuln.detection.vuln_management",
    "VersionedVulnChecker": "vuln.detection.vuln_management",
    "SBOMGenerator": "vuln.detection.vuln_management",
    "VulnerabilityKnowledgeGraphBuilder": "vuln.detection.vuln_management",
    "VulnerabilityRuleEngine": "vuln.detection.vuln_management",
    "SensitiveDataLeakageChecker": "vuln.detection.vuln_management",
    "AutomatedRootCauseAnalyzer": "vuln.detection.vuln_management",
    "SecurityConfigAuditor": "vuln.detection.vuln_management",
    "CrossProjectVulnerabilityCorrelationAnalyzer": "vuln.detection.vuln_management",
    "GitDiffAnalysisTrigger": "vuln.detection.vuln_management",
    "DynamicAnalysisEnvironmentManager": "vuln.detection.vuln_management",
    "analyze_supply_chain": "vuln.detection.vuln_management",
    # supply_chain
    "LibraryComponent": "vuln.detection.supply_chain",
    "VulnerabilityMatch": "vuln.detection.supply_chain",
    "SoftwareBillOfMaterials": "vuln.detection.supply_chain",
    "SupplyChainAnalyzer": "vuln.detection.supply_chain",
    # sbom_exporter
    "SBOMComponent": "vuln.detection.sbom_exporter",
    "SBOMDocument": "vuln.detection.sbom_exporter",
    "SBOMExporter": "vuln.detection.sbom_exporter",
    "export_sbom_from_analysis": "vuln.detection.sbom_exporter",
    # vuln_deduplicator
    "ClusterSimilarity": "vuln.detection.vuln_deduplicator",
    "DeduplicationStrategy": "vuln.detection.vuln_deduplicator",
    "VulnerabilitySignature": "vuln.detection.vuln_deduplicator",
    "VulnerabilityCluster": "vuln.detection.vuln_deduplicator",
    "DeduplicationResult": "vuln.detection.vuln_deduplicator",
    "VulnDeduplicator": "vuln.detection.vuln_deduplicator",
    "deduplicate_vulnerabilities": "vuln.detection.vuln_deduplicator",
    # vuln_dedup_merger
    "VulnDedupMerger": "vuln.detection.vuln_dedup_merger_alt",
    "MergeResult": "vuln.detection.vuln_dedup_merger_alt",
    # vuln_lifecycle_api
    "VulnStatus": "vuln.detection.vuln_lifecycle_api",
    "VulnSeverity": "vuln.detection.vuln_lifecycle_api",
    "VulnLifecycleAPI": "vuln.detection.vuln_lifecycle_api",
    # security_isolation
    "SandboxType": "vuln.detection.security_isolation",
    "CodeSanitizer": "vuln.detection.security_isolation",
    "BinarySanitizer": "vuln.detection.security_isolation",
    "SandboxExecutor": "vuln.detection.security_isolation",
    "GvisorExecutor": "vuln.detection.security_isolation",
    "FirecrackerExecutor": "vuln.detection.security_isolation",
    "DockerExecutor": "vuln.detection.security_isolation",
    "SubprocessExecutor": "vuln.detection.security_isolation",
    "SandboxManager": "vuln.detection.security_isolation",
    "LLMDataSanitizer": "vuln.detection.security_isolation",
    "get_sandbox_manager": "vuln.detection.security_isolation",
    "get_llm_sanitizer": "vuln.detection.security_isolation",
    # attack_to_exploit
    "ExploitabilityPrediction": "vuln.detection.attack_to_exploit",
    "predict_exploitability": "vuln.detection.attack_to_exploit",
    "rank_by_exploitability": "vuln.detection.attack_to_exploit",
    # supply_chain_reachability
    "ReachabilityResult": "vuln.detection.supply_chain_reachability",
    "CallGraphBuilder": "vuln.detection.supply_chain_reachability",
    "analyze_reachability": "vuln.detection.supply_chain_reachability",
    # vuln_verification_sandbox
    "SandboxBackend": "vuln.detection.vuln_verification_sandbox",
    "PoCGenerator": "vuln.detection.vuln_verification_sandbox",
    "VerificationResult": "vuln.detection.vuln_verification_sandbox",
    "analyze_crash": "vuln.detection.vuln_verification_sandbox",
    # vuln_propagation
    "VulnerabilityNode": "vuln.detection.vuln_propagation",
    "PropagationEdge": "vuln.detection.vuln_propagation",
    "PropagationResult": "vuln.detection.vuln_propagation",
    "VulnPropagationAnalyzer": "vuln.detection.vuln_propagation",
    "analyze_vuln_propagation": "vuln.detection.vuln_propagation",
    "build_program_dependency_graph": "vuln.detection.vuln_propagation",
    "find_affected_functions": "vuln.detection.vuln_propagation",
    # vuln_rewriter
    "VulnerabilityType": "vuln.detection.vuln_rewriter",
    "RewriteStrategy": "vuln.detection.vuln_rewriter",
    "FunctionSummary": "vuln.detection.vuln_rewriter",
    "VulnerabilityInfo": "vuln.detection.vuln_rewriter",
    "RewriteResult": "vuln.detection.vuln_rewriter",
    "IRNode": "vuln.detection.vuln_rewriter",
    "IRBuilder": "vuln.detection.vuln_rewriter",
    "ConstraintSolver": "vuln.detection.vuln_rewriter",
    "CodeSynthesizer": "vuln.detection.vuln_rewriter",
    "VulnerabilityRewriter": "vuln.detection.vuln_rewriter",
    "VulnerabilityRewriterTask": "vuln.detection.vuln_rewriter",
    "rewrite_vulnerable_function": "vuln.detection.vuln_rewriter",
    # yara_auto_gen
    "FeatureType": "vuln.detection.yara_auto_gen",
    "RulePriority": "vuln.detection.yara_auto_gen",
    "YaraFeature": "vuln.detection.yara_auto_gen",
    "YaraRule": "vuln.detection.yara_auto_gen",
    "ValidationResult": "vuln.detection.yara_auto_gen",
    "GenerationResult": "vuln.detection.yara_auto_gen",
    "YaraAutoGenerator": "vuln.detection.yara_auto_gen",
    "generate_yara_rules": "vuln.detection.yara_auto_gen",
    # yara_manager
    "YaraRuleMeta": "vuln.detection.yara_manager",
    "YaraMatchResult": "vuln.detection.yara_manager",
    "YaraRuleGenerator": "vuln.detection.yara_manager",
    "YaraScanner": "vuln.detection.yara_manager",
    "generate_yara_from_analysis": "vuln.detection.yara_manager",
    "yara_scan_target": "vuln.detection.yara_manager",
    # attack_mapper
    "map_vulnerability": "vuln.detection.attack_mapper",
    "CWE_ATTACK_MAP": "vuln.detection.attack_mapper",
    # anomaly_zeroday
    "AnomalyLevel": "vuln.detection.anomaly_zeroday",
    "AnomalyReport": "vuln.detection.anomaly_zeroday",
    "NormalModel": "vuln.detection.anomaly_zeroday",
    "ZScoreAnomalyDetector": "vuln.detection.anomaly_zeroday",
    "IsolationForestAnomalyDetector": "vuln.detection.anomaly_zeroday",
    "AnomalyZerodayAnalyzer": "vuln.detection.anomaly_zeroday",
    # ids_rule_generator
    "RuleProtocol": "vuln.detection.ids_rule_generator",
    "RuleAction": "vuln.detection.ids_rule_generator",
    "AttackSignature": "vuln.detection.ids_rule_generator",
    "IDSRuleContent": "vuln.detection.ids_rule_generator",
    "IDSRuleGenerator": "vuln.detection.ids_rule_generator",
    "NetworkFunctionInfo": "vuln.detection.ids_rule_generator",
    "generate_ids_rules": "vuln.detection.ids_rule_generator",
    # sandbox_escape_detector
    "EscapeAttemptType": "vuln.detection.sandbox_escape_detector",
    "EscapeSeverity": "vuln.detection.sandbox_escape_detector",
    "EscapeAttempt": "vuln.detection.sandbox_escape_detector",
    "SandboxMonitoringResult": "vuln.detection.sandbox_escape_detector",
    "SandboxEscapeDetector": "vuln.detection.sandbox_escape_detector",
    "detect_sandbox_escape": "vuln.detection.sandbox_escape_detector",
    # sandbox_policy_gen
    "BPFInstruction": "vuln.detection.sandbox_policy_gen",
    "SyscallInfo": "vuln.detection.sandbox_policy_gen",
    "PolicyType": "vuln.detection.sandbox_policy_gen",
    "SandboxPolicy": "vuln.detection.sandbox_policy_gen",
    "SandboxPolicyGenerator": "vuln.detection.sandbox_policy_gen",
    "generate_sandbox_policy": "vuln.detection.sandbox_policy_gen",
    # vulnerability_reporter
    "ReportPlatform": "vuln.detection.vulnerability_reporter",
    "ReportSeverity": "vuln.detection.vulnerability_reporter",
    "VulnerabilityReport": "vuln.detection.vulnerability_reporter",
    "SubmissionResult": "vuln.detection.vulnerability_reporter",
    "create_vulnerability_report": "vuln.detection.vulnerability_reporter",
    "export_report_to_file": "vuln.detection.vulnerability_reporter",
    # false_positive_filter
    "BenignPatternLearner": "vuln.detection.false_positive_filter",
    "FalsePositiveFilter": "vuln.detection.false_positive_filter",
    "create_false_positive_filter": "vuln.detection.false_positive_filter",
    # llm_vuln_detector
    "VulnSignalType": "vuln.detection.llm_vuln_detector",
    "VulnSignal": "vuln.detection.llm_vuln_detector",
    "LLMVulnReport": "vuln.detection.llm_vuln_detector",
    "LLMVulnerabilityDetector": "vuln.detection.llm_vuln_detector",
    "HybridVulnDetector": "vuln.detection.llm_vuln_detector",
    "detect_vulnerability_llm": "vuln.detection.llm_vuln_detector",
    "batch_detect_llm": "vuln.detection.llm_vuln_detector",
    # graph_binary_embedder
    "ArchFamily": "vuln.detection.graph_binary_embedder",
    "BasicBlockNode": "vuln.detection.graph_binary_embedder",
    "FunctionGraph": "vuln.detection.graph_binary_embedder",
    "GraphEmbedding": "vuln.detection.graph_binary_embedder",
    "GraphBinaryEmbedder": "vuln.detection.graph_binary_embedder",
    "CrossArchAligner": "vuln.detection.graph_binary_embedder",
    "build_graph_from_disasm": "vuln.detection.graph_binary_embedder",
    "compute_similarity_matrix": "vuln.detection.graph_binary_embedder",
    # fuzzing_orchestrator
    "FuzzerType": "vuln.detection.fuzzing_orchestrator",
    "FuzzerStatus": "vuln.detection.fuzzing_orchestrator",
    "CrashSeverity": "vuln.detection.fuzzing_orchestrator",
    "FuzzerConfig": "vuln.detection.fuzzing_orchestrator",
    "CrashInfo": "vuln.detection.fuzzing_orchestrator",
    "FuzzingCampaign": "vuln.detection.fuzzing_orchestrator",
    "FuzzingOrchestrator": "vuln.detection.fuzzing_orchestrator",
    "CrashTriager": "vuln.detection.fuzzing_orchestrator",
    "fuzz_target": "vuln.detection.fuzzing_orchestrator",
    "triage_crash_directory": "vuln.detection.fuzzing_orchestrator",
    # exploit_generation_pipeline
    "ExploitStrategy": "vuln.detection.exploit_generation_pipeline",
    "PayloadArch": "vuln.detection.exploit_generation_pipeline",
    "VulnDescriptor": "vuln.detection.exploit_generation_pipeline",
    "ROPGadget": "vuln.detection.exploit_generation_pipeline",
    "ExploitPlan": "vuln.detection.exploit_generation_pipeline",
    "ExploitResult": "vuln.detection.exploit_generation_pipeline",
    "generate_exploit": "vuln.detection.exploit_generation_pipeline",
    # multimodal_vuln_fusion
    "ModalEvidence": "vuln.detection.multimodal_vuln_fusion",
    "FusionResult": "vuln.detection.multimodal_vuln_fusion",
    "MultiModalVulnFuser": "vuln.detection.multimodal_vuln_fusion",
    "fuse_vulnerability_scores": "vuln.detection.multimodal_vuln_fusion",
    "compute_evidence_discord": "vuln.detection.multimodal_vuln_fusion",
    # runtime_vuln_verifier
    "VerificationStatus": "vuln.detection.runtime_vuln_verifier",
    "RuntimeState": "vuln.detection.runtime_vuln_verifier",
    "VerificationResult": "vuln.detection.runtime_vuln_verifier",
    "GDBRunner": "vuln.detection.runtime_vuln_verifier",
    "ASANRunner": "vuln.detection.runtime_vuln_verifier",
    "RuntimeVulnVerifier": "vuln.detection.runtime_vuln_verifier",
    "verify_finding": "vuln.detection.runtime_vuln_verifier",
    "batch_verify_findings": "vuln.detection.runtime_vuln_verifier",
    # binary_diff_analyzer
    "ChangeCategory": "vuln.detection.binary_diff_analyzer",
    "SecurityImpact": "vuln.detection.binary_diff_analyzer",
    "BinaryChange": "vuln.detection.binary_diff_analyzer",
    "DiffReport": "vuln.detection.binary_diff_analyzer",
    "BinaryDiffAnalyzer": "vuln.detection.binary_diff_analyzer",
    "diff_binaries": "vuln.detection.binary_diff_analyzer",
    "compare_function_lists": "vuln.detection.binary_diff_analyzer",
    # vuln_chain_analyzer
    "VulnNode": "vuln.detection.vuln_chain_analyzer",
    "ChainEdge": "vuln.detection.vuln_chain_analyzer",
    "VulnChain": "vuln.detection.vuln_chain_analyzer",
    "ChainAnalysisResult": "vuln.detection.vuln_chain_analyzer",
    "VulnChainAnalyzer": "vuln.detection.vuln_chain_analyzer",
    "analyze_vulnerability_chains": "vuln.detection.vuln_chain_analyzer",
    "build_vuln_node": "vuln.detection.vuln_chain_analyzer",
    # patch_quality_evaluator
    "PatchQuality": "vuln.detection.patch_quality_evaluator",
    "DimensionScore": "vuln.detection.patch_quality_evaluator",
    "PatchEvaluation": "vuln.detection.patch_quality_evaluator",
    "PatchQualityEvaluator": "vuln.detection.patch_quality_evaluator",
    "evaluate_patch": "vuln.detection.patch_quality_evaluator",
    # binary_entropy_analyzer
    "PackingStatus": "vuln.detection.binary_entropy_analyzer",
    "SectionType": "vuln.detection.binary_entropy_analyzer",
    "SectionEntropy": "vuln.detection.binary_entropy_analyzer",
    "EntropyReport": "vuln.detection.binary_entropy_analyzer",
    "BinaryEntropyAnalyzer": "vuln.detection.binary_entropy_analyzer",
    "analyze_entropy": "vuln.detection.binary_entropy_analyzer",
    "quick_entropy_check": "vuln.detection.binary_entropy_analyzer",
    # anvil_v2 (2026-08-02)
    "CalibrationSample": "vuln.detection.anvil_v2",
    "ConformalThreshold": "vuln.detection.anvil_v2",
    "ANVILResult": "vuln.detection.anvil_v2",
    "ANVILDetector": "vuln.detection.anvil_v2",
    "calibrate_from_dataset": "vuln.detection.anvil_v2",
    # five_modal_fusion (2026-08-02)
    "FiveModalFuser": "vuln.detection.five_modal_fusion",
    "make_evidence": "vuln.detection.five_modal_fusion",
    "fuse_five_modals": "vuln.detection.five_modal_fusion",
    "_FIVE_MODAL_WEIGHTS": "vuln.detection.five_modal_fusion",
}


def __getattr__(name: str) -> _Any:
    """惰性加载入口——首次属性访问触发import。
    PEP 562模块级__getattr__机制（Python 3.7+）。
    """
    module_path = _LAZY_MAP.get(name)
    if module_path is None:
        raise AttributeError(f"module 'vuln_detection' has no attribute '{name}'")
    mod = _importlib.import_module(module_path)
    attr = getattr(mod, name)
    # 绑定至当前模块命名空间，后续访问绕过__getattr__
    setattr(_sys.modules[__name__], name, attr)
    return attr


# 预加载vuln_management——其他模块依赖其基类，规避循环导入递归深度问题
def _eager_load_core() -> None:
    try:
        _importlib.import_module("vuln.detection.vuln_management")
    except Exception:
        pass


_eager_load_core()
