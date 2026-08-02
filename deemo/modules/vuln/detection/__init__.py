# 2026-07-20 — vuln_detection package init with lazy imports
# 按需加载子模块，避免启动时全量导入的冷启动延迟。
# 对外暴露核心类和工厂函数，隐藏内部实现细节。

import sys as _sys
import importlib as _importlib
from typing import Any as _Any

# 暴露的关键符号表 —— IDE自动补全依赖此映射
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
]

# 懒加载映射表 —— 首次访问属性时按需import
_LAZY_MAP: dict = {
    # vuln_management (优先加载，其他模块依赖其基类)
    "VulnerabilityContext": "vuln_detection.vuln_management",
    "DataFlowPath": "vuln_detection.vuln_management",
    "CVEFootprint": "vuln_detection.vuln_management",
    "DataTag": "vuln_detection.vuln_management",
    "VulnerabilityKnowledgeNode": "vuln_detection.vuln_management",
    "InferenceRule": "vuln_detection.vuln_management",
    "VulnerabilitySlicer": "vuln_detection.vuln_management",
    "VulnerabilityReporter": "vuln_detection.vuln_management",
    "VulnerabilityReasoner": "vuln_detection.vuln_management",
    "ExposureAnalyzer": "vuln_detection.vuln_management",
    "CodeLocator": "vuln_detection.vuln_management",
    "ThreatIntelClient": "vuln_detection.vuln_management",
    "VersionExtractor": "vuln_detection.vuln_management",
    "VersionedVulnChecker": "vuln_detection.vuln_management",
    "SBOMGenerator": "vuln_detection.vuln_management",
    "VulnerabilityKnowledgeGraphBuilder": "vuln_detection.vuln_management",
    "VulnerabilityRuleEngine": "vuln_detection.vuln_management",
    "SensitiveDataLeakageChecker": "vuln_detection.vuln_management",
    "AutomatedRootCauseAnalyzer": "vuln_detection.vuln_management",
    "SecurityConfigAuditor": "vuln_detection.vuln_management",
    "CrossProjectVulnerabilityCorrelationAnalyzer": "vuln_detection.vuln_management",
    "GitDiffAnalysisTrigger": "vuln_detection.vuln_management",
    "DynamicAnalysisEnvironmentManager": "vuln_detection.vuln_management",
    "analyze_supply_chain": "vuln_detection.vuln_management",
    # supply_chain
    "LibraryComponent": "vuln_detection.supply_chain",
    "VulnerabilityMatch": "vuln_detection.supply_chain",
    "SoftwareBillOfMaterials": "vuln_detection.supply_chain",
    "SupplyChainAnalyzer": "vuln_detection.supply_chain",
    # sbom_exporter
    "SBOMComponent": "vuln_detection.sbom_exporter",
    "SBOMDocument": "vuln_detection.sbom_exporter",
    "SBOMExporter": "vuln_detection.sbom_exporter",
    "export_sbom_from_analysis": "vuln_detection.sbom_exporter",
    # vuln_deduplicator
    "ClusterSimilarity": "vuln_detection.vuln_deduplicator",
    "DeduplicationStrategy": "vuln_detection.vuln_deduplicator",
    "VulnerabilitySignature": "vuln_detection.vuln_deduplicator",
    "VulnerabilityCluster": "vuln_detection.vuln_deduplicator",
    "DeduplicationResult": "vuln_detection.vuln_deduplicator",
    "VulnDeduplicator": "vuln_detection.vuln_deduplicator",
    "deduplicate_vulnerabilities": "vuln_detection.vuln_deduplicator",
    # vuln_dedup_merger
    "VulnDedupMerger": "vuln_detection.vuln_dedup_merger",
    "MergeResult": "vuln_detection.vuln_dedup_merger",
    # vuln_lifecycle_api
    "VulnStatus": "vuln_detection.vuln_lifecycle_api",
    "VulnSeverity": "vuln_detection.vuln_lifecycle_api",
    "VulnLifecycleAPI": "vuln_detection.vuln_lifecycle_api",
    # security_isolation
    "SandboxType": "vuln_detection.security_isolation",
    "CodeSanitizer": "vuln_detection.security_isolation",
    "BinarySanitizer": "vuln_detection.security_isolation",
    "SandboxExecutor": "vuln_detection.security_isolation",
    "GvisorExecutor": "vuln_detection.security_isolation",
    "FirecrackerExecutor": "vuln_detection.security_isolation",
    "DockerExecutor": "vuln_detection.security_isolation",
    "SubprocessExecutor": "vuln_detection.security_isolation",
    "SandboxManager": "vuln_detection.security_isolation",
    "LLMDataSanitizer": "vuln_detection.security_isolation",
    "get_sandbox_manager": "vuln_detection.security_isolation",
    "get_llm_sanitizer": "vuln_detection.security_isolation",
    # attack_to_exploit
    "ExploitabilityPrediction": "vuln_detection.attack_to_exploit",
    "predict_exploitability": "vuln_detection.attack_to_exploit",
    "rank_by_exploitability": "vuln_detection.attack_to_exploit",
    # supply_chain_reachability
    "ReachabilityResult": "vuln_detection.supply_chain_reachability",
    "CallGraphBuilder": "vuln_detection.supply_chain_reachability",
    "analyze_reachability": "vuln_detection.supply_chain_reachability",
    # vuln_verification_sandbox
    "SandboxBackend": "vuln_detection.vuln_verification_sandbox",
    "PoCGenerator": "vuln_detection.vuln_verification_sandbox",
    "VerificationResult": "vuln_detection.vuln_verification_sandbox",
    "analyze_crash": "vuln_detection.vuln_verification_sandbox",
    # vuln_propagation
    "VulnerabilityNode": "vuln_detection.vuln_propagation",
    "PropagationEdge": "vuln_detection.vuln_propagation",
    "PropagationResult": "vuln_detection.vuln_propagation",
    "VulnPropagationAnalyzer": "vuln_detection.vuln_propagation",
    "analyze_vuln_propagation": "vuln_detection.vuln_propagation",
    "build_program_dependency_graph": "vuln_detection.vuln_propagation",
    "find_affected_functions": "vuln_detection.vuln_propagation",
    # vuln_rewriter
    "VulnerabilityType": "vuln_detection.vuln_rewriter",
    "RewriteStrategy": "vuln_detection.vuln_rewriter",
    "FunctionSummary": "vuln_detection.vuln_rewriter",
    "VulnerabilityInfo": "vuln_detection.vuln_rewriter",
    "RewriteResult": "vuln_detection.vuln_rewriter",
    "IRNode": "vuln_detection.vuln_rewriter",
    "IRBuilder": "vuln_detection.vuln_rewriter",
    "ConstraintSolver": "vuln_detection.vuln_rewriter",
    "CodeSynthesizer": "vuln_detection.vuln_rewriter",
    "VulnerabilityRewriter": "vuln_detection.vuln_rewriter",
    "VulnerabilityRewriterTask": "vuln_detection.vuln_rewriter",
    "rewrite_vulnerable_function": "vuln_detection.vuln_rewriter",
    # yara_auto_gen
    "FeatureType": "vuln_detection.yara_auto_gen",
    "RulePriority": "vuln_detection.yara_auto_gen",
    "YaraFeature": "vuln_detection.yara_auto_gen",
    "YaraRule": "vuln_detection.yara_auto_gen",
    "ValidationResult": "vuln_detection.yara_auto_gen",
    "GenerationResult": "vuln_detection.yara_auto_gen",
    "YaraAutoGenerator": "vuln_detection.yara_auto_gen",
    "generate_yara_rules": "vuln_detection.yara_auto_gen",
    # yara_manager
    "YaraRuleMeta": "vuln_detection.yara_manager",
    "YaraMatchResult": "vuln_detection.yara_manager",
    "YaraRuleGenerator": "vuln_detection.yara_manager",
    "YaraScanner": "vuln_detection.yara_manager",
    "generate_yara_from_analysis": "vuln_detection.yara_manager",
    "yara_scan_target": "vuln_detection.yara_manager",
    # attack_mapper
    "map_vulnerability": "vuln_detection.attack_mapper",
    "CWE_ATTACK_MAP": "vuln_detection.attack_mapper",
    # anomaly_zeroday
    "AnomalyLevel": "vuln_detection.anomaly_zeroday",
    "AnomalyReport": "vuln_detection.anomaly_zeroday",
    "NormalModel": "vuln_detection.anomaly_zeroday",
    "ZScoreAnomalyDetector": "vuln_detection.anomaly_zeroday",
    "IsolationForestAnomalyDetector": "vuln_detection.anomaly_zeroday",
    "AnomalyZerodayAnalyzer": "vuln_detection.anomaly_zeroday",
    # ids_rule_generator
    "RuleProtocol": "vuln_detection.ids_rule_generator",
    "RuleAction": "vuln_detection.ids_rule_generator",
    "AttackSignature": "vuln_detection.ids_rule_generator",
    "IDSRuleContent": "vuln_detection.ids_rule_generator",
    "IDSRuleGenerator": "vuln_detection.ids_rule_generator",
    "NetworkFunctionInfo": "vuln_detection.ids_rule_generator",
    "generate_ids_rules": "vuln_detection.ids_rule_generator",
    # sandbox_escape_detector
    "EscapeAttemptType": "vuln_detection.sandbox_escape_detector",
    "EscapeSeverity": "vuln_detection.sandbox_escape_detector",
    "EscapeAttempt": "vuln_detection.sandbox_escape_detector",
    "SandboxMonitoringResult": "vuln_detection.sandbox_escape_detector",
    "SandboxEscapeDetector": "vuln_detection.sandbox_escape_detector",
    "detect_sandbox_escape": "vuln_detection.sandbox_escape_detector",
    # sandbox_policy_gen
    "BPFInstruction": "vuln_detection.sandbox_policy_gen",
    "SyscallInfo": "vuln_detection.sandbox_policy_gen",
    "PolicyType": "vuln_detection.sandbox_policy_gen",
    "SandboxPolicy": "vuln_detection.sandbox_policy_gen",
    "SandboxPolicyGenerator": "vuln_detection.sandbox_policy_gen",
    "generate_sandbox_policy": "vuln_detection.sandbox_policy_gen",
    # vulnerability_reporter
    "ReportPlatform": "vuln_detection.vulnerability_reporter",
    "ReportSeverity": "vuln_detection.vulnerability_reporter",
    "VulnerabilityReport": "vuln_detection.vulnerability_reporter",
    "SubmissionResult": "vuln_detection.vulnerability_reporter",
    "create_vulnerability_report": "vuln_detection.vulnerability_reporter",
    "export_report_to_file": "vuln_detection.vulnerability_reporter",
    # false_positive_filter
    "BenignPatternLearner": "vuln_detection.false_positive_filter",
    "FalsePositiveFilter": "vuln_detection.false_positive_filter",
    "create_false_positive_filter": "vuln_detection.false_positive_filter",
    # llm_vuln_detector
    "VulnSignalType": "vuln_detection.llm_vuln_detector",
    "VulnSignal": "vuln_detection.llm_vuln_detector",
    "LLMVulnReport": "vuln_detection.llm_vuln_detector",
    "LLMVulnerabilityDetector": "vuln_detection.llm_vuln_detector",
    "HybridVulnDetector": "vuln_detection.llm_vuln_detector",
    "detect_vulnerability_llm": "vuln_detection.llm_vuln_detector",
    "batch_detect_llm": "vuln_detection.llm_vuln_detector",
    # graph_binary_embedder
    "ArchFamily": "vuln_detection.graph_binary_embedder",
    "BasicBlockNode": "vuln_detection.graph_binary_embedder",
    "FunctionGraph": "vuln_detection.graph_binary_embedder",
    "GraphEmbedding": "vuln_detection.graph_binary_embedder",
    "GraphBinaryEmbedder": "vuln_detection.graph_binary_embedder",
    "CrossArchAligner": "vuln_detection.graph_binary_embedder",
    "build_graph_from_disasm": "vuln_detection.graph_binary_embedder",
    "compute_similarity_matrix": "vuln_detection.graph_binary_embedder",
    # fuzzing_orchestrator
    "FuzzerType": "vuln_detection.fuzzing_orchestrator",
    "FuzzerStatus": "vuln_detection.fuzzing_orchestrator",
    "CrashSeverity": "vuln_detection.fuzzing_orchestrator",
    "FuzzerConfig": "vuln_detection.fuzzing_orchestrator",
    "CrashInfo": "vuln_detection.fuzzing_orchestrator",
    "FuzzingCampaign": "vuln_detection.fuzzing_orchestrator",
    "FuzzingOrchestrator": "vuln_detection.fuzzing_orchestrator",
    "CrashTriager": "vuln_detection.fuzzing_orchestrator",
    "fuzz_target": "vuln_detection.fuzzing_orchestrator",
    "triage_crash_directory": "vuln_detection.fuzzing_orchestrator",
    # exploit_generation_pipeline
    "ExploitStrategy": "vuln_detection.exploit_generation_pipeline",
    "PayloadArch": "vuln_detection.exploit_generation_pipeline",
    "VulnDescriptor": "vuln_detection.exploit_generation_pipeline",
    "ROPGadget": "vuln_detection.exploit_generation_pipeline",
    "ExploitPlan": "vuln_detection.exploit_generation_pipeline",
    "ExploitResult": "vuln_detection.exploit_generation_pipeline",
    "generate_exploit": "vuln_detection.exploit_generation_pipeline",
    # multimodal_vuln_fusion
    "ModalEvidence": "vuln_detection.multimodal_vuln_fusion",
    "FusionResult": "vuln_detection.multimodal_vuln_fusion",
    "MultiModalVulnFuser": "vuln_detection.multimodal_vuln_fusion",
    "fuse_vulnerability_scores": "vuln_detection.multimodal_vuln_fusion",
    "compute_evidence_discord": "vuln_detection.multimodal_vuln_fusion",
    # runtime_vuln_verifier
    "VerificationStatus": "vuln_detection.runtime_vuln_verifier",
    "RuntimeState": "vuln_detection.runtime_vuln_verifier",
    "VerificationResult": "vuln_detection.runtime_vuln_verifier",
    "GDBRunner": "vuln_detection.runtime_vuln_verifier",
    "ASANRunner": "vuln_detection.runtime_vuln_verifier",
    "RuntimeVulnVerifier": "vuln_detection.runtime_vuln_verifier",
    "verify_finding": "vuln_detection.runtime_vuln_verifier",
    "batch_verify_findings": "vuln_detection.runtime_vuln_verifier",
    # binary_diff_analyzer
    "ChangeCategory": "vuln_detection.binary_diff_analyzer",
    "SecurityImpact": "vuln_detection.binary_diff_analyzer",
    "BinaryChange": "vuln_detection.binary_diff_analyzer",
    "DiffReport": "vuln_detection.binary_diff_analyzer",
    "BinaryDiffAnalyzer": "vuln_detection.binary_diff_analyzer",
    "diff_binaries": "vuln_detection.binary_diff_analyzer",
    "compare_function_lists": "vuln_detection.binary_diff_analyzer",
    # vuln_chain_analyzer
    "VulnNode": "vuln_detection.vuln_chain_analyzer",
    "ChainEdge": "vuln_detection.vuln_chain_analyzer",
    "VulnChain": "vuln_detection.vuln_chain_analyzer",
    "ChainAnalysisResult": "vuln_detection.vuln_chain_analyzer",
    "VulnChainAnalyzer": "vuln_detection.vuln_chain_analyzer",
    "analyze_vulnerability_chains": "vuln_detection.vuln_chain_analyzer",
    "build_vuln_node": "vuln_detection.vuln_chain_analyzer",
    # patch_quality_evaluator
    "PatchQuality": "vuln_detection.patch_quality_evaluator",
    "DimensionScore": "vuln_detection.patch_quality_evaluator",
    "PatchEvaluation": "vuln_detection.patch_quality_evaluator",
    "PatchQualityEvaluator": "vuln_detection.patch_quality_evaluator",
    "evaluate_patch": "vuln_detection.patch_quality_evaluator",
    # binary_entropy_analyzer
    "PackingStatus": "vuln_detection.binary_entropy_analyzer",
    "SectionType": "vuln_detection.binary_entropy_analyzer",
    "SectionEntropy": "vuln_detection.binary_entropy_analyzer",
    "EntropyReport": "vuln_detection.binary_entropy_analyzer",
    "BinaryEntropyAnalyzer": "vuln_detection.binary_entropy_analyzer",
    "analyze_entropy": "vuln_detection.binary_entropy_analyzer",
    "quick_entropy_check": "vuln_detection.binary_entropy_analyzer",
}


def __getattr__(name: str) -> _Any:
    """懒加载入口——首次访问模块属性时触发import。
    Python 3.7+的PEP 562模块级__getattr__机制。
    """
    module_path = _LAZY_MAP.get(name)
    if module_path is None:
        raise AttributeError(f"module 'vuln_detection' has no attribute '{name}'")
    mod = _importlib.import_module(module_path)
    attr = getattr(mod, name)
    # 绑定到当前模块，后续访问绕过__getattr__
    setattr(_sys.modules[__name__], name, attr)
    return attr


# 预加载vuln_management——其他模块依赖其基类，避免循环导入时的递归深度问题
def _eager_load_core() -> None:
    try:
        _importlib.import_module("vuln_detection.vuln_management")
    except Exception:
        pass


_eager_load_core()
