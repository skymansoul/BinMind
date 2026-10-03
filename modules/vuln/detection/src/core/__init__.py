# core子包入口
import os as _os

from deemo.modules.vuln.detection.src.core.confidence import BayesianConfidenceScorer, confidence_score, fuse_scores
from deemo.modules.vuln.detection.src.core.taint_engine import TaintTracker, TaintSource, TaintSink, TaintNode, TaintPath
from deemo.modules.vuln.detection.src.core.plugin import PluginBase, PluginManager, PluginMeta, discover_plugins
from deemo.modules.vuln.detection.src.core.vuln_db import VulnDB, FindingRecord, get_vuln_db
from deemo.modules.vuln.detection.src.core.vuln_lifecycle import (
    VulnLifecycle, VulnRecord, VulnStatus, VulnSeverity,
    StatusChange, _VALID_TRANSITIONS,
)
from deemo.modules.vuln.detection.src.core.vuln_dedup import (
    DeduplicationStrategy, ClusterSimilarity, MatchConfidence,
    VulnerabilitySignature, VulnerabilityCluster,
    DeduplicationResult, MergedFinding, MergeConflict, MergeResult,
    VulnDeduplicator, VulnDedupMerger,
    deduplicate_vulnerabilities, merge_from_sources,
)

# vuln_mgmt拆分模块（来自vuln_management.py解耦）
from deemo.modules.vuln.detection.src.core.vuln_mgmt_core import (
    VulnerabilityContext, DataFlowPath, CVEFootprint, DataTag,
    VulnerabilityKnowledgeNode, InferenceRule,
    VulnerabilityReporter, VulnerabilityReasoner, ExposureAnalyzer,
    CodeLocator, _RateLimiter, ThreatIntelClient, VersionExtractor,
    VersionedVulnChecker, SBOMGenerator, analyze_supply_chain,
)
from deemo.modules.vuln.detection.src.core.vuln_mgmt_slicer import VulnerabilitySlicer
from deemo.modules.vuln.detection.src.core.vuln_mgmt_knowledge import (
    VulnerabilityKnowledgeGraphBuilder, VulnerabilityRuleEngine,
    SensitiveDataLeakageChecker, AutomatedRootCauseAnalyzer,
    SecurityConfigAuditor, CrossProjectVulnerabilityCorrelationAnalyzer,
    GitDiffAnalysisTrigger, DynamicAnalysisEnvironmentManager,
)
# 漏洞因果依赖图（exploit chain推断）
from deemo.modules.vuln.detection.src.core.vuln_causal_graph import (
    VulnCausalGraph, VulnCausalNode, CausalEdge, CausalRelation,
)

_debug = _os.environ.get("VULN_DEBUG", "") == "1"

__all__ = [
    "BayesianConfidenceScorer", "confidence_score", "fuse_scores",
    "TaintTracker", "TaintSource", "TaintSink", "TaintNode", "TaintPath",
    "PluginBase", "PluginManager", "PluginMeta", "discover_plugins",
    "VulnDB", "FindingRecord", "get_vuln_db",
    "VulnLifecycle", "VulnRecord", "VulnStatus", "VulnSeverity",
    "StatusChange", "_VALID_TRANSITIONS",
    "DeduplicationStrategy", "ClusterSimilarity", "MatchConfidence",
    "VulnerabilitySignature", "VulnerabilityCluster",
    "DeduplicationResult", "MergedFinding", "MergeConflict", "MergeResult",
    "VulnDeduplicator", "VulnDedupMerger",
    "deduplicate_vulnerabilities", "merge_from_sources",
    # vuln_mgmt 拆分模块导出
    "VulnerabilityContext", "DataFlowPath", "CVEFootprint", "DataTag",
    "VulnerabilityKnowledgeNode", "InferenceRule",
    "VulnerabilityReporter", "VulnerabilityReasoner", "ExposureAnalyzer",
    "CodeLocator", "ThreatIntelClient", "VersionExtractor",
    "VersionedVulnChecker", "SBOMGenerator", "analyze_supply_chain",
    "VulnerabilitySlicer",
    "VulnerabilityKnowledgeGraphBuilder", "VulnerabilityRuleEngine",
    "SensitiveDataLeakageChecker", "AutomatedRootCauseAnalyzer",
    "SecurityConfigAuditor", "CrossProjectVulnerabilityCorrelationAnalyzer",
    "GitDiffAnalysisTrigger", "DynamicAnalysisEnvironmentManager",
    # vuln_causal_graph 模块导出
    "VulnCausalGraph", "VulnCausalNode", "CausalEdge", "CausalRelation",
]
