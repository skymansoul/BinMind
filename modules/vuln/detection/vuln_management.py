# 漏洞管理与知识图谱子系统。
# CVE关联、推理驱动利用链构建、合规映射、威胁情报整合。
#
# 架构决策: 原始2635行文件已拆分为:
#   - vuln_detection.src.core.vuln_mgmt_core   (dataclasses+reporter+threat intel+SBOM)
#   - vuln_detection.src.core.vuln_mgmt_slicer  (VulnerabilitySlicer backward slicing)
#   - vuln_detection.src.core.vuln_mgmt_knowledge (knowledge graph+rule engine+RCA)
# 外部调用者无需修改import路径, _LAZY_MAP仍指向vuln_detection.vuln_management。
#
# 本文件仅负责re-export，无自有实现，不引入任何额外依赖。

# vuln_mgmt_core re-export (dataclasses+reporter+reasoner+exposure+threat intel+SBOM)
from deemo.modules.vuln.detection.src.core.vuln_mgmt_core import (
    VulnerabilityContext,
    DataFlowPath,
    CVEFootprint,
    DataTag,
    VulnerabilityKnowledgeNode,
    InferenceRule,
    VulnerabilityReporter,
    VulnerabilityReasoner,
    ExposureAnalyzer,
    CodeLocator,
    _RateLimiter,
    ThreatIntelClient,
    VersionExtractor,
    VersionedVulnChecker,
    SBOMGenerator,
    analyze_supply_chain,
)

# vuln_mgmt_slicer re-export (backward slicing engine)
from deemo.modules.vuln.detection.src.core.vuln_mgmt_slicer import VulnerabilitySlicer

# vuln_mgmt_knowledge re-export (knowledge graph+rule engine+leakage+RCA+config audit)
from deemo.modules.vuln.detection.src.core.vuln_mgmt_knowledge import (
    VulnerabilityKnowledgeGraphBuilder,
    VulnerabilityRuleEngine,
    SensitiveDataLeakageChecker,
    AutomatedRootCauseAnalyzer,
    SecurityConfigAuditor,
    CrossProjectVulnerabilityCorrelationAnalyzer,
    GitDiffAnalysisTrigger,
    DynamicAnalysisEnvironmentManager,
)

# re-export facade完成: 24个class+1个function已保留。
# 直接消费者建议从拆分后的子模块导入。
# 向后兼容: 此文件仍为规范入口点。
