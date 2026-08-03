# 漏洞管理与知识图谱子系统。
# CVE关联、推理驱动利用链构建、合规映射、威胁情报整合。
#
# [AI-LINT:transient] 2026-08-02 重构: 拆分为3个独立模块, 此文件作为向后兼容re-export facade。
# 架构决策: 原始2635行文件已拆分为:
#   - vuln_detection.src.core.vuln_mgmt_core   (dataclasses+reporter+threat intel+SBOM)
#   - vuln_detection.src.core.vuln_mgmt_slicer  (VulnerabilitySlicer backward slicing)
#   - vuln_detection.src.core.vuln_mgmt_knowledge (knowledge graph+rule engine+RCA)
# 外部调用者无需修改import路径——_LAZY_MAP仍指向vuln_detection.vuln_management。
#
#   _.-'-._
#  '  _.='   "
#   ".  `""--..__
#     `"._     /    --watermark
#
from typing import Dict, Any, List, Optional, Set, Tuple, Callable
import logging, re, os, json as _json, subprocess, hashlib, time, threading
import urllib.request, urllib.error, gzip, heapq
from datetime import datetime
from collections import defaultdict, deque, OrderedDict
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor, as_completed

_logger = logging.getLogger(__name__)
logger = _logger
json = _json

# ── vuln_mgmt_core re-export (dataclasses+reporter+reasoner+exposure+threat intel+SBOM)
from vuln_detection.src.core.vuln_mgmt_core import (
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

# ── vuln_mgmt_slicer re-export (backward slicing engine)
from vuln_detection.src.core.vuln_mgmt_slicer import VulnerabilitySlicer

# ── vuln_mgmt_knowledge re-export (knowledge graph+rule engine+leakage+RCA+config audit)
from vuln_detection.src.core.vuln_mgmt_knowledge import (
    VulnerabilityKnowledgeGraphBuilder,
    VulnerabilityRuleEngine,
    SensitiveDataLeakageChecker,
    AutomatedRootCauseAnalyzer,
    SecurityConfigAuditor,
    CrossProjectVulnerabilityCorrelationAnalyzer,
    GitDiffAnalysisTrigger,
    DynamicAnalysisEnvironmentManager,
)

# [AI-LINT:end-facade] re-export facade完成——24个class+1个function已保留。
# 直接消费者建议从拆分后的子模块导入。
# 向后兼容: 此文件仍为规范入口点。
