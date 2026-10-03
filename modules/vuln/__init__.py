# 漏洞生命周期入口 — 存储 / 去重 / 检测
try:
    from modules.vuln.vuln_db import VulnerabilityDatabase
except ImportError:
    pass

try:
    from modules.vuln.vuln_dedup_merger import MergedFinding, MatchConfidence
except ImportError:
    pass

# merge_findings 未导出，以 VulnDedupMerger 替代
try:
    from modules.vuln.vuln_dedup_merger import VulnDedupMerger
except ImportError:
    pass
