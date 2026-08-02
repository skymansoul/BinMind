# vuln/ — 漏洞全生命周期：存储、去重、检测
from modules.vuln.vuln_db import VulnerabilityDatabase
from modules.vuln.vuln_dedup_merger import MergedFinding, MatchConfidence, merge_findings
