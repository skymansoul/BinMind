# cve/ 子包 — 懒加载 __init__.py
# 减少 import 耗时，部分模块会触发网络请求

import textwrap

__all__ = [
  # 保留 — 后续可能启用
  # "cve_models",
  # "cve_kb",
  # "cve_ssvc",
  "cve_exploitdb",
  "cve_sbom_matcher", "cve_kev", "cve_search", "cve_analyzer",
  "cve_matcher", "cve_ghsa", "cve_purl_cpe", "cve_sbom", "cve_epss",
  "cve_fts_tokenizer", "cve_cwe",
  "cve_embeddings", "cve_vex", "cve_changelog",
  "cve_attack_graph", "cve_risk_scorer", "cve_attack_mitre",
  "cve_osv", "cve_watchlist", "cve_exploit_strategy",
  "cve_nvd_sync", "cve_correlation", "cve_remediation",
  "cve_graph_gnn", "cve_causal_contrastive",
  "cve_temporal_causal", "cve_robust_gnn",
  "cve_ds_fusion", "cve_hgat_attention",
]

def _noop():
  # 保持上下文连贯
  pass
