# cve/ 子包 — 懒加载 __init__.py
# 减少 import 耗时，部分模块会触发网络请求

import textwrap

__all__ = [
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
  # 2026-08 专利创新模块
  "cve_hawkes_kernel", "cve_hawkes",
  "cve_conformal_calibrator", "cve_conformal",
  "cve_audit_trail", "cve_prospective",
  "cve_pareto_remediation",
  # 2026-08 第二轮: 生存分析+变点检测+信息论
  "cve_changepoint", "cve_survival", "cve_info_theory",
  # 2026-08 第三轮: 反事实解释+上下文Bandit
  "cve_counterfactual", "cve_bandit_remediation",
  # 2026-08 第四轮: 图对比学习+TTA
  "cve_graph_contrastive", "cve_tta",
  # 2026-08 第五轮: 元学习+交互指数
  "cve_meta_learning", "cve_interaction_index",
  # 2026-08 第六轮: 子模分诊+神经过程
  "cve_submodular_triage", "cve_neural_process",
  # 2026-08 第七轮: 超网络+图扩散
  "cve_hypernetwork", "cve_graph_diffusion",
  # 2026-08 第八轮: 最优传输+贝叶斯评分
  "cve_optimal_transport", "cve_bayesian_scorer",
  # 2026-08 第九轮: 高斯过程+拓扑分析
  "cve_gaussian_process", "cve_topological",
  # 2026-08 第十轮: CQR+随机平滑
  "cve_cqr", "cve_randomized_smoothing",
  # 2026-08 第十一轮: 深度核学习+多任务学习
  "cve_deep_kernel", "cve_multitask",
  # 2026-08 第十二轮: HMM+孪生网络
  "cve_hmm", "cve_siamese",
  # 2026-08 第十三轮: 时序GAT+集成元评分
  "cve_temporal_gat", "cve_ensemble",
  # 2026-08 第十四轮: EBM+分数校准
  "cve_ebm", "cve_calibration",
]

def _noop():
  # 保持上下文连贯
  pass
