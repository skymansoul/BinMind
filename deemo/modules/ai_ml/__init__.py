# ai_ml/ 智能/ML 模块入口，懒加载子模块及结构化 src/ 子包
# 扁平命名空间由 modules/__init__.py _FlatFinder 接管解析；
# 本 __init__.py 使 ai_ml 成为可被子包导入的正规 package，
# 并提供 from modules.ai_ml import X 属性访问。

import importlib

_submodules: dict[str, str] = {
    # -- 结构化子包 --
    "src": ".src",

    # -- 常用 flat 模块（按需懒加载，其余交 _FlatFinder 覆盖） --
    "deep_search": ".deep_search",
    "nn_model_scanner": ".nn_model_scanner",
    "vuln_ml": ".vuln_ml",
    "knowledge_graph": ".knowledge_graph",
    "llm_crash_generator": ".llm_crash_generator",
    "rl_mutate": ".rl_mutate",
    "rl_exploit_agent": ".rl_exploit_agent",
    "rl_vuln_agent": ".rl_vuln_agent",
    "gnn_vuln_detector": ".gnn_vuln_detector",
    "gnn_vulnerability_detector": ".gnn_vulnerability_detector",
    "ml_features": ".ml_features",
    "ai_mutator": ".ai_mutator",
    "ai_path_prioritizer": ".ai_path_prioritizer",
    "program_synth_exploit": ".program_synth_exploit",
    "multimodal_vuln_analyzer": ".multimodal_vuln_analyzer",
    "llm_guided_symbex": ".llm_guided_symbex",
    "ml_guided_symbex": ".ml_guided_symbex",
    "llm_deobfuscator": ".llm_deobfuscator",
    "vuln_trend_forecaster": ".vuln_trend_forecaster",
    "vuln_trend_predictor": ".vuln_trend_predictor",
    "threat_intel": ".threat_intel",
    "threat_intelligence_aggregator": ".threat_intelligence_aggregator",
    "symbol_recovery": ".symbol_recovery",
    "distilled_vuln_detector": ".distilled_vuln_detector",
    "function_summarizer": ".function_summarizer",
    "pseudocode_explainer": ".pseudocode_explainer",
    "pseudocode_renamer": ".pseudocode_renamer",
    "pseudocode_compressor": ".pseudocode_compressor",
    "ai_function_namer": ".ai_function_namer",
    "ai_confidence_calibrator": ".ai_confidence_calibrator",
    "ai_ensemble_voting": ".ai_ensemble_voting",
    "semantic_diff": ".semantic_diff",
    "semantic_search": ".semantic_search",
    "semantic_search_llm": ".semantic_search_llm",
    "adaptive_ai_model": ".adaptive_ai_model",
    "adaptive_profiler": ".adaptive_profiler",
    "custom_ai_finetune_pipeline": ".custom_ai_finetune_pipeline",
    "data_quality": ".data_quality",
    "feature_importance": ".feature_importance",
    "fewshot_active_sampler": ".fewshot_active_sampler",
    "graph_contrastive_search": ".graph_contrastive_search",
    "gat_graph_encoder": ".gat_graph_encoder",
    "mixhop_gnn": ".mixhop_gnn",
    "multi_view_gnn": ".multi_view_gnn",
    "mlm_pretrain": ".mlm_pretrain",
    "graph_augmentation": ".graph_augmentation",
    "cross_arch_transfer": ".cross_arch_transfer",
    "obfuscation_resilience": ".obfuscation_resilience",
    "trajectory_anomaly": ".trajectory_anomaly",
    "diffusion_anomaly": ".diffusion_anomaly",
    "binary_embedding_trainer": ".binary_embedding_trainer",
    "register_pattern_ml": ".register_pattern_ml",
    "hex_byte_embedder": ".hex_byte_embedder",
    "code_embedding_fix": ".code_embedding_fix",
    "graphrag_retriever": ".graphrag_retriever",
    "graph_db": ".graph_db",
    "llm_agent_binary": ".llm_agent_binary",
    "multimodal_embedding": ".multimodal_embedding",
    "on_demand_summary": ".on_demand_summary",
    "summary_based_analyzer": ".summary_based_analyzer",
    "vector_search_accelerator": ".vector_search_accelerator",
    "dataflow_embedder": ".dataflow_embedder",
    "function_comment_generator": ".function_comment_generator",
    "two_channel_vuln_detector": ".two_channel_vuln_detector",
    "patch_vuln_discovery": ".patch_vuln_discovery",
    "adversarial_testing": ".adversarial_testing",
    "token_consumption_tracker": ".token_consumption_tracker",
    "benchmark_cache": ".benchmark_cache",
}


def __getattr__(name: str):
    if name in _submodules:
        return importlib.import_module(_submodules[name], package=__package__)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = sorted(_submodules.keys())
