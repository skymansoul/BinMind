# 跨模态分析子模块注册与懒加载入口

__version__ = "0.4.0"

_submodules = {
    "multi_dimension_stats_api": ".multi_dimension_stats_api",
    "multi_stage_orchestrator": ".multi_stage_orchestrator",
    "multi_target_exploit_adapter": ".multi_target_exploit_adapter",
    "multicore_parallel_analyzer": ".multicore_parallel_analyzer",
    "multi_modal_attention": ".multi_modal_attention",
    "multi_modal_alignment": ".multi_modal_alignment",
    "multi_modal_confidence": ".multi_modal_confidence",
    "multi_modal_retrieval": ".multi_modal_retrieval",
    "multi_modal_fusion": ".multi_modal_fusion",
    "multi_modal_survival": ".multi_modal_survival",
    "multi_modal_conformal": ".multi_modal_conformal",
    # 跨模态幻觉检测 / Shapley归因 / 时序衰减加权 / 跨模态异常检测 (2026 Q3 专利补齐)
    "cross_modal_hallucination": ".cross_modal_hallucination",
    "modal_shapley_attribution": ".modal_shapley_attribution",
    "temporal_modal_weighting": ".temporal_modal_weighting",
    "cross_modal_anomaly": ".cross_modal_anomaly",
    "modal_budget_optimizer": ".modal_budget_optimizer",
}

def __getattr__(name):
    if name in _submodules:
        import importlib
        return importlib.import_module(_submodules[name], package=__package__)
    raise AttributeError("module {} has no attribute {}".format(__name__, name))

__all__ = list(_submodules.keys()) + ["__version__"]
