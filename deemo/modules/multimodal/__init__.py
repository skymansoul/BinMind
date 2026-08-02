# 2026-07-24
# multimodal — cross-modal analysis & fusion

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
}

def __getattr__(name):
    if name in _submodules:
        import importlib
        return importlib.import_module(_submodules[name], package=__package__)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

__all__ = list(_submodules.keys()) + ["__version__"]
