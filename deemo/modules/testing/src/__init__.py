# 2026-07-20
# testing/src — differential testing & fuzzing framework

__version__ = "0.4.0"

_submodules = {
    "utils": ".utils",
    "config": ".config",
    "diff_tester": ".diff_tester",
    "engine_diff": ".engine_diff",
    "test_gen": ".test_gen",
    "orchestrator": ".orchestrator",
    "property_based": ".property_based",
    "fuzzing": ".fuzzing",
    "markov_fuzz": ".markov_fuzz",
    "power_schedule": ".power_schedule",
    "dictionary_builder": ".dictionary_builder",
    "seed_selector": ".seed_selector",
    "type_aware_fuzz": ".type_aware_fuzz",
    "concolic_bridge": ".concolic_bridge",
    "triage_reporter": ".triage_reporter",
    "memory_pattern": ".memory_pattern",
    "directed_fuzz": ".directed_fuzz",
    "concurrency_fuzz": ".concurrency_fuzz",
    "taint_tracker": ".taint_tracker",
    "uaf_detector": ".uaf_detector",
    "rop_analyzer": ".rop_analyzer",
    "crash_cluster": ".crash_cluster",
    "grammar_infer": ".grammar_infer",
    "regression_corpus": ".regression_corpus",
}

def __getattr__(name):
    if name in _submodules:
        import importlib
        return importlib.import_module(_submodules[name], package=__package__)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

__all__ = list(_submodules.keys()) + ["__version__"]
