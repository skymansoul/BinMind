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
}

def __getattr__(name):
    if name in _submodules:
        import importlib
        return importlib.import_module(_submodules[name], package=__package__)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

__all__ = list(_submodules.keys()) + ["__version__"]
