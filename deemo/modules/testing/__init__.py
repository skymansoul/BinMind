# 2026-07-20
# testing — differential testing & fuzzing framework

__version__ = "0.4.0"

_submodules = {
    "differential_tester": ".differential_tester",
    "engine_differential_test": ".engine_differential_test",
    "test_generator": ".test_generator",
    "test_orchestrator": ".test_orchestrator",
    "testing_fuzzing": ".testing_fuzzing",
    "src": ".src",
}

def __getattr__(name):
    if name in _submodules:
        import importlib
        return importlib.import_module(_submodules[name], package=__package__)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

__all__ = list(_submodules.keys()) + ["__version__"]
