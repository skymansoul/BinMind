# 2026-07-16
# smart_contract/src — EVM bytecode analysis pipeline

__version__ = "0.4.0"

_submodules = {
    "opcodes": ".opcodes",
    "parser": ".parser",
    "cfg": ".cfg",
    "pattern_matcher": ".pattern_matcher",
    "taint_tracker": ".taint_tracker",
    "detectors": ".detectors",
    "reporter": ".reporter",
}

def __getattr__(name):
    if name in _submodules:
        import importlib
        return importlib.import_module(_submodules[name], package=__package__)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

__all__ = list(_submodules.keys()) + ["__version__"]
