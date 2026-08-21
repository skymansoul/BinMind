# smart_contract/src - EVM bytecode analysis pipeline
# Lazy-load submodules via _submodules registry

__version__ = "0.5.0"

_submodules = {
    "core": ".core",
    "parser": ".parser",
    "detectors": ".detectors",
    "analyzer": ".analyzer",
    "reporter": ".reporter",
    "utils": ".utils",
    "opcodes": ".core.opcodes",
    "cfg": ".cfg",
    "pattern_matcher": ".pattern_matcher",
    "taint_tracker": ".taint_tracker",
    # 跨合约污点流分析
    "cross_contract_taint": ".cross_contract_taint",
    "cli": ".cli",
}

def __getattr__(name):
    if name in _submodules:
        import importlib
        return importlib.import_module(_submodules[name], package=__package__)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

__all__ = list(_submodules.keys()) + ["__version__"]
