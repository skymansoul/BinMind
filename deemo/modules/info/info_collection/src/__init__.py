# 2026-07-14
# info_collection/src — binary intelligence core
# 单一入口，延迟加载所有子模块

__version__ = "0.3.0"

_submodules = {
    "config": ".config",
    "utils": ".utils",
    "binary_info": ".binary_info",
    "anonymizer": ".anonymizer",
    "findings": ".findings",
    "injection_detect": ".injection_detect",
    "lateral": ".lateral",
    "persistence": ".persistence",
    "spoofing": ".spoofing",
    "tls_detect": ".tls_detect",
    "leak_analyzer": ".leak_analyzer",
    "pii": ".pii",
    "cli": ".cli",
}

def __getattr__(name):
    if name in _submodules:
        import importlib
        return importlib.import_module(_submodules[name], package=__package__)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

__all__ = list(_submodules.keys()) + ["__version__"]
