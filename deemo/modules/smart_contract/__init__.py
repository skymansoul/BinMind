# 2026-07-16
# smart_contract — EVM smart contract vulnerability analysis

__version__ = "0.4.0"

_submodules = {
    "smart_contract_analyzer": ".smart_contract_analyzer",
    "src": ".src",
}

def __getattr__(name):
    if name in _submodules:
        import importlib
        return importlib.import_module(_submodules[name], package=__package__)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

__all__ = list(_submodules.keys()) + ["__version__"]
