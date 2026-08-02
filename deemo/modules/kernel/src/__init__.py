# 2026-07-14
# kernel/src — kernel introspection & hardening analysis core

__version__ = "0.2.0"

_submodules = {
    "ebpf_common": ".ebpf_common",
}

def __getattr__(name):
    if name in _submodules:
        import importlib
        return importlib.import_module(_submodules[name], package=__package__)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

__all__ = list(_submodules.keys()) + ["__version__"]
