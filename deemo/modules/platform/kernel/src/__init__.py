# kernel/src -- kernel introspection & hardening analysis core

__version__ = "0.2.0"

_submodules = {
    "ebpf_common": ".ebpf_common",
    "ebpf_analyzer": ".ebpf_analyzer",
    "ebpf_taint_tracker": ".ebpf_taint_tracker",
    "kernel_exploit_gen": ".kernel_exploit_gen",
    "windows_kernel_callback_detector": ".windows_kernel_callback_detector",
    "cli": ".cli",
    "utils": ".utils",
}

def __getattr__(name):
    if name in _submodules:
        import importlib
        return importlib.import_module(_submodules[name], package=__package__)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

__all__ = list(_submodules.keys()) + ["__version__"]
