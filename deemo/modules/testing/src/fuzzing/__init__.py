# 多引擎模糊测试子系统

__version__ = "0.3.0"

_submodules = {
    "fuzzer": ".fuzzer",
    "protocol": ".protocol",
    "concurrency": ".concurrency",
    "coverage": ".coverage",
    "crash_dedup": ".crash_dedup",
    "campaign": ".campaign",
    "env_fuzz": ".env_fuzz",
    "fs_check": ".fs_check",
    "net_diff": ".net_diff",
    "complexity": ".complexity",
    "multi_fuzz": ".multi_fuzz",
    "asan_parser": ".asan_parser",
    "vuln_search": ".vuln_search",
    "input_infer": ".input_infer",
}

def __getattr__(name):
    if name in _submodules:
        import importlib
        return importlib.import_module(_submodules[name], package=__package__)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

__all__ = list(_submodules.keys()) + ["__version__"]
