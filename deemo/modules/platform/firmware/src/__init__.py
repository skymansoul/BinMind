# 2026-07-15
# firmware/src 子模块懒加载入口

_SRC_LAZY = {"core": ".core", "extractor": ".extractor",
             "analyzers": ".analyzers", "reporter": ".reporter",
             "logger": ".core.logger"}


def __getattr__(name: str):
    if name in _SRC_LAZY:
        import importlib
        mod = importlib.import_module(_SRC_LAZY[name], __package__)
        globals()[name] = mod
        return mod
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__() -> list[str]:
    return list(_SRC_LAZY.keys())
