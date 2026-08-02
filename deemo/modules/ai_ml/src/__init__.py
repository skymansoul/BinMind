# 2026-07-14
# ai_ml/src/__init__.py
# 懒加载入口 -- 每个子包按需导入，避免冷启动加载所有ML依赖
# 设计权衡：用__getattr__而非显式import，启动快但首次访问有延迟

__all__ = [
    "data", "gnn", "llm", "ml", "mutation",
    "training", "evaluation", "inference",
    "anomaly", "explain", "active", "augment", "utils",
]

_SUBPACKAGE_MAP = {
    "data": ".data",
    "gnn": ".gnn",
    "llm": ".llm",
    "ml": ".ml",
    "mutation": ".mutation",
    "training": ".training",
    "evaluation": ".evaluation",
    "inference": ".inference",
    "anomaly": ".anomaly",
    "explain": ".explain",
    "active": ".active",
    "augment": ".augment",
    "utils": ".utils",
}

_loaded = {}


def __getattr__(name: str):
    if name in _loaded:
        return _loaded[name]
    if name in _SUBPACKAGE_MAP:
        import importlib
        mod = importlib.import_module(_SUBPACKAGE_MAP[name], __package__)
        _loaded[name] = mod
        return mod
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
