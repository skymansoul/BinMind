# 反编译引擎 — lazy-loading module 入口

import importlib
import logging

log = logging.getLogger(__name__)

__version__ = "0.4.0"

_SUB_MODULES: dict[str, str] = {
    "core": ".core",
    "ir": ".ir",
    "utils": ".utils",
    "config": ".config",
}

_CACHED: dict[str, object] = {}


def __getattr__(name: str) -> object:
    if name in _CACHED:
        return _CACHED[name]
    if name == "__version__":
        return __version__
    if name not in _SUB_MODULES:
        raise AttributeError(
            f"module 'analysis.decompiler' has no attribute '{name}'"
        )
    mod = importlib.import_module(
        _SUB_MODULES[name],
        __package__ or "modules.analysis.decompiler.src"
    )
    _CACHED[name] = mod
    return mod


__all__ = sorted(list(_SUB_MODULES.keys()) + ["__version__"])
