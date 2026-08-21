# dynamic — lazy-loading module 入口
# Exports sub-systems: engine, memory, 追踪, 插桩
# 仿真, forensic, vmi
#
# Using registry pattern instead inheritance — less type-safe but avoids
# deep class hierarchies hurt readability
#
# Architecture note: sub-module a thin facade over engine/
# directory, 包含 real implementation. facades 提供
# a stable public API engine/ internals churn freely

import importlib
import logging

log = logging.getLogger(__name__)

__version__ = "0.4.0"

_SUB_MODULES: dict[str, str] = {
    # Public facade modules — thin 封装s over engine/ internals
    "engine": ".engine",
    "memory": ".memory",
    "tracing": ".tracing",
    "instrumentation": ".instrumentation",
    "emulation": ".emulation",
    "forensic": ".forensic",
    "vmi": ".vmi",
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
            f"module 'analysis.dynamic' has no attribute '{name}'"
        )
    mod = importlib.import_module(
        _SUB_MODULES[name],
        __package__ or "modules.analysis.dynamic.src"
    )
    _CACHED[name] = mod
    return mod


__all__ = sorted(list(_SUB_MODULES.keys()) + ["__version__"])
