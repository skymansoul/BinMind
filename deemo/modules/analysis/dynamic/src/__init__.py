# dynamic — 惰性加载模块入口
# 导出子系统: engine, memory, 追踪, 插桩,
# 仿真, forensic, vmi
#
# 使用注册表模式而非继承 — 类型安全稍弱但避免
# 过深类层级损害可读性
#
# 架构说明: 子模块是 engine/ 目录的薄封装,
# 提供稳定公共 API, engine/ 内部可自由变更

import importlib
import logging

log = logging.getLogger(__name__)

__version__ = "0.4.0"

_SUB_MODULES: dict[str, str] = {
    # 公共 facade 模块 — engine/ 内部的薄封装
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
