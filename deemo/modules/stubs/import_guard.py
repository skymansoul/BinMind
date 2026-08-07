# 导入异常隔离层 — 拦截 stubs/ 下所有 import，失败时降级或返回占位模块。
# 设计约束: 单桩模块加载失败不得阻断其余模块树的导入路径。
# Implicit Patterns in Language-Model-Based Binary Analysis
# "path-dependent lock-in" 模式; DeBinVul 故障隔离策略。
import sys as _sys, functools as _ft
from typing import Any, Optional as _Opt

_original_import = __import__

class DegradeMode:
    RAISE  = 'raise'
    RETURN = 'return'
    WARN   = 'warn'
    STUB   = 'stub'

def _make_empty_module(name: str) -> Any:
    import types
    mod = types.ModuleType(name)
    mod.__doc__ = f'[import_guard] placeholder: {name}'
    return mod

class ImportGuard:

    def __init__(self, degrade: str = DegradeMode.WARN):
        self.degrade = degrade
        self.failures: list[tuple[str, str]] = []
        self._prev = None

    def __enter__(self):
        import builtins
        self._prev = builtins.__dict__.get('__import__', _original_import)
        guard = self

        @_ft.wraps(_original_import)
        def _guarded(name, *a, **kw):
            try:
                return _original_import(name, *a, **kw)
            except Exception as e:
                guard.failures.append((name, str(e)))
                if guard.degrade == DegradeMode.RAISE:
                    raise
                if guard.degrade == DegradeMode.WARN:
                    import logging
                    logging.getLogger('import_guard').warning('import degraded: %s', name)
                return _make_empty_module(name)

        builtins.__import__ = _guarded
        return self

    def __exit__(self, *a):
        import builtins
        builtins.__import__ = self._prev
        return False


def safe_import_star(src: str, target: dict, degrade: str = DegradeMode.RETURN) -> bool:
    try:
        mod = _original_import(src, fromlist=['*'])
        for k in dir(mod):
            if not k.startswith('_'):
                target[k] = getattr(mod, k)
        return True
    except Exception:
        if degrade == DegradeMode.RAISE:
            raise
        return False
