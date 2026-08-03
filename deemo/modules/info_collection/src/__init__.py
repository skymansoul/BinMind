# info_collection/src/ -- 意图推断与采集路由子包入口
# 向上导出 intent_route / llm_intent_infer 中的核心符号

import importlib

_submodules: dict[str, str] = {
    "intent_route": ".intent_route",
    "llm_intent_infer": ".llm_intent_infer",
}

def __getattr__(name: str):
    if name in _submodules:
        return importlib.import_module(_submodules[name], package=__package__)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

__all__ = sorted(_submodules.keys())
