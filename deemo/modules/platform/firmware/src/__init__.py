# platform/firmware/src/: 固件分析结构化核心包入口
# 向上层 platform/firmware/__init__.py 提供分析器/提取器/报告器等子包，
# 并提供 CLI 与 main 入口模块。

import importlib

_submodules: dict[str, str] = {
    "analyzers": ".analyzers",
    "cli": ".cli",
    "core": ".core",
    "extractor": ".extractor",
    "main": ".main",
    "reporter": ".reporter",
}

def __getattr__(name: str):
    if name in _submodules:
        return importlib.import_module(_submodules[name], package=__package__)
    raise AttributeError("module {} has no attribute {}".format(__name__, name))

__all__ = sorted(_submodules.keys())
