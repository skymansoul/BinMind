# 兼容入口：实现位于 analysis/dynamic/engine/，保留旧路径导入。
import importlib
_mod = importlib.import_module("modules.analysis.dynamic.engine.taint_engine_v2")
globals().update({k: v for k, v in _mod.__dict__.items() if not k.startswith("_")})
