# 兼容入口：模块已迁移至 info_collection/interactive_shell.py，保留原扁平导入路径
import importlib
_mod = importlib.import_module("modules.info_collection.interactive_shell")
globals().update({k: v for k, v in _mod.__dict__.items() if not k.startswith("_")})
