# 兼容入口：模块已迁移至 core/binary_info.py，保留原扁平导入路径
import importlib
_mod = importlib.import_module("core.binary_info")
globals().update({k: v for k, v in _mod.__dict__.items() if not k.startswith("_")})
