# 兼容入口：模块已迁移至子目录，保留原扁平导入路径。
import importlib
_mod = importlib.import_module("modules.poc_generator")
globals().update({k: v for k, v in _mod.__dict__.items() if not k.startswith("_")})
