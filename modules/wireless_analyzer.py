# 兼容入口：实现位于 network/，保留原扁平导入路径。
import importlib
_mod = importlib.import_module("modules.network.wireless_analyzer")
globals().update({k: v for k, v in _mod.__dict__.items() if not k.startswith("_")})
