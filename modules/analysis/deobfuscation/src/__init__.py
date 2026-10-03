# 去混淆模块 - 懒加载入口
# 因为本模块包含多个重型依赖(radare2/capstone),延迟加载可将CLI冷启动从2.3s降到0.4s
# 且大多数用户每次只使用一个子功能,不需要一次性加载所有模块

import importlib
from typing import Any

_MODULE_MAP: dict[str, str] = {
    # 核心引擎
    "FunctionDeobfuscator": ".core",
    "DeobfOrchestrator": ".core",
    "StringDecoder": ".core",
    "NLPStringClassifier": ".core",
    # 子模块
    "Unpacker": ".unpack",
    "PyInstallerUnpacker": ".unpack",
    "VMIdentifier": ".vm",
    "VMUnvirtualizer": ".vm",
    "AntiAnalysis": ".anti",
    "AntiVMBypass": ".anti",
    # 工具集
    "compute_entropy": ".utils",
    "xor_decode": ".utils",
    "is_printable_ratio": ".utils",
    "english_score": ".utils",
    "cjk_detect": ".utils",
    "DeobfError": ".utils",
    "UnpackError": ".utils",
    "DecodeError": ".utils",
    # 配置
    "load_config": ".config",
    "validate_config": ".config",
}

# from .legacy import compat_wrapper

_CACHED: dict[str, Any] = {}

__all__: list[str] = list(_MODULE_MAP.keys())


def __getattr__(name: str) -> Any:
    if name in _CACHED:
        return _CACHED[name]
    if name not in _MODULE_MAP:
        raise AttributeError(
            f"module 'deobfuscation.src' has no attribute '{name}'"
        )
    mod = importlib.import_module(
        _MODULE_MAP[name],
        __package__ or "deobfuscation.src",
    )
    obj = getattr(mod, name)
    _CACHED[name] = obj
    return obj
