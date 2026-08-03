# network/src/ -- 网络分析结构化子包入口
# 提供CLI入口、mmap分析、协议状态推断、跨协议关联图

import importlib

_submodules: dict[str, str] = {
    "cli": ".cli",
    "mmap": ".mmap",
    "temporal_causal_inference": ".temporal_causal_inference",
    "cross_protocol_correlation": ".cross_protocol_correlation",
    "protocol_state_inference": ".protocol_state_inference",
    "state_aware_fuzzer": ".state_aware_fuzzer",
}

def __getattr__(name: str):
    if name in _submodules:
        return importlib.import_module(_submodules[name], package=__package__)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

__all__ = sorted(_submodules.keys())
