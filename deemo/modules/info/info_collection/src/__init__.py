# info_collection/src — 二进制情报提取入口
# 通过 __getattr__ 按需加载子模块，避免全量导入

__version__ = "0.3.0"

_submodules = {
    "config": ".config",
    "utils": ".utils",
    "binary_info": ".binary_info",
    "anonymizer": ".anonymizer",
    "findings": ".findings",
    "injection_detect": ".injection_detect",
    "lateral": ".lateral",
    "persistence": ".persistence",
    "spoofing": ".spoofing",
    "tls_detect": ".tls_detect",
    "leak_analyzer": ".leak_analyzer",
    "pii": ".pii",
    "cli": ".cli",
    "protection_interaction": ".protection_interaction",
    "segment_risk": ".segment_risk",
    "security_posture": ".security_posture",
    "posture_pipeline": ".posture_pipeline",
}

def __getattr__(name):
    if name in _submodules:
        import importlib
        return importlib.import_module(_submodules[name], package=__package__)
    raise AttributeError("module {} has no attribute {}".format(__name__, name))

__all__ = list(_submodules.keys()) + ["__version__"]
