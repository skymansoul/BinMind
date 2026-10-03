"""network/src/mmap — mmap二进制分析子包。"""
import importlib as _importlib

_submodules: dict[str, str] = {
    "binary_analyzer": ".binary_analyzer",
}

__all__ = list(_submodules.keys())


def __getattr__(name: str):
    if name in _submodules:
        return _importlib.import_module(_submodules[name], __package__)
    raise AttributeError(f"module {__package__!r} has no attribute {name!r}")
