# 2026-07-15
# kernel — OS-level kernel security analysis

__version__ = "0.3.1"

# 子模块注册表 — 懒加载入口。
# key=外部属性名, value=导入路径(相对于当前包)
_submodules = {
    "ebpf_analyzer": ".ebpf_analyzer",
    "ebpf_taint_tracker": ".ebpf_taint_tracker",
    "kernel_exploit_gen": ".kernel_exploit_gen",
    "windows_kernel_callback_detector": ".windows_kernel_callback_detector",
    "kernel_config_analyzer": ".kernel_config_analyzer",
    "kernel_module_parser": ".kernel_module_parser",
    "syscall_table_analyzer": ".syscall_table_analyzer",
    "src": ".src",
}

# 可选子模块 — 导入失败时不抛出异常，仅静默跳过
# 用于尚未实现或依赖外部库的模块
_optional_submodules: set[str] = {"syscall_table_analyzer", "src"}


def __getattr__(name):
    """懒加载子模块访问器。

    首次访问 kernel.ebpf_analyzer 时触发 import，
    之后由 Python 缓存机制直接返回模块对象。
    """
    if name in _submodules:
        import importlib
        try:
            return importlib.import_module(_submodules[name], package=__package__)
        except ImportError as exc:
            if name in _optional_submodules:
                # 可选模块缺失：返回占位对象
                return _MissingSubmodule(name, str(exc))
            raise
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


class _MissingSubmodule:
    """可选子模块的占位对象 — 访问时抛出有意义的错误信息。"""
    __slots__ = ("_name", "_reason")

    def __init__(self, name: str, reason: str):
        self._name = name
        self._reason = reason

    def __repr__(self):
        return f"<missing submodule {self._name!r}: {self._reason}>"

    def __bool__(self):
        return False


# 模块元信息 — 供外部工具链查询
def version_info() -> dict:
    """返回版本信息及各子模块的可用性状态。"""
    _available = {}
    for _name, _path in _submodules.items():
        try:
            __import__(_path.lstrip("."), fromlist=[_name],
                       level=1 if _path.startswith(".") else 0)
            _available[_name] = "loaded"
        except ImportError:
            _available[_name] = "missing" if _name in _optional_submodules else "error"
    return {
        "version": __version__,
        "modules": _available,
    }


def list_available() -> list[str]:
    """返回当前可导入的子模块名称列表。"""
    return [n for n in _submodules if n not in _optional_submodules]


__all__ = list(_submodules.keys()) + ["__version__", "version_info", "list_available"]
