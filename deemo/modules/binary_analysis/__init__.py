# 扁平命名空间：analysis/static/binary_analysis 子模块的再导出。
# 测试与调用方以 modules.binary_analysis.<name> 形式引用新布局下的模块，
# 此处惰性转发，避免包导入时触发重型依赖加载。

import importlib as _importlib

_REEXPORT = (
    "vuln_management",
    "exploit_primitives",
    "memory_heap",
    "kernel_driver",
    "ml_features",
    "symbolic_analysis",
)


def __getattr__(name):
    if name in _REEXPORT:
        mod = _importlib.import_module(
            f"modules.analysis.static.binary_analysis.{name}")
        globals()[name] = mod
        return mod
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
