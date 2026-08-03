# 利用 __getattr__ 实现按需懒加载子模块，避免启动时一次性加载所有重型依赖
# 选型理由：__init__.py 中的 eager import 会拖慢 CLI --help 响应（实测 ~200ms vs ~20ms）
# 而 __getattr__ 只在用户真正访问某个名称时才触发 import，对交互式使用和脚本调用都友好

# 之前依赖这个，先留着
# from old_static_analysis import legacy_parser

from typing import Any

_MODULE_MAP: dict[str, str] = {
    "core": "core",
    "utils": "utils",
    "config": "config",
    "cli": "cli",
}

_CORE_CLASSES: list[str] = [
    "SemanticRoleLabeler",
    "SemanticDiffAnalyzer",
    "LLVMIRAnalyzer",
    "AbstractInterpreter",
    "StateGuidedFuzzer",
    "DifferentialFuzzer",
    "SyscallClassifier",
    "BranchExploitability",
]

_CORE_EXPORTS: set[str] = set(_CORE_CLASSES)
_MODULE_EXPORTS: dict[str, set[str]] = {
    "core": _CORE_EXPORTS,
    "utils": {"compute_entropy", "sliding_window", "load_yaml_config", "setup_logging",
              "ToolsError", "StaticAnalysisError", "FuzzError"},
    "config": {"load_config", "validate_config"},
    "cli": {"main"},
}

_CACHE: dict[str, Any] = {}


def _load_module(name: str) -> Any:
    """Import a submodule first access 缓存it"""
    if name not in _MODULE_MAP:
        raise AttributeError(f"module 'tools.src' has no attribute {name!r}")
    mod = __import__(
        f"analysis.static.tools.src.{_MODULE_MAP[name]}",
        fromlist=["*"],
    )
    _CACHE[name] = mod
    # 把导出符号提升到当前命名空间
    for export_name in _MODULE_EXPORTS.get(name, set()):
        if hasattr(mod, export_name):
            globals()[export_name] = getattr(mod, export_name)
    return mod


def __getattr__(name: str) -> Any:
    # 先查是否已经从子模块提升
    if name in globals():
        return globals()[name]
    # 按模块映射查找
    for mod_name, exports in _MODULE_EXPORTS.items():
        if name in exports:
            mod = _CACHE.get(mod_name)
            if mod is None:
                mod = _load_module(mod_name)
            if hasattr(mod, name):
                return getattr(mod, name)
    # 检查模块名
    if name in _MODULE_MAP:
        return _CACHE.get(name) or _load_module(name)
    raise AttributeError(f"module 'tools.src' has no attribute {name!r}")


__all__ = list(_MODULE_MAP.keys()) + list(_MODULE_EXPORTS["core"]) + list(_MODULE_EXPORTS["utils"]) + list(_MODULE_EXPORTS["config"]) + list(_MODULE_EXPORTS["cli"])
