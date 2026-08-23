#!/usr/bin/env python3
"""
symbolic.src — 符号执行引擎包

通过显式 __all__ 导出实现惰性加载子模块。子模块在首次访问时导入，
最小化启动时间。

子模块映射:
executor → .src.executor (SymbolicExecutor, SymbolicState 等)
solver → .src.solver (ConstraintSolver, Z3ExpressionBuilder 等)
optimizer → .src.optimizer (PathOptimizer, ConstraintSimplifier 等)
explorer → .src.explorer (LLMGuidedExplorer, 适配器等)
constraint → .src.solver (约束管理别名)
utils → .src.utils (格式式转换、覆盖率、错误)
config → .src.config (YAML 配置加载器)

导出面设计为扁平结构，用户可:
from analysis.symbolic.src import SymbolicExecutor, ConstraintSolver

版本跟踪: __all__ 或惰性映射变更时递增
"""
# from collections import OrderedDict  # python3.7+不需要了
__version__ = "0.12.0"

# 惰性加载子模块映射
_submodules = {
    "executor": ".src.executor",
    "solver": ".src.solver",
    "optimizer": ".src.optimizer",
    "explorer": ".src.explorer",
    "constraint": ".src.solver",  # 别名
    "utils": ".src.utils",
    "config": ".src.config",
}

# 重导出映射: 名称 -> (子模块键, 可选导出名)
# 导出名与键不同时指定，否则为 None
_re_exports = {
    # executor
    "SymbolicExecutor": ("executor", None),
    "SymbolicState": ("executor", None),
    "SymbolicExplorationResult": ("executor", None),
    "ExecutionStrategy": ("executor", None),
    "IR_Op": ("executor", None),
    "IRInstruction": ("executor", None),
    "SymExpr": ("executor", None),
    # solver
    "ConstraintSolver": ("solver", None),
    "Z3ExpressionBuilder": ("solver", None),
    "SymbolicError": ("solver", None),
    "SolverTimeout": ("solver", None),
    "SolverNotFound": ("solver", None),
    "has_z3": ("solver", None),
    # optimizer
    "PathOptimizer": ("optimizer", None),
    "ConstraintSimplifier": ("optimizer", None),
    # explorer
    "LLMGuidedExplorer": ("explorer", None),
    "PathRankerAdapter": ("explorer", None),
    "StrategySwitcherAdapter": ("explorer", None),
    # utils
    "smtlib_to_z3": ("utils", None),
    "z3_to_smtlib": ("utils", None),
    "parse_constraints": ("utils", None),
    "serialize_state": ("utils", None),
    "deserialize_state": ("utils", None),
    "compute_path_coverage": ("utils", None),
    "compute_branch_coverage": ("utils", None),
    "PathExplosionError": ("utils", None),
    "UnsupportedInstructionError": ("utils", None),
    "StateSerializationError": ("utils", None),
    # config
    "Config": ("config", None),
    "load_config": ("config", None),
    "get_default_config": ("config", None),
}


def __getattr__(name: str):
    """
    惰性加载子模块或重导出，仅在首次属性访问时触发导入

    策略: 若 name 是子模块键（如 'executor'、'solver'）则导入对应模块。
    若 name 是重导出符号（如 'SymbolicExecutor'）则导入所属子模块并获取属性。

    时间复杂度: 缓存命中 O(1)；首次访问 O(module_import)
    空间复杂度: 每个属性 O(1) 额外开销

    边界情况: 循环导入通过 __getattr__ 机制避免，子模块不在模块加载时导入
    """
    import importlib
    import time

    # 子模块访问: from symbolic.src import executor
    if name in _submodules:
        mod = importlib.import_module(_submodules[name], package=__package__)
        return mod

    # 重导出访问: from symbolic.src import SymbolicExecutor
    if name in _re_exports:
        sub_key, export_name = _re_exports[name]
        mod_path = _submodules.get(sub_key)
        if mod_path is None:
            raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
        mod = importlib.import_module(mod_path, package=__package__)
        attr_name = export_name if export_name else name
        if hasattr(mod, attr_name):
            return getattr(mod, attr_name)
        raise AttributeError(
            f"module {mod_path!r} has no attribute {attr_name!r}"
        )

    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__():
    """返回公共名称列表供 tab 补全。O(1)"""
    base = list(__all__) if "__all__" in globals() else []
    return sorted(set(base + list(_submodules.keys()) + list(_re_exports.keys())))


# 显式 __all__ 供 star import 使用
__all__ = sorted(_re_exports.keys())
