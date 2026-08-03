#!/usr/bin/env python3
"""
symbolic.src — 符号执行 engine package

Lazy-loading submodules explicit __all__ exports. Submodules
imported first access, keeping startup time minimal

Submodule map:
executor ->.src.executor (SymbolicExecutor, SymbolicState, etc.)
solver ->.src.solver (ConstraintSolver, Z3ExpressionBuilder, etc.)
优化器 ->.src.优化器 (Path优化器, ConstraintSimplifier, etc.)
explorer ->.src.explorer (LLMGuidedExplorer, 适配器s)
constraint ->.src.solver (alias for constraint management)
utils ->.src.utils (格式化 conversion, 覆盖率, errors)
配置 ->.src.配置 (YAML 配置 加载器)

Export surface designed flat — users:
analysis.symbolic.src import SymbolicExecutor, ConstraintSolver

Version tracking: bumped whenever __all__ or lazy map changes
"""
# from collections import OrderedDict  # python3.7+不需要了
__version__ = "0.12.0"

# Submodule map for lazy loading
_submodules = {
    "executor": ".src.executor",
    "solver": ".src.solver",
    "optimizer": ".src.optimizer",
    "explorer": ".src.explorer",
    "constraint": ".src.solver",  # Alias
    "utils": ".src.utils",
    "config": ".src.config",
}

# Re-export map: name -> (submodule_key, optional_export_name)
# export_name differs name, specify; otherwise None
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
    # 优化器
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
    # 配置
    "Config": ("config", None),
    "load_config": ("config", None),
    "get_default_config": ("config", None),
}


def __getattr__(name: str):
    """
    Lazy-加载 submodule or re-export first attribute access
    
    Strategy: 'name' a submodule key (like 'executor', 'solver')
    import corresponding module. 'name' a re-export symbol
    (like 'SymbolicExecutor'), import owning submodule grab
    attribute
    
    Time: O(1) for 缓存hits; O(module_import) for first access
    Space: O(1) overhead per attribute
    
    Edge case: Circular imports avoided because submodules
    import via __getattr__, never module 加载 time
    """
    import importlib
    import time

    # Submodule access: ` symbolic.src import executor`
    if name in _submodules:
        mod = importlib.import_module(_submodules[name], package=__package__)
        return mod

    # Re-export access: ` symbolic.src import SymbolicExecutor`
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
    """返回 list public names for tab completion. O(1)"""
    base = list(__all__) if "__all__" in globals() else []
    return sorted(set(base + list(_submodules.keys()) + list(_re_exports.keys())))


# Explicit __all__ for star imports
__all__ = sorted(_re_exports.keys())
