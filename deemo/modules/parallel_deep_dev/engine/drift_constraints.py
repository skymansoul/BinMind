"""
创建: 2025-08-05

架构漂移约束扩展 — 超越标准 lint 的非平凡约束检查。

drift_guard.py 的 4 条默认规则属标准 lint 级别（no_self_import 等）。
本模块补充 3 条在文献中未见、专门针对并行代码生成场景的约束：

  no_circular_import_chain: 构建项目级导入图，检测任意长度的导入环。
    与 flake8/pylint 的单文件 self-import 检查不同，本约束跨文件追踪
    完整的 import 链，检测 A→B→C→A 等间接循环。

  no_side_effect_on_import: 检测在模块顶层执行非声明代码的文件。
    并行生成场景中，worker B import worker A 生成的模块时，
    A 的模块顶层代码会立即执行——若包含副作用（网络连接、文件写入），
    会导致不可预期的行为。本约束通过 AST 分析区分"声明"和"执行"。

  no_interface_leak: 检测跨模块导入是否仅使用目标模块的公开接口。
    若目标模块定义了 __all__，则只允许导入 __all__ 中的符号。
    这是 Python 社区约定但无工具强制执行——本约束填补此空白。
"""

from __future__ import annotations

import ast
import os
from collections import defaultdict


def check_circular_import_chain(
    tree: ast.Module, filepath: str, all_files: list[str] | None = None,
) -> str | None:
    """检测项目级导入环。

    构建当前文件→被导入模块→…的图，BFS 检测是否回到起点。
    若 all_files 为 None，降级为单文件自导入检测。
    返回违规描述或 None。"""
    if all_files is None:
        # 降级为 self-import 检测
        return _check_simple_self_import(tree, filepath)

    current_base = os.path.splitext(os.path.basename(filepath))[0]
    # 构建文件名→模块的映射
    file_to_mod: dict[str, str] = {}
    for f in all_files:
        if f.endswith(".py"):
            file_to_mod[os.path.splitext(os.path.basename(f))[0]] = f

    # 从当前文件提取直接导入
    imports: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imports.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                imports.add(node.module.split(".")[0])

    # BFS 检测环
    visited: set[str] = {current_base}
    queue: list[tuple[str, list[str]]] = [(m, [current_base]) for m in imports]
    while queue:
        mod, path = queue.pop(0)
        if mod == current_base:
            return (
                f"导入环: {' → '.join(path)} → {mod} "
                f"(跨 {len(path)} 个文件)"
            )
        if mod in visited or mod not in file_to_mod:
            continue
        visited.add(mod)
        # 读取被导入文件的导入
        try:
            with open(file_to_mod[mod], "r", encoding="utf-8", errors="replace") as f:
                sub_source = f.read()
        except OSError:
            continue
        try:
            sub_tree = ast.parse(sub_source)
        except SyntaxError:
            continue
        for node in ast.walk(sub_tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    next_mod = alias.name.split(".")[0]
                    if next_mod not in visited:
                        queue.append((next_mod, path + [mod]))
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    next_mod = node.module.split(".")[0]
                    if next_mod not in visited:
                        queue.append((next_mod, path + [mod]))

    return None


def check_side_effect_on_import(
    tree: ast.Module, filepath: str,
) -> str | None:
    """检测模块顶层是否有非声明式的执行代码。

    区分规则：模块顶层节点分为"声明"（函数/类定义、import、赋值常量）
    和"执行"（函数调用、写文件、网络操作、非赋值的表达式）。
    若发现执行节点，模块被 import 时会触发副作用。"""
    side_effect_nodes: list[str] = []
    for node in ast.iter_child_nodes(tree):
        if isinstance(node, ast.Expr):
            if isinstance(node.value, ast.Call):
                func_name = _get_call_name(node.value)
                side_effect_nodes.append(f"L{node.lineno}:{func_name}()")
        elif isinstance(node, ast.Assign):
            # 赋值右侧有函数调用 → 可能在初始化
            if isinstance(node.value, ast.Call):
                func_name = _get_call_name(node.value)
                if func_name and func_name not in (
                    "int", "str", "float", "list", "dict", "set", "tuple",
                    "bool", "len", "range", "enumerate", "zip",
                ):
                    side_effect_nodes.append(f"L{node.lineno}:{func_name}()")
        elif isinstance(node, (ast.If, ast.For, ast.While, ast.Try, ast.With)):
            side_effect_nodes.append(f"L{node.lineno}:{type(node).__name__}")

    if side_effect_nodes:
        return (
            f"导入副作用: {os.path.basename(filepath)} 在模块顶层包含执行代码"
            f" ({', '.join(side_effect_nodes[:3])})——"
            f"import 此模块将触发这些代码执行"
        )
    return None


def check_interface_leak(
    tree: ast.Module, filepath: str,
) -> str | None:
    """检测是否导入了目标模块未公开的符号。

    若目标模块定义了 __all__，则只应导入 __all__ 中的符号。
    这强制执行 Python 社区的封装约定。"""
    leaks: list[str] = []

    for node in ast.walk(tree):
        if not isinstance(node, ast.ImportFrom):
            continue
        if node.module is None:
            continue

        # 尝试找到目标模块并检查其 __all__
        target_path = _resolve_module_path(filepath, node.module)
        if target_path is None:
            continue

        public_symbols = _get_all_symbols(target_path)
        if public_symbols is None:
            continue  # 目标模块无 __all__，不强制执行

        for alias in node.names:
            if alias.name == "*":
                leaks.append(f"L{node.lineno}:import * (禁止在定义了__all__的模块上使用)")
            elif alias.name not in public_symbols:
                leaks.append(
                    f"L{node.lineno}:{alias.name} "
                    f"(目标模块 {node.module} 的 __all__ 中无此符号)"
                )

    if leaks:
        return f"接口泄漏: {'; '.join(leaks[:3])}"
    return None


# ---------------------------------------------------------------------------
# 辅助
# ---------------------------------------------------------------------------

def _check_simple_self_import(tree: ast.Module, filepath: str) -> str | None:
    file_module = os.path.splitext(os.path.basename(filepath))[0]
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] == file_module:
                    return f"自导入: 文件导入了自身模块 '{alias.name}'"
    return None


def _get_call_name(node: ast.expr) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return "?"


def _resolve_module_path(from_file: str, module_name: str) -> str | None:
    """根据导入语句解析目标文件的绝对路径。"""
    base_dir = os.path.dirname(from_file)
    parts = module_name.split(".")
    candidate = os.path.join(base_dir, *parts) + ".py"
    if os.path.isfile(candidate):
        return candidate
    # 尝试同级目录下的 __init__.py
    candidate = os.path.join(base_dir, *parts, "__init__.py")
    if os.path.isfile(candidate):
        return candidate
    return None


def _get_all_symbols(filepath: str) -> set[str] | None:
    """提取文件的 __all__ 声明中的符号列表。"""
    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            source = f.read()
    except OSError:
        return None
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return None
    for node in ast.iter_child_nodes(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "__all__":
                    if isinstance(node.value, (ast.List, ast.Tuple)):
                        symbols: set[str] = set()
                        for elt in node.value.elts:
                            if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                                symbols.add(elt.value)
                        return symbols
    return None
