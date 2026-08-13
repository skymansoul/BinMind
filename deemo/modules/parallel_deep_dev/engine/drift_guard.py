"""
创建: 2024-09-27
修改:
  2025-08-01 - 压缩节分隔符控制行数
实时架构漂移防护 — 并行 worker 输出落盘前拦截架构违规。

DriftBench/RoleFix 均为事后检测。本模块在 executor 写入文件前
用轻量 AST 约束引擎静态检查，两级处置：
  CRITICAL — 拒绝写入，返回违规详情用于 prompt 增强重生成
  WARNING  — 允许写入，将违规写入黑板供审查

区别于 ArchCodex 的 @arch 标签注入（不强制）和 eess 的 CI 门禁（事后），
"生成时拦截 + 违规感知 prompt 增强"的组合在文献中未见，
将防护点从 CI 后移到生成中，缩短反馈回路。
"""

from __future__ import annotations

import ast
import os
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable

# 非平凡约束委托给 engine/drift_constraints.py
from parallel_deep_dev.engine.drift_constraints import (
    check_circular_import_chain,
    check_side_effect_on_import,
    check_interface_leak,
)


class Severity(Enum):
    CRITICAL = "critical"   # 拒绝写入
    WARNING = "warning"      # 允许写入，记录违规


@dataclass
class ArchConstraint:
    """单条架构约束。check 是接受 AST 和文件路径、返回违规描述或 None 的可调用对象。"""
    name: str
    description: str
    severity: Severity
    check: Callable[[ast.Module, str], str | None]
    # check 返回 None 表示通过；返回非空字符串表示违规描述


@dataclass
class Violation:
    """单次违规记录。"""
    filepath: str
    constraint_name: str
    description: str
    severity: Severity
    lineno: int = 0


@dataclass
class DriftGuard:
    """实时架构漂移防护引擎。

    constraints: 架构约束列表，默认使用内置规则集
    max_violations_per_file: 单文件最多报告的违规数，防止告警淹没
    """

    constraints: list[ArchConstraint] = field(default_factory=list)
    max_violations_per_file: int = 5

    def __post_init__(self):
        if not self.constraints:
            self.constraints = _default_constraints()

    def check_file(self, filepath: str, source: str | None = None) -> list[Violation]:
        """检查单个文件是否违反架构约束。

        若提供 source，直接解析；否则从 filepath 读取。
        返回违规列表；空列表表示通过所有约束。"""
        if source is None:
            try:
                with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                    source = f.read()
            except OSError:
                return []

        try:
            tree = ast.parse(source)
        except SyntaxError:
            # 语法错误的文件跳过架构检查——语法验证在另一层处理
            return []

        violations: list[Violation] = []
        for c in self.constraints:
            if len(violations) >= self.max_violations_per_file:
                break
            result = c.check(tree, filepath)
            if result is not None:
                violations.append(Violation(
                    filepath=filepath,
                    constraint_name=c.name,
                    description=result,
                    severity=c.severity,
                ))
        return violations

    def check_and_decide(
        self,
        filepath: str,
        source: str | None = None,
    ) -> tuple[bool, list[Violation]]:
        """检查并给出处置建议。
        返回 (allow_write, violations)。
        allow_write=False 表示存在 CRITICAL 违规，应拒绝写入。"""
        violations = self.check_file(filepath, source)
        has_critical = any(v.severity == Severity.CRITICAL for v in violations)
        return (not has_critical, violations)

    def augment_prompt_context(self, violations: list[Violation]) -> str:
        """将违规信息转化为 prompt 增强上下文。
        worker 的下一轮 prompt 可附加此上下文以引导修复。"""
        if not violations:
            return ""
        critical = [v for v in violations if v.severity == Severity.CRITICAL]
        warnings = [v for v in violations if v.severity == Severity.WARNING]

        parts: list[str] = ["\n### 架构约束违规（必须修复）\n"]
        for v in critical:
            parts.append(
                f"- [CRITICAL] {v.constraint_name}: {v.description}\n"
                f"  文件: {os.path.basename(v.filepath)}"
            )
        if warnings:
            parts.append("\n### 架构约束警告（建议修复）\n")
            for v in warnings[:3]:
                parts.append(
                    f"- [WARNING] {v.constraint_name}: {v.description}"
                )
        return "\n".join(parts)


# 默认约束集 — 可通过 DriftGuard(constraints=[...]) 覆盖或扩展
def _default_constraints() -> list[ArchConstraint]:
    return [
        # 规则 1: 禁止循环导入检测（静态：同一文件不应导入自身）
        ArchConstraint(
            name="no_self_import",
            description="文件不得导入自身或自身的子模块形成直接循环",
            severity=Severity.CRITICAL,
            check=_check_self_import,
        ),
        # 规则 2: 禁止从 __pycache__ 或测试目录导入
        ArchConstraint(
            name="no_forbidden_import_source",
            description="不得从 __pycache__、.git 内部或测试固件目录导入",
            severity=Severity.CRITICAL,
            check=_check_forbidden_import_sources,
        ),
        # 规则 3: 检测超长导入链（深度 > 5 的 from ... import ... 嵌套）
        ArchConstraint(
            name="deep_import_chain",
            description="导入深度不应超过 5 层——过深的导入链暗示模块边界模糊",
            severity=Severity.WARNING,
            check=_check_deep_import_chain,
        ),
        # 规则 4: 私有模块跨包访问（导入以 _ 开头的其他包的模块）
        ArchConstraint(
            name="cross_package_private_import",
            description="不得从其他包导入私有模块（以 _ 开头的模块名）",
            severity=Severity.WARNING,
            check=_check_cross_package_private,
        ),
        # 规则 5: 项目级导入环检测（跨文件 BFS，非平凡——区别于 flake8 的单文件检查）
        ArchConstraint(
            name="no_circular_import_chain",
            description="检测跨文件的导入环（A→B→C→A），任意长度",
            severity=Severity.CRITICAL,
            check=lambda tree, fp: _check_circular_wrapper(tree, fp),
        ),
        # 规则 6: 导入副作用检测（模块顶层包含执行代码）
        ArchConstraint(
            name="no_side_effect_on_import",
            description="模块顶层不应包含函数调用等执行代码——import 时会立即触发",
            severity=Severity.WARNING,
            check=lambda tree, fp: _check_side_effect_wrapper(tree, fp),
        ),
        # 规则 7: 接口泄漏检测（导入未在 __all__ 中声明的符号）
        ArchConstraint(
            name="no_interface_leak",
            description="跨模块导入应仅使用目标 __all__ 中的公开符号",
            severity=Severity.WARNING,
            check=lambda tree, fp: _check_interface_leak_wrapper(tree, fp),
        ),
    ]


# 约束检查函数 — 每个返回 str|None
def _check_self_import(tree: ast.Module, filepath: str) -> str | None:
    """检测文件是否导入了自身或其直接父包。"""
    file_module = os.path.splitext(os.path.basename(filepath))[0]
    file_dir = os.path.basename(os.path.dirname(filepath))

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                target = alias.name.split(".")[0]
                if target == file_module or target == file_dir:
                    return (
                        f"自导入: 文件导入了自身或父包模块 '{alias.name}'"
                    )
        elif isinstance(node, ast.ImportFrom):
            if node.module is None:
                continue
            base = node.module.split(".")[0]
            if base == file_module and node.level == 1:
                return (
                    f"自导入: 使用相对导入导入了同包模块 '{node.module}' "
                    f"(可能构成循环)"
                )
    return None


def _check_forbidden_import_sources(tree: ast.Module, filepath: str) -> str | None:
    """检测导入源是否来自禁止目录。"""
    forbidden = {"__pycache__", ".git", ".claude", "test_fixtures", "conftest"}

    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            if node.module is None:
                continue
            parts = node.module.split(".")
            for p in parts:
                if p in forbidden:
                    return (
                        f"禁止导入源: 从 '{node.module}' 导入——"
                        f"'{p}' 是内部/测试目录，不应被业务代码依赖"
                    )
    return None


def _check_deep_import_chain(tree: ast.Module, filepath: str) -> str | None:
    """检测导入链深度。from a.b.c.d.e.f import X → 深度 6。"""
    max_depth = 0
    max_module = ""

    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            if node.module is None:
                continue
            parts = node.module.split(".")
            depth = len(parts) + (1 if node.level > 0 else 0)
            if depth > max_depth:
                max_depth = depth
                max_module = node.module

    if max_depth > 5:
        return (
            f"深层导入: '{max_module}' 的导入深度为 {max_depth}，"
            f"超过阈值 5——建议引入中间 __init__.py 重导出来扁平化接口"
        )
    return None


def _check_cross_package_private(tree: ast.Module, filepath: str) -> str | None:
    """检测是否从其他包导入了私有模块（以 _ 开头）。"""
    this_package = os.path.basename(os.path.dirname(filepath))

    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            if node.module is None:
                continue
            parts = node.module.split(".")
            # 检查路径中是否有以 _ 开头的段（但不包括本包内的私有模块）
            for part in parts:
                if part.startswith("_") and part != this_package:
                    # 排除标准库私有模块（如 _abc, _io）
                    if part not in ("_abc", "_io", "_collections_abc", "_functools",
                                     "_thread", "_signal", "_socket", "_ssl"):
                        return (
                            f"跨包私有导入: 从 '{node.module}' 导入了私有模块 "
                            f"'{part}'——私有模块的接口不稳定，不应被外部依赖"
                        )
    return None


# 与黑板和执行器的集成入口
# 约束包装器——将 drift_constraints 的函数适配到 ArchConstraint.check 签名
# 各包装器内部处理 filepath→source 的读取和 all_files 上下文传递

def _check_circular_wrapper(tree: ast.Module, filepath: str) -> str | None:
    # 收集项目文件列表用于跨文件环检测
    root = os.path.dirname(os.path.dirname(filepath)) if os.path.isdir(filepath) else os.path.dirname(filepath)
    py_files: list[str] = []
    if os.path.isdir(root):
        for dp, _, fns in os.walk(root):
            py_files.extend(os.path.join(dp, fn) for fn in fns if fn.endswith(".py"))
    return check_circular_import_chain(tree, filepath, py_files if py_files else None)


def _check_side_effect_wrapper(tree: ast.Module, filepath: str) -> str | None:
    return check_side_effect_on_import(tree, filepath)


def _check_interface_leak_wrapper(tree: ast.Module, filepath: str) -> str | None:
    return check_interface_leak(tree, filepath)


def guard_check_batch(
    guard: DriftGuard,
    filepaths: list[str],
    blackboard=None,
) -> dict[str, list[Violation]]:
    """批量检查文件并可选地将违规写入黑板。

    返回 {filepath: [Violation, ...]}，仅包含有违规的文件。
    worker 可通过黑板查询自己产出的文件是否触发架构违规。"""
    results: dict[str, list[Violation]] = {}

    for fpath in filepaths:
        if not fpath.endswith(".py"):
            continue
        allow, violations = guard.check_and_decide(fpath)
        if violations:
            results[fpath] = violations

    if blackboard is not None:
        critical_count = 0
        for fpath, violations in results.items():
            for v in violations:
                if v.severity == Severity.CRITICAL:
                    blackboard.deposit(
                        "error",
                        f"[架构违规] {os.path.basename(fpath)}: {v.description}",
                        source_module="drift_guard",
                        tags=["architecture", "drift", v.severity.value],
                    )
                    critical_count += 1
                elif v.severity == Severity.WARNING and critical_count < 5:
                    blackboard.deposit(
                        "warning",
                        f"[架构警告] {os.path.basename(fpath)}: {v.description}",
                        source_module="drift_guard",
                        tags=["architecture", "drift", "warning"],
                    )

    return results
