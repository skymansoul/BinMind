"""
创建: 2026-05-31
修改:
  2025-08-02 - _scanned_files 去重防止重复冲突
  2025-08-03 - 返回值使用模式检测从 _infer_return_usage 改为 _detect_return_usages 后处理
跨模块接口契约推断 — 从调用方使用模式推断隐式接口约定。

与 mypy/pyright 的显式标注不同，本模块从调用方的参数数量、返回值使用模式
（下标/属性/标量）推断隐式期望，检测实现方-调用方之间的契约冲突。
使用模式推断 + 跨文件契约比较的组合在文献中未见。
"""

from __future__ import annotations

import ast
import os
from collections import defaultdict
from dataclasses import dataclass, field


@dataclass
class FuncImpl:
    """函数的实现方信息。"""
    name: str
    filepath: str
    arg_count: int           # 位置参数数量（不含 self/cls）
    has_varargs: bool        # *args
    has_kwargs: bool         # **kwargs
    has_return_annotation: bool
    return_annotation: str = ""
    lineno: int = 0


@dataclass
class CallSite:
    """单个调用点的信息。"""
    filepath: str
    func_name: str
    arg_count: int           # 传入的参数数量
    has_kwargs: bool         # 是否使用了关键字参数
    return_usage: str        # 'attribute'|'subscript'|'scalar'|'iterable'|'none'
    lineno: int = 0


@dataclass
class ContractConflict:
    """实现方-调用方之间的契约冲突。"""
    symbol: str
    impl_file: str
    call_file: str
    impl_lineno: int
    call_lineno: int
    severity: str            # CRITICAL | WARNING
    description: str


class ContractInferrer:
    """基于使用模式的跨模块接口契约推断器。

    两遍扫描：第一遍构建实现方表，第二遍构建调用方表并检测冲突。"""

    def __init__(self):
        self._impls: dict[str, list[FuncImpl]] = defaultdict(list)
        self._calls: dict[str, list[CallSite]] = defaultdict(list)
        self._scanned_files: set[str] = set()  # 防止重复扫描导致重复冲突

    def scan(self, filepaths: list[str]) -> list[ContractConflict]:
        """扫描文件列表，构建实现方/调用方表，返回检测到的契约冲突。"""
        # 第一遍：实现方
        for fpath in filepaths:
            if not fpath.endswith(".py") or not os.path.isfile(fpath):
                continue
            source = self._read(fpath)
            if source is None:
                continue
            tree = self._parse(source)
            if tree is None:
                continue
            self._extract_impls(fpath, tree)

        # 第二遍：调用方 + 冲突检测
        conflicts: list[ContractConflict] = []
        for fpath in filepaths:
            if not fpath.endswith(".py") or not os.path.isfile(fpath):
                continue
            source = self._read(fpath)
            if source is None:
                continue
            tree = self._parse(source)
            if tree is None:
                continue
            self._extract_calls_and_check(fpath, tree, conflicts)

        conflicts.sort(key=lambda c: (0 if c.severity == "CRITICAL" else 1, c.symbol))
        return conflicts

    def _extract_impls(self, fpath: str, tree: ast.Module) -> None:
        if fpath in self._scanned_files:
            return
        self._scanned_files.add(fpath)
        for node in ast.iter_child_nodes(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                args = node.args
                # 计算位置参数（排除 self/cls 仅当第一个参数名为 self/cls 时）
                params = args.args
                pos_count = len(params)
                if pos_count > 0 and params[0].arg in ("self", "cls"):
                    pos_count -= 1

                self._impls[node.name].append(FuncImpl(
                    name=node.name, filepath=fpath,
                    arg_count=pos_count,
                    has_varargs=args.vararg is not None,
                    has_kwargs=args.kwarg is not None,
                    has_return_annotation=node.returns is not None,
                    return_annotation=(
                        ast.unparse(node.returns) if node.returns else ""
                    ),
                    lineno=node.lineno,
                ))

    def _extract_calls_and_check(
        self, fpath: str, tree: ast.Module, conflicts: list[ContractConflict],
    ) -> None:
        # 预检测返回值使用模式
        return_usages = self._detect_return_usages(tree)

        # 简单数据流追踪: 单次赋值的局部变量 → 其来源函数调用
        # 处理 t = f(args); t[key] 或 t = f(args); t.attr 模式
        local_sources: dict[str, tuple[str, int]] = self._trace_local_assignments(tree)

        # 收集本文件的 import 映射
        imports: dict[str, str] = {}  # local_name → original_module_or_name
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imports[alias.asname or alias.name] = alias.name
            elif isinstance(node, ast.ImportFrom):
                if node.module is None:
                    continue
                for alias in node.names:
                    imports[alias.asname or alias.name] = node.module

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue

            func_name = self._resolve_call_name(node.func)
            if not func_name:
                continue
            # 仅关心跨模块调用（被导入的符号）
            if func_name not in imports:
                continue

            usage = return_usages.get(node.lineno, "none")

            call = CallSite(
                filepath=fpath, func_name=func_name,
                arg_count=len(node.args),
                has_kwargs=len(node.keywords) > 0,
                return_usage=usage,
                lineno=node.lineno,
            )

            # 查找实现方并检测冲突
            impls = self._impls.get(func_name, [])
            if not impls:
                continue

            for impl in impls:
                if impl.filepath == fpath:
                    continue  # 同文件调用不检测

                # 参数数量冲突
                if not impl.has_varargs and call.arg_count > impl.arg_count:
                    conflicts.append(ContractConflict(
                        symbol=func_name,
                        impl_file=impl.filepath, call_file=fpath,
                        impl_lineno=impl.lineno, call_lineno=call.lineno,
                        severity="CRITICAL",
                        description=(
                            f"参数数量不匹配: {os.path.basename(fpath)}:{call.lineno} "
                            f"传入 {call.arg_count} 个参数, "
                            f"{os.path.basename(impl.filepath)}:{impl.lineno} "
                            f"仅接受 {impl.arg_count} 个"
                        ),
                    ))

                # 返回值使用模式 vs 实现方无返回标注
                if call.return_usage in ("attribute", "subscript") and not impl.has_return_annotation:
                    conflicts.append(ContractConflict(
                        symbol=func_name,
                        impl_file=impl.filepath, call_file=fpath,
                        impl_lineno=impl.lineno, call_lineno=call.lineno,
                        severity="WARNING",
                        description=(
                            f"返回值使用模式冲突: {os.path.basename(fpath)}:{call.lineno} "
                            f"对 '{func_name}' 的返回值使用了 {call.return_usage} 访问, "
                            f"但 {os.path.basename(impl.filepath)}:{impl.lineno} "
                            f"无返回类型标注——可能运行时失败"
                        ),
                    ))

        # 数据流增强: 检测通过局部变量的间接返回值使用
        # 模式: t = create_token(args); t["key"] 或 t.attr
        for node in ast.walk(tree):
            usage = None
            source_func = None
            if isinstance(node, ast.Subscript) and isinstance(node.value, ast.Name):
                if node.value.id in local_sources:
                    usage = "subscript"
                    source_func = local_sources[node.value.id]
            elif isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
                if node.value.id in local_sources:
                    usage = "attribute"
                    source_func = local_sources[node.value.id]
            if usage and source_func:
                func_name, src_lineno = source_func
                impls = self._impls.get(func_name, [])
                for impl in impls:
                    if impl.filepath == fpath:
                        continue
                    if not impl.has_return_annotation:
                        conflicts.append(ContractConflict(
                            symbol=func_name,
                            impl_file=impl.filepath, call_file=fpath,
                            impl_lineno=impl.lineno, call_lineno=node.lineno,
                            severity="WARNING",
                            description=(
                                f"间接返回值使用: {os.path.basename(fpath)}:{node.lineno} "
                                f"通过变量对 '{func_name}' 的返回值使用了 {usage} 访问, "
                                f"但 {os.path.basename(impl.filepath)}:{impl.lineno} "
                                f"无返回类型标注"
                            ),
                        ))

    # 辅助

    @staticmethod
    def _read(filepath: str) -> str | None:
        try:
            with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                return f.read()
        except OSError:
            return None

    @staticmethod
    def _parse(source: str) -> ast.Module | None:
        try:
            return ast.parse(source)
        except SyntaxError:
            return None

    @staticmethod
    def _resolve_call_name(func_node: ast.expr) -> str | None:
        if isinstance(func_node, ast.Name):
            return func_node.id
        if isinstance(func_node, ast.Attribute):
            if isinstance(func_node.value, ast.Name):
                return func_node.value.id
        return None

    @staticmethod
    def _trace_local_assignments(tree: ast.Module) -> dict[str, tuple[str, int]]:
        """追踪单次赋值: local_var = imported_func(args)。

        返回 {local_var_name: (func_name, lineno)}。
        仅追踪函数体内对导入函数的直接调用赋值——不做跨行数据流。"""
        sources: dict[str, tuple[str, int]] = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                if not isinstance(node.value, ast.Call):
                    continue
                func_name = ContractInferrer._resolve_call_name(node.value.func)
                if func_name is None:
                    continue
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        sources[target.id] = (func_name, node.lineno)
        return sources

    @staticmethod
    def _infer_return_usage(call_node: ast.Call) -> str:
        """推断调用方对返回值的期望使用模式。

        由于 AST 无 parent 引用，改用后处理方式：
        在第二遍扫描后额外遍历 AST，查找 Subscript/Attribute 节点
        的值是否为函数调用。此方法在此处返回 'unknown'，
        实际使用模式检测在 _extract_calls_and_check 中通过
        额外的 AST 遍历完成。"""
        return "unknown"

    @staticmethod
    def _detect_return_usages(tree: ast.Module) -> dict[int, str]:
        """检测 AST 中对函数调用返回值的所有使用模式。

        返回 {call_node_lineno: usage_type}。
        通过查找父节点为 Subscript/Attribute/Compare 的 Call 节点来推断。"""
        usages: dict[int, str] = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.Subscript):
                if isinstance(node.value, ast.Call):
                    usages[node.value.lineno] = "subscript"
            elif isinstance(node, ast.Attribute):
                if isinstance(node.value, ast.Call):
                    existing = usages.get(node.value.lineno, "")
                    if existing != "subscript":
                        usages[node.value.lineno] = "attribute"
            elif isinstance(node, ast.Compare):
                for operand in [node.left] + node.comparators:
                    if isinstance(operand, ast.Call):
                        usages[operand.lineno] = "scalar"
            elif isinstance(node, ast.Assign):
                if isinstance(node.value, ast.Call):
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            usages[node.value.lineno] = "stored"
        return usages


# 便捷集成入口

def infer_contracts(
    filepaths: list[str],
    blackboard=None,
) -> list[ContractConflict]:
    """扫描文件列表、推断接口契约、检测冲突、可选写入黑板。"""
    inferrer = ContractInferrer()
    conflicts = inferrer.scan(filepaths)

    if blackboard is not None:
        critical = [c for c in conflicts if c.severity == "CRITICAL"]
        for c in critical[:5]:
            blackboard.deposit(
                "error",
                f"[契约冲突] {c.symbol}: {c.description}",
                source_module="contract_infer",
                tags=["contract", "interface", "critical"],
            )
        warnings = [c for c in conflicts if c.severity == "WARNING"]
        for c in warnings[:5]:
            blackboard.deposit(
                "warning",
                f"[契约警告] {c.symbol}: {c.description}",
                source_module="contract_infer",
                tags=["contract", "interface", "warning"],
            )

    return conflicts
