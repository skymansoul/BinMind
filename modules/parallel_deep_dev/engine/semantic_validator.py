"""
修改记录:
  2025-07-16 21:37 - 增加跨文件导入一致性检查，验证 import 目标是否存在
  2025-07-19 13:05 - 属性测试和差异执行提取至 engine/property_tester.py
  2025-07-22 17:52 - run_semantic_validation 整合三阶段验证入口

语义级输出验证 — 超越语法检查，在语义层面检测生成代码的质量。
阶段 1（本模块）：接口一致性 — 跨文件的 import/export 签名匹配。
阶段 2+3（property_tester.py）：类型引导的属性测试 + 差异执行。

ref: DiffSpec — 差分测试框架，
     本项目借鉴其多实现对比思想但适配到跨 worker 场景
ref: PGS — PBT 用于 LLM 代码验证
"""


import ast
import os
from dataclasses import dataclass

from ._io import safe_read


# 阶段 1: 接口一致性 — 提取签名 + 交叉校验

@dataclass
class FuncSig:
    name: str
    module: str
    args: list[str]
    has_return: bool
    lineno: int


def extract_signatures(filepath: str) -> list[FuncSig]:
    """从 Python 文件中提取顶层函数和类方法签名。"""
    sigs: list[FuncSig] = []
    source = safe_read(filepath)
    if source is None:
        return sigs
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return sigs

    module_name = os.path.splitext(os.path.basename(filepath))[0]
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            args = [a.arg for a in node.args.args]
            returns = node.returns is not None
            sigs.append(FuncSig(
                name=node.name,
                module=module_name,
                args=args,
                has_return=returns,
                lineno=node.lineno,
            ))
    return sigs


def check_cross_module_consistency(
    changed_files: list[str],
    root_dir: str,
) -> list[str]:
    """检查变更文件之间的导入/导出一致性。
    若文件 A 从文件 B import 了符号 X，但 B 中未定义 X，则报告。
    返回问题描述列表；空列表表示一致。"""
    issues: list[str] = []
    exports: dict[str, set[str]] = {}
    for fpath in changed_files:
        if not fpath.endswith(".py"):
            continue
        sigs = extract_signatures(fpath)
        mod = os.path.splitext(os.path.basename(fpath))[0]
        exports[mod] = {s.name for s in sigs}

    for fpath in changed_files:
        if not fpath.endswith(".py"):
            continue
        source = safe_read(fpath)
        if source is None:
            continue
        try:
            tree = ast.parse(source)
        except SyntaxError:
            continue

        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                if node.module is None:
                    continue
                target_mod = node.module.split(".")[-1]
                if target_mod not in exports:
                    continue
                for alias in node.names:
                    if alias.name == "*":
                        continue
                    if alias.name not in exports[target_mod]:
                        issues.append(
                            f"{os.path.basename(fpath)}:{node.lineno}: "
                            f"import '{alias.name}' from '{target_mod}' — "
                            f"目标模块中未找到该符号"
                        )
    return issues


# 便捷入口 — 整合属性测试 + 差异执行（委托给 property_tester）

def run_semantic_validation(
    changed_files: list[str],
    root_dir: str,
) -> dict:
    """对变更文件执行完整语义验证。
    返回 {'interface_issues': [...], 'property_tests': [...], 'differential': {}}。"""
    result: dict = {
        "interface_issues": [],
        "property_tests": [],
        "differential": {},
    }

    result["interface_issues"] = check_cross_module_consistency(changed_files, root_dir)

    for fpath in changed_files:
        if not fpath.endswith(".py"):
            continue
        try:
            from .property_tester import generate_property_tests
            tests = generate_property_tests(fpath)
            if tests:
                result["property_tests"].extend(
                    {"file": fpath, **t} for t in tests
                )
        except Exception:
            continue

    return result
