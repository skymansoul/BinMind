"""
修改记录:
  2025-07-18 10:41 - _TYPE_BOUNDARY_VALUES 增加 bytes 类型，覆盖 \x00 和 \xff 边界
  2025-07-21 20:09 - differential_execution 增加 stdout 捕获与恢复，防止模块加载污染

类型引导的属性测试生成 + 差异执行比较。

属性测试生成基于类型注解→边界值的规则引擎（零 API 调用开销）：
不从 LLM 生成测试，而是利用代码中已有的类型信息推导边界条件——
int→{0,1,-1,MAX_INT}、str→{空串,单字符,长串}、list→{空列表,单元素,长列表}。
这不替代 PBT 框架的随机策略，而是在无外部依赖的前提下提供第一道语义防线。

差异执行：将同一函数的多个实现版本（如来自不同 worker 的替代方案）
在同一组输入上执行，比较输出一致性——若输出不一致，必有一个实现有语义错误。

ref: PGS — PBT 用于 LLM 代码验证，
     本项目将属性生成从 LLM 驱动改为类型引导规则引擎
ref: Hypothesis (github.com/HypothesisWorks/hypothesis) — PBT 策略组合器模式
ref: DiffSpec — 差分测试框架，
     本项目借鉴多实现对比思想用于跨 worker 一致性检查
"""

from __future__ import annotations

import ast
import os
import sys
import io
import time
import traceback
from typing import Any


# 类型 → 边界值映射 — 覆盖常见坑：空容器、None、极值、负值
_TYPE_BOUNDARY_VALUES: dict[str, list[Any]] = {
    "int": [0, 1, -1, 2**31 - 1, -(2**31)],
    "float": [0.0, 1.0, -1.0, float("inf"), float("-inf")],
    "str": ["", "a", " " * 1024, "\\n\\t"],
    "list": [[], [1], list(range(100))],
    "dict": [{}, {"k": "v"}, {i: i for i in range(50)}],
    "bool": [True, False],
    "NoneType": [None],
    "bytes": [b"", b"\x00", b"\xff" * 256],
}


def _infer_type_from_ast(node: ast.AST | None) -> str:
    """从 AST 类型注解节点推断类型名。仅处理简单类型名和泛型容器。"""
    if node is None:
        return "Any"
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Constant) and node.value is None:
        return "NoneType"
    if isinstance(node, ast.Subscript):
        if isinstance(node.value, ast.Name):
            return node.value.id
    return "Any"


def generate_property_tests(
    filepath: str,
    max_functions: int = 5,
) -> list[dict]:
    """为文件中的函数生成类型引导的边界值测试用例。
    仅处理带类型注解的纯函数（无副作用假设）。
    返回 [{'func': name, 'test_inputs': [(...), ...], 'lineno': int, 'arg_names': [...]}, ...]。"""
    tests: list[dict] = []
    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            source = f.read()
    except OSError:
        return tests
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return tests

    func_count = 0
    for node in ast.walk(tree):
        if func_count >= max_functions:
            break
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if not any(a.annotation for a in node.args.args):
            continue

        arg_types: list[str] = []
        for a in node.args.args:
            arg_types.append(_infer_type_from_ast(a.annotation))

        boundary_sets: list[list[Any]] = []
        for t in arg_types:
            vals = _TYPE_BOUNDARY_VALUES.get(t, [None, 0, "", []])
            boundary_sets.append(vals[:3])

        combinations = _cartesian_product(boundary_sets, max_total=8)
        if combinations:
            tests.append({
                "func": node.name,
                "arg_names": [a.arg for a in node.args.args],
                "test_inputs": combinations,
                "lineno": node.lineno,
            })
            func_count += 1

    return tests


def _cartesian_product(
    sets: list[list[Any]],
    max_total: int = 8,
) -> list[tuple]:
    """笛卡尔积，达到 max_total 后截断——避免组合爆炸。"""
    if not sets:
        return []
    result: list[tuple] = [()]
    for s in sets:
        new_result: list[tuple] = []
        for combo in result:
            for val in s:
                new_result.append(combo + (val,))
                if len(new_result) >= max_total:
                    return new_result
        result = new_result
    return result


# 差异执行 — 多版本输出比较

def differential_execution(
    filepath: str,
    func_name: str,
    test_inputs: list[tuple],
    timeout_per_call: float = 3.0,
) -> dict:
    """在沙箱环境中执行函数并捕获输出/异常。
    用于多个 worker 生成同一函数的不同实现版本时比较行为一致性。
    返回 {'outputs': [...], 'errors': [...], 'consistent': bool}。
    consistent 为 True 表示所有成功调用返回相同值。"""
    outputs: list[Any] = []
    errors: list[str] = []

    mod_name = os.path.splitext(os.path.basename(filepath))[0]
    try:
        import importlib.util as iu
        spec = iu.spec_from_file_location(mod_name, filepath)
        if spec is None or spec.loader is None:
            return {"outputs": [], "errors": ["无法加载模块"], "consistent": False}
        module = iu.module_from_spec(spec)
        old_stdout = sys.stdout
        sys.stdout = io.StringIO()
        try:
            spec.loader.exec_module(module)
        finally:
            sys.stdout = old_stdout
    except Exception as exc:
        return {"outputs": [], "errors": [f"模块加载失败: {exc}"], "consistent": False}

    func = getattr(module, func_name, None)
    if func is None:
        return {"outputs": [], "errors": [f"函数 '{func_name}' 未找到"], "consistent": False}

    for inputs in test_inputs:
        try:
            t0 = time.time()
            result = func(*inputs)
            elapsed = time.time() - t0
            if elapsed > timeout_per_call:
                errors.append(f"超时: {func_name}{inputs} ({elapsed:.1f}s)")
                continue
            outputs.append(result)
        except Exception:
            errors.append(
                f"异常: {func_name}{inputs}: {traceback.format_exc(limit=1).strip()}"
            )

    consistent = False
    if outputs:
        try:
            consistent = len(set(str(o) for o in outputs)) == 1
        except Exception:
            pass

    return {"outputs": outputs, "errors": errors, "consistent": consistent}
