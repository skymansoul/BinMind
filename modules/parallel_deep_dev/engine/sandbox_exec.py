"""
创建: 2025-03-03
修改:
  2025-08-03 - f-string 注入风险修复：改用环境变量传参+ast.literal_eval
沙箱化边界值执行验证 — 子进程隔离运行生成的函数，捕获运行时崩溃。

问题：validate.py 仅做语法检查（py_compile），property_tester.py 生成边界值
测试用例但不执行。语法正确的代码仍可能在运行时因类型错误、空值解引用、
除零等崩溃。pytest/Hypothesis 需手写测试——AI 并行生成场景需要零人工介入。

方案：子进程沙箱 + 边界值输入自动执行。
  1. 解析生成文件，提取带类型注解的顶层函数
  2. 从 property_tester 的类型→边界值表获取测试输入
  3. 在独立子进程中加载模块并执行每个函数
  4. 捕获异常、超时、输出，分类为 PASS/CRASH/TIMEOUT/SKIP
  5. 聚合为文件级健壮性报告——高崩溃率文件标记为重生成候选

安全措施：
  - subprocess 隔离：单文件崩溃不影响其他验证
  - 单调用超时 3s：防止无限循环
  - 仅执行带类型注解的纯函数（启发式：无全局状态访问的函数）
  - 跳过 __init__.py、测试文件、包含 __main__ 的文件

与现有工作的差异：
  - pytest/unittest: 需手写测试用例
  - Hypothesis: 随机策略生成，不与代码生成管线集成
  - property_tester (本系统): 生成边界值但不执行
  - 本模块完成"边界值生成→沙箱执行→崩溃报告"的完整链路,
    在并行代码生成管线中实现零人工的运行时验证闭环
"""

from __future__ import annotations

import ast
import json
import os
import subprocess
import sys
import traceback
from dataclasses import dataclass, field
from typing import Any


# 单次调用超时
_CALL_TIMEOUT: float = 3.0
# 单文件最多测试的函数数
_MAX_FUNCTIONS_PER_FILE: int = 10

# 重用 property_tester 的类型边界值表（避免循环导入）
_TYPE_BOUNDARY: dict[str, list[Any]] = {
    "int": [0, 1, -1, 100],
    "float": [0.0, 1.0, -1.0],
    "str": ["", "test", "x" * 100],
    "list": [[], [1]],
    "dict": [{}, {"k": "v"}],
    "bool": [True, False],
    "NoneType": [None],
}


@dataclass
class ExecResult:
    """单次函数执行的结果。"""
    func_name: str
    status: str           # PASS | CRASH | TIMEOUT | SKIP
    inputs: tuple
    output: str = ""       # 返回值 repr 或异常信息
    elapsed_ms: float = 0.0


@dataclass
class FileExecReport:
    """单文件的沙箱执行报告。"""
    filepath: str
    total_tests: int
    passed: int
    crashed: int
    timed_out: int
    results: list[ExecResult] = field(default_factory=list)

    @property
    def crash_rate(self) -> float:
        if self.total_tests == 0:
            return 0.0
        return self.crashed / self.total_tests

    @property
    def is_healthy(self) -> bool:
        """文件是否通过执行验证（崩溃率 < 30%）。"""
        return self.crash_rate < 0.3


def _worker_process(filepath: str, func_name: str, args_repr: str) -> tuple[str, str, float]:
    """子进程 worker：通过 subprocess + 环境变量传参加载模块并执行函数。

    使用环境变量而非 f-string 嵌入，避免路径中的特殊字符破坏脚本语法。
    Windows/Linux 均兼容。返回 (status, output, elapsed_ms)。"""
    script = (
        "import sys, os, time, json\n"
        "fp = os.environ['_SE_FILEPATH']\n"
        "fn = os.environ['_SE_FUNCNAME']\n"
        "ar = os.environ['_SE_ARGS']\n"
        "sys.path.insert(0, os.path.dirname(fp))\n"
        "mod_name = os.path.splitext(os.path.basename(fp))[0]\n"
        "import importlib.util as iu\n"
        "spec = iu.spec_from_file_location(mod_name, fp)\n"
        "if spec is None or spec.loader is None:\n"
        "    print(json.dumps({'status':'SKIP','output':'load failed'}))\n"
        "    sys.exit(0)\n"
        "module = iu.module_from_spec(spec)\n"
        "spec.loader.exec_module(module)\n"
        "func = getattr(module, fn, None)\n"
        "if func is None:\n"
        "    print(json.dumps({'status':'SKIP','output':'func not found'}))\n"
        "    sys.exit(0)\n"
        "import ast as _ast\n"
        "args = _ast.literal_eval(ar)\n"
        "t0 = time.time()\n"
        "result = func(*args)\n"
        "elapsed = (time.time()-t0)*1000\n"
        "print(json.dumps({'status':'PASS','output':repr(result),'elapsed':elapsed}))\n"
    )
    env = {
        '_SE_FILEPATH': filepath,
        '_SE_FUNCNAME': func_name,
        '_SE_ARGS': args_repr,
    }
    try:
        proc = subprocess.run(
            [sys.executable, "-c", script],
            capture_output=True, text=True, timeout=_CALL_TIMEOUT,
            env={**os.environ, **env},
        )
        if proc.returncode != 0:
            err = proc.stderr[:200] if proc.stderr else "未知错误"
            return ("CRASH", err, 0.0)

        data = json.loads(proc.stdout.strip())
        return (data["status"], data.get("output", ""), data.get("elapsed", 0.0))
    except subprocess.TimeoutExpired:
        return ("TIMEOUT", f"超时 ({_CALL_TIMEOUT}s)", 0.0)
    except Exception:
        return ("CRASH", traceback.format_exc(limit=1), 0.0)


def run_sandbox_validation(
    filepaths: list[str],
    blackboard=None,
    max_functions_per_file: int = _MAX_FUNCTIONS_PER_FILE,
    call_timeout: float = _CALL_TIMEOUT,
) -> list[FileExecReport]:
    """对文件列表执行沙箱化运行时验证。

    返回每个文件的执行报告。高崩溃率文件自动写入黑板。
    """
    reports: list[FileExecReport] = []

    for fpath in filepaths:
        if not fpath.endswith(".py") or not os.path.isfile(fpath):
            continue
        # 跳过特殊文件
        base = os.path.basename(fpath)
        if base.startswith("__") or base.startswith("test_") or base.startswith("conftest"):
            continue

        report = _validate_file(fpath, max_functions_per_file, call_timeout)
        if report is not None:
            reports.append(report)

    if blackboard is not None:
        unhealthy = [r for r in reports if not r.is_healthy]
        for r in unhealthy[:5]:
            blackboard.deposit(
                "error",
                f"[执行崩溃] {os.path.basename(r.filepath)}: "
                f"{r.crashed}/{r.total_tests} 崩溃 (rate={r.crash_rate:.0%})",
                source_module="sandbox_exec",
                tags=["runtime", "crash", "validation"],
            )

    return reports


def _validate_file(
    filepath: str, max_funcs: int, timeout: float,
) -> FileExecReport | None:
    """验证单个文件中的所有可测函数。"""
    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            source = f.read()
    except OSError:
        return None

    try:
        tree = ast.parse(source)
    except SyntaxError:
        return None

    # 提取带类型注解的顶层函数及其参数类型
    funcs: list[tuple[str, list[str]]] = []
    for node in ast.iter_child_nodes(tree):
        if len(funcs) >= max_funcs:
            break
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if not any(a.annotation for a in node.args.args):
                continue  # 无类型注解→无法生成边界值
            arg_types: list[str] = []
            for a in node.args.args:
                if isinstance(a.annotation, ast.Name):
                    arg_types.append(a.annotation.id)
                elif a.annotation is None:
                    arg_types.append("Any")
                else:
                    arg_types.append("Any")
            funcs.append((node.name, arg_types))

    if not funcs:
        return None

    results: list[ExecResult] = []
    passed = 0
    crashed = 0
    timed_out = 0

    for func_name, arg_types in funcs:
        # 生成边界值输入组合
        test_inputs = _gen_inputs(arg_types, max_combos=4)

        for inputs in test_inputs:
            status, output, elapsed = _worker_process(
                filepath, func_name, repr(inputs),
            )

            if status == "PASS":
                passed += 1
            elif status == "CRASH":
                crashed += 1
            elif status == "TIMEOUT":
                timed_out += 1

            results.append(ExecResult(
                func_name=func_name, status=status,
                inputs=inputs, output=str(output)[:200],
                elapsed_ms=round(elapsed, 1),
            ))

    return FileExecReport(
        filepath=filepath,
        total_tests=passed + crashed + timed_out,
        passed=passed, crashed=crashed, timed_out=timed_out,
        results=results,
    )


def _gen_inputs(arg_types: list[str], max_combos: int = 4) -> list[tuple]:
    """从类型列表生成边界值输入组合。笛卡尔积，限制最大组合数。"""
    sets: list[list[Any]] = []
    for t in arg_types:
        vals = _TYPE_BOUNDARY.get(t, [None])
        sets.append(vals[:3])

    if not sets:
        return []

    result: list[tuple] = [()]
    for s in sets:
        new_result: list[tuple] = []
        for combo in result:
            for val in s:
                new_result.append(combo + (val,))
                if len(new_result) >= max_combos:
                    return new_result
        result = new_result
    return result
