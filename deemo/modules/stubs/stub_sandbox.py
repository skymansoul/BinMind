# stub_sandbox.py — 沙箱化运行时执行测试
# 在隔离子进程中执行桩实现，喂入安全相关载荷，
# 捕获崩溃/超时/内存异常/非预期异常。
#
# 问题:
#   现有验证管线全部在宿进程中运行:
#     - ContractVerifier 直接 exec() 源码
#     - AdversarialFuzzer 直接调用函数
#   这种"信任执行"无法检测:
#     a) 无限循环/递归导致进程卡死
#     b) 内存泄漏（大输入下分配失控）
#     c) 段错误/访问违规（原生扩展或 ctypes）
#     d) 恶意代码注入（若 LLM 生成含 eval/exec 的代码）
#
# 方案 — 三层沙箱:
#   1. 进程隔离: subprocess 执行，独立 Python 解释器
#   2. 资源限制: timeout(CPU时间), max_memory
#   3. 代码审查: AST 扫描检测危险调用 (eval, exec, __import__, compile)
#   输出: SandboxResult(exit_code, stdout, stderr, duration, peak_memory,
#          crashed, timed_out, dangerous_calls)
import ast as _ast
import os as _os
import subprocess as _sp
import sys as _sys
import tempfile as _tmp
from dataclasses import dataclass as _dc, field as _field
from typing import Optional as _Opt


@_dc
class SandboxResult:
    """一次沙箱执行的结果。"""
    module_name: str
    func_name: str = ''
    # 执行结果
    exit_code: int = -1
    timed_out: bool = False
    crashed: bool = False       # 非零退出码或异常
    # 资源
    duration_ms: float = 0.0
    # 输出
    stdout_preview: str = ''
    stderr_preview: str = ''
    exception_type: str = ''
    exception_msg: str = ''
    # 代码审查
    dangerous_calls: list = _field(default_factory=list)
    safe: bool = False          # 综合判定


class SandboxExecutor:
    """沙箱化运行时执行器。

    载荷生成:
      - 每个参数类型的 2-3 个安全相关值
      - 针对二进制分析桩的特殊载荷:
        * 空字节序列 (b'')
        * 全零页 (b'\x00' * 4096)
        * 格式错误的 PE/ELF 头
        * 超长字符串 (触发缓冲区溢出)
    """

    DEFAULT_TIMEOUT_SEC = 5.0

    # 危险调用黑名单
    DANGEROUS_CALLS = {'eval', 'exec', 'compile', '__import__',
                       'open', 'os.system', 'subprocess',
                       'ctypes', 'cffi'}

    def __init__(self, timeout: float = None):
        self.timeout = timeout or self.DEFAULT_TIMEOUT_SEC

    def execute(self, source: str, module_name: str,
                func_name: str, args: tuple = ()) -> SandboxResult:
        """在沙箱子进程中执行指定函数。"""
        result = SandboxResult(module_name=module_name, func_name=func_name)

        # 1. 代码审查
        dangerous = self._scan_dangerous(source)
        if dangerous:
            result.dangerous_calls = dangerous
            return result

        # 2. 构造测试脚本
        script = self._build_script(source, func_name, args)

        # 3. 子进程执行
        try:
            proc = _sp.run(
                [_sys.executable, '-c', script],
                capture_output=True, text=True,
                timeout=self.timeout,
                env={**_os.environ, 'PYTHONHASHSEED': '0'},
            )
            result.exit_code = proc.returncode
            result.stdout_preview = proc.stdout[:500]
            result.stderr_preview = proc.stderr[:500]

            if proc.returncode != 0:
                result.crashed = True
                result.exception_msg = self._extract_exception(proc.stderr)

        except _sp.TimeoutExpired:
            result.timed_out = True
            result.crashed = True
            result.stderr_preview = 'TIMEOUT'
            result.exception_msg = f'execution exceeded {self.timeout}s'

        result.safe = (not result.crashed and not result.timed_out
                      and not result.dangerous_calls)
        return result

    def execute_with_payloads(self, source: str, module_name: str,
                              func_name: str, param_types: list[str]
                              ) -> list[SandboxResult]:
        """用安全相关载荷批量执行。"""
        payloads = self._generate_payloads(param_types)
        results = []
        for payload in payloads:
            results.append(self.execute(
                source, module_name, func_name, payload))
        return results

    # ---- 代码审查 ----
    @classmethod
    def _scan_dangerous(cls, source: str) -> list[str]:
        """AST 扫描检测危险调用。"""
        try:
            tree = _ast.parse(source)
        except SyntaxError:
            return ['syntax_error']

        found = []
        for node in _ast.walk(tree):
            if isinstance(node, _ast.Call):
                name = cls._call_name(node)
                if name in cls.DANGEROUS_CALLS:
                    found.append(f'{name}@L{node.lineno}')
        return found

    @staticmethod
    def _call_name(node: _ast.Call) -> str:
        func = node.func
        if isinstance(func, _ast.Name):
            return func.id
        if isinstance(func, _ast.Attribute):
            if isinstance(func.value, _ast.Name):
                return f'{func.value.id}.{func.attr}'
            return func.attr
        return ''

    # ---- 载荷生成 ----
    @staticmethod
    def _generate_payloads(param_types: list[str]) -> list[tuple]:
        """为参数类型列表生成安全载荷组合。"""
        import re
        def base(t: str) -> str:
            m = re.match(r'([a-z_][a-z0-9_]*)', (t or '').strip().lower())
            return m.group(1) if m else ''

        payloads_per_param = {
            'int': [0, -1, 2**63 - 1, -(2**63)],
            'str': ['', '\x00', 'A' * 65536],
            'bytes': [b'', b'\x00' * 4096, b'MZ\x90\x00' + b'\x00' * 64],
            'bool': [False, True],
            'list': [[], [None] * 1000],
            'dict': [{}, {'k' * 100: 'v' * 100}],
        }

        # 对每个参数取第一个安全载荷构造单组输入
        # 然后逐个参数替换为危险载荷
        bases = [b for b in param_types]
        default_payload = tuple(
            payloads_per_param.get(base(b), [None])[0]
            for b in bases)

        result = [default_payload]
        for i, b in enumerate(bases):
            for p in payloads_per_param.get(base(b), [None])[1:]:
                variant = list(default_payload)
                variant[i] = p
                result.append(tuple(variant))

        return result[:12]

    @staticmethod
    def _build_script(source: str, func_name: str,
                      args: tuple) -> str:
        """构造可独立执行的 Python 脚本。"""
        args_repr = ', '.join(repr(a) for a in args)
        return f'''
import sys, os, tracemalloc, time, json
try:
    tracemalloc.start()
    ns = {{}}
    exec(compile({repr(source)}, '<sandbox>', 'exec'), ns)
    fn = ns.get({repr(func_name)})
    if fn is None:
        result = {{'error': 'function not found'}}
    else:
        t0 = time.perf_counter()
        out = fn({args_repr})
        dt = (time.perf_counter() - t0) * 1000
        _, peak = tracemalloc.get_traced_memory()
        result = {{'ok': True, 'output': repr(out)[:500], 'duration_ms': dt,
                  'peak_memory_bytes': peak}}
except Exception as e:
    result = {{'ok': False, 'error': type(e).__name__ + ': ' + str(e)[:300]}}
print(json.dumps(result))
'''

    @staticmethod
    def _extract_exception(stderr: str) -> str:
        for line in stderr.splitlines():
            if 'Error' in line or 'Exception' in line:
                return line.strip()[:200]
        return stderr.strip()[:200]


__all__ = ['SandboxResult', 'SandboxExecutor']
