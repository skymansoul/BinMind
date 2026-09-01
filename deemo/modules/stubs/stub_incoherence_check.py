# stub_incoherence_check.py — Oracle-Free 双策略一致性校验
# 不依赖 ground truth 判定生成代码正确性：
#   两条独立策略分别生成实现 → 同输入执行 → 比较输出。
#   输出不一致 ⇒ 至少一侧有误（可证明的下界）。
#
# 理论基础:
#   Valentin et al., "Estimating Correctness Without Oracles in
#   LLM-Based Code Generation":
#   非相干性 I(d) = P(实现₁(X) ≠ 实现₂(X)) ≥ 0
#   且 I(d) ≤ 2 × 错误率(d)，即非相干性是错误率的下界。
#   → 零假阳性：不一致一定意味着至少一侧错误。
#
# 本模块的增量:
#   原论文针对通用 HumanEval/MBPP 的 LLM 代码生成，
#   本模块将其适配到合约驱动桩实现的两条异质策略
#   (TemplateGenerator 规则引擎 vs LLMGenerator 神经引擎)，
#   利用策略独立性增强不一致信号的检测效力。
import ast as _ast
import math as _math
import re as _re
import types as _types
import sys as _sys
from itertools import product as _product
from dataclasses import dataclass as _dc, field as _field
from typing import Optional as _Opt, Callable

from modules.stubs.stub_contract import (
    StubContract as _StubContract,
    FuncContract as _FuncContract,
)


@_dc
class DualImplementation:
    """同一合约的两条独立策略生成结果。"""
    module_name: str
    strategy_a: str = ''       # 策略A名称（如 'template'）
    source_a: str = ''
    strategy_b: str = ''       # 策略B名称（如 'llm'）
    source_b: str = ''


@_dc
class IncoherenceResult:
    """一次双策略一致性校验的完整结论。

    incoherence_rate: 输出不一致的测试用例占比。
    按 arXiv:2507.00057 定理，真实错误率 ≥ incoherence_rate / 2。
    """
    module_name: str
    func_name: str
    total_cases: int = 0
    mismatch_cases: int = 0
    incoherence_rate: float = 0.0        # mismatch / total
    error_lower_bound: float = 0.0       # incoherence_rate / 2
    mismatches: list = _field(default_factory=list)
    strategy_a_failures: int = 0         # 策略A执行异常次数
    strategy_b_failures: int = 0         # 策略B执行异常次数
    verdict: str = 'unknown'             # consistent | inconsistent | both_failed | single_only


class IncoherenceChecker:
    """双策略非相干性校验引擎。

    流程:
      1. 两条策略分别生成源码 → 编译为独立模块
      2. 对合约中每个可测试函数，构造输入集
      3. 两模块的同名函数分别执行 → 比较返回值
      4. 聚合不一致率，输出 IncoherenceResult

    约束:
      - 仅对可构造无副作用测试输入的函数执行（同 ContractVerifier 的 io_testable 判定）
      - NotImplementedError 视为"该策略未产出有效实现"，不计入不一致
      - 两条策略均失败时 verdict = 'both_failed'
    """

    def __init__(self, input_gen: _Opt[Callable] = None):
        self.input_gen = input_gen or self._default_inputs

    def check(self, contract: _StubContract,
              dual: DualImplementation) -> dict:
        """对整个模块执行双策略一致性校验。

        返回: {func_name: IncoherenceResult, ..., '__summary__': {overall_incoherence, ...}}
        """
        if not dual.source_a or not dual.source_b:
            return {'__summary__': {'verdict': 'incomplete',
                                    'reason': '缺少一侧策略源码'}}

        mod_a = self._compile(dual.source_a, f'{dual.module_name}_a')
        mod_b = self._compile(dual.source_b, f'{dual.module_name}_b')

        if mod_a is None and mod_b is None:
            return {'__summary__': {'verdict': 'both_failed',
                                    'reason': '两侧编译均失败'}}
        if mod_a is None:
            return {'__summary__': {'verdict': 'single_only',
                                    'reason': f'仅 {dual.strategy_b} 编译通过'}}
        if mod_b is None:
            return {'__summary__': {'verdict': 'single_only',
                                    'reason': f'仅 {dual.strategy_a} 编译通过'}}

        results = {}
        for fc in contract.functions:
            if not self._testable(fc):
                continue
            fn_a = getattr(mod_a, fc.name, None)
            fn_b = getattr(mod_b, fc.name, None)
            if fn_a is None or fn_b is None:
                continue
            results[fc.name] = self._compare_functions(fc, fn_a, fn_b)

        return self._summarize(results, dual)

    def _compare_functions(self, fc: _FuncContract, fn_a, fn_b) -> IncoherenceResult:
        """对单个函数的两条实现逐输入比较输出。"""
        r = IncoherenceResult(module_name='', func_name=fc.name)
        inputs = self.input_gen(fc)

        for args in inputs:
            try:
                out_a = fn_a(*args)
            except NotImplementedError:
                r.strategy_a_failures += 1
                continue
            except Exception:
                r.strategy_a_failures += 1
                continue

            try:
                out_b = fn_b(*args)
            except NotImplementedError:
                r.strategy_b_failures += 1
                continue
            except Exception:
                r.strategy_b_failures += 1
                continue

            r.total_cases += 1
            if not self._outputs_equal(out_a, out_b):
                r.mismatch_cases += 1
                r.mismatches.append({
                    'input': self._safe_repr(args),
                    'output_a': self._safe_repr(out_a),
                    'output_b': self._safe_repr(out_b),
                })

        if r.total_cases > 0:
            r.incoherence_rate = r.mismatch_cases / r.total_cases
            r.error_lower_bound = r.incoherence_rate / 2.0

        both_failed = (r.strategy_a_failures > 0 and r.strategy_b_failures > 0
                       and r.total_cases == 0)
        if both_failed:
            r.verdict = 'both_failed'
        elif r.mismatch_cases == 0:
            r.verdict = 'consistent'
        else:
            r.verdict = 'inconsistent'
        return r

    @staticmethod
    def _summarize(results: dict, dual: DualImplementation) -> dict:
        func_results = {k: v for k, v in results.items()
                       if k != '__summary__'}
        total_cases = sum(r.total_cases for r in func_results.values())
        total_mismatches = sum(r.mismatch_cases for r in func_results.values())
        overall_incoherence = (total_mismatches / total_cases
                              if total_cases > 0 else 0.0)

        # 汇总判定: 任一函数不一致 → 模块级不一致
        has_inconsistent = any(r.verdict == 'inconsistent'
                              for r in func_results.values())
        all_consistent = all(r.verdict in ('consistent',)
                            for r in func_results.values() if r.total_cases > 0)

        summary = {
            'module_name': dual.module_name,
            'strategy_a': dual.strategy_a,
            'strategy_b': dual.strategy_b,
            'functions_tested': len(func_results),
            'total_cases': total_cases,
            'total_mismatches': total_mismatches,
            'overall_incoherence': round(overall_incoherence, 4),
            'error_lower_bound': round(overall_incoherence / 2.0, 4),
            'verdict': ('inconsistent' if has_inconsistent
                       else 'consistent' if all_consistent
                       else 'incomplete'),
        }
        func_results['__summary__'] = summary
        return func_results

    def _compile(self, source: str, label: str):
        """编译源码为隔离的模块对象。"""
        try:
            _ast.parse(source)
        except SyntaxError:
            return None
        try:
            mod = _types.ModuleType(f'_inchk_{label}')
            exec(compile(source, f'<incoherence-{label}>', 'exec'), mod.__dict__)
            return mod
        except Exception:
            return None
        finally:
            _sys.modules.pop(f'_inchk_{label}', None)

    @staticmethod
    def _testable(fc: _FuncContract) -> bool:
        """判定函数是否可安全地构造测试输入并调用。"""
        params = [p for p in fc.params if p.kind not in ('varargs', 'varkw')]
        if not params:
            return True
        return all(p.annotation for p in params)

    @staticmethod
    def _outputs_equal(a, b) -> bool:
        """比较两个输出是否等价。

        策略: 优先用 ==；不可比较的类型（如自定义对象）退化为 repr 比较。
        浮点数特殊处理（相对误差 ≤ 1e-9）。
        """
        if a is b:
            return True
        if isinstance(a, float) and isinstance(b, float):
            return _math.isclose(a, b, rel_tol=1e-9, abs_tol=1e-12)
        try:
            return a == b
        except Exception:
            return repr(a) == repr(b)

    @staticmethod
    def _default_inputs(fc: _FuncContract) -> list[tuple]:
        """默认输入生成：每个参数取边界值 + 典型值。"""
        params = [p for p in fc.params if p.kind not in ('varargs', 'varkw')]
        if not params:
            return [()]

        def base_type(ann: str) -> str:
            a = (ann or '').strip().lower()
            m = _re.match(r'([a-z_][a-z0-9_]*)', a)
            return m.group(1) if m else ''

        value_map = {
            'int': [0, 1, -1, 42],
            'float': [0.0, 1.0, -1.0, 3.14],
            'str': ['', 'a', 'test'],
            'bytes': [b'', b'\x00', b'test'],
            'bool': [False, True],
            'list': [[], [0]],
            'dict': [{}, {'k': 0}],
            'set': [set(), {0}],
            'tuple': [(), (0,)],
        }

        candidates = [value_map.get(base_type(p.annotation), [None])
                     for p in params]

        combos = list(_product(*candidates))
        return combos[:16]

    @staticmethod
    def _safe_repr(obj) -> str:
        try:
            s = repr(obj)
            return s[:200] + '...' if len(s) > 200 else s
        except Exception:
            return '<unrepresentable>'


def check_dual_implementation(contract: _StubContract,
                              source_template: str,
                              source_llm: str) -> dict:
    """一行式双策略校验入口。"""
    dual = DualImplementation(
        module_name=contract.module_name,
        strategy_a='template', source_a=source_template,
        strategy_b='llm', source_b=source_llm,
    )
    checker = IncoherenceChecker()
    return checker.check(contract, dual)


__all__ = [
    'DualImplementation', 'IncoherenceResult',
    'IncoherenceChecker', 'check_dual_implementation',
]
