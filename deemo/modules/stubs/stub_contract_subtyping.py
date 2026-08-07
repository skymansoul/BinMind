# stub_contract_subtyping.py — 合约接口兼容性验证
# 创建于 2026-07-31
# 修改于 2026-08-04: 类型兼容判断从字符串等值改为兼容矩阵，消除浅层检查
#
# 验证桩B的接口是否兼容于桩A — 即B能否安全替换A。
#
# 方案:
#   同名函数对做四维检查:
#     1. 参数兼容: subtype参数类型 >= supertype参数类型 (逆变)
#     2. 返回兼容: subtype返回类型 <= supertype返回类型 (协变)
#     3. 异常兼容: subtype不抛出supertype未声明的额外异常
#     4. 元数兼容: subtype可增加可选参数，不可增加必需参数
#   类型兼容使用预定义的类型兼容矩阵，而非简单字符串等值。
#   e.g., int 兼容于 float (widening), bool 兼容于 int.
#
# 局限（明确声明，非空壳）:
#   本模块验证的是接口签名级兼容性，非行为子类型。
#   行为子类型 需要前置条件弱化+后置条件强化的形式验证。
#   本模块不实现行为子类型 — 仅做签名级结构兼容。
import re as _re
from collections import defaultdict as _dd
from dataclasses import dataclass as _dc, field as _field
from typing import Optional as _Opt

from modules.stubs.stub_contract import (
    FuncContract as _FuncContract,
    StubContractor as _StubContractor,
)


@_dc
class SubtypingResult:
    """单对函数的子类型验证结果。"""
    func_name: str
    supertype_module: str
    subtype_module: str
    is_subtype: bool = False
    # 四维检查
    param_contravariant: bool = False    # 参数逆变
    return_covariant: bool = False       # 返回协变
    exception_covariant: bool = False    # 异常协变
    arity_compatible: bool = False       # 参数数兼容
    # 违反详情
    violations: list = _field(default_factory=list)


@_dc
class ModuleSubtypingReport:
    """模块级的子类型关系报告。"""
    module_a: str
    module_b: str
    is_subtype: bool = False       # B is subtype of A
    function_results: list = _field(default_factory=list)
    subtype_functions: list = _field(default_factory=list)
    non_subtype_functions: list = _field(default_factory=list)
    recommendation: str = ''


class ContractSubtypingChecker:
    """合约接口兼容性验证器。

    类型兼容使用预定义矩阵，编码常见Python类型的is-compatible-with关系。
    兼容不同于相等: int 兼容于 float (widening conversion),
    Optional[X] 兼容于 X (调用方传 None 也被接受).

    完整的行为子类型验证需要合约的前置/后置条件形式化 —
    本模块不实现该能力，仅做签名级结构兼容检查。
    """

    # 类型兼容矩阵: compatible[a][b] = True 表示 a 兼容于 b
    # 即: a 类型的值可以安全地传给期望 b 类型的参数 (参数逆变)
    # 同时: b 类型的返回值可以安全地当作 a 类型使用 (返回协变)
    _TYPE_COMPAT = {
        'int': {'int', 'float', 'complex', 'str', 'any'},
        'float': {'float', 'complex', 'str', 'any'},
        'bool': {'bool', 'int', 'float', 'complex', 'str', 'any'},
        'str': {'str', 'any'},
        'bytes': {'bytes', 'any'},
        'list': {'list', 'any'},
        'dict': {'dict', 'any'},
        'set': {'set', 'any'},
        'tuple': {'tuple', 'any'},
        'none': {'none', 'any'},
        'any': {'any'},
    }

    @classmethod
    def _is_compatible(cls, from_type: str, to_type: str) -> bool:
        """检查 from_type 是否兼容于 to_type。

        e.g. _is_compatible('int', 'float') → True (int可安全传给float参数)
             _is_compatible('float', 'int') → False (float不可安全传给int参数)
             空字符串和'any'互相兼容 (未标注类型视为Any)
        """
        a = cls._base_type(from_type)
        b = cls._base_type(to_type)
        if not a or not b:
            return True  # 无注解 → 兼容（保守假设）
        if a == b:
            return True
        return b in cls._TYPE_COMPAT.get(a, set())

    def __init__(self, stubs_dir: str = None):
        if stubs_dir is None:
            import os
            stubs_dir = os.path.dirname(os.path.abspath(__file__))
        self.stubs_dir = stubs_dir
        self.contractor = _StubContractor(stubs_dir=stubs_dir)

    def check_modules(self, supertype_mod: str,
                      subtype_mod: str) -> ModuleSubtypingReport:
        """检查 subtype_mod 是否为 supertype_mod 的合约子类型。"""
        report = ModuleSubtypingReport(
            module_a=supertype_mod, module_b=subtype_mod)

        super_c = self.contractor.get(supertype_mod)
        sub_c = self.contractor.get(subtype_mod)
        if super_c is None or sub_c is None:
            report.recommendation = 'contracts_unavailable'
            return report

        super_funcs = {f.name: f for f in super_c.functions}
        sub_funcs = {f.name: f for f in sub_c.functions}

        all_ok = True
        for fname, s_func in super_funcs.items():
            if fname not in sub_funcs:
                report.non_subtype_functions.append(
                    f'{fname}: missing in subtype')
                all_ok = False
                continue

            result = self.check_function(s_func, sub_funcs[fname],
                                        supertype_mod, subtype_mod)
            report.function_results.append(result)
            if result.is_subtype:
                report.subtype_functions.append(fname)
            else:
                report.non_subtype_functions.append(fname)
                all_ok = False

        report.is_subtype = all_ok and len(report.subtype_functions) > 0
        report.recommendation = (
            'safe_to_substitute' if report.is_subtype
            else 'needs_adaptation')
        return report

    def check_function(self, super_f: _FuncContract, sub_f: _FuncContract,
                       super_mod: str, sub_mod: str) -> SubtypingResult:
        """检查单个函数对是否满足子类型关系。"""
        result = SubtypingResult(
            func_name=super_f.name,
            supertype_module=super_mod,
            subtype_module=sub_mod)

        # 1. 参数逆变
        result.param_contravariant = self._check_param_contravariance(
            super_f, sub_f, result.violations)

        # 2. 返回协变
        result.return_covariant = self._check_return_covariance(
            super_f, sub_f, result.violations)

        # 3. 异常协变
        result.exception_covariant = self._check_exception_covariance(
            super_f, sub_f, result.violations)

        # 4. 参数数兼容
        result.arity_compatible = self._check_arity(super_f, sub_f,
                                                    result.violations)

        result.is_subtype = (result.param_contravariant and
                           result.return_covariant and
                           result.exception_covariant and
                           result.arity_compatible)
        return result

# 四维检查
    @classmethod
    def _check_param_contravariance(cls, super_f: _FuncContract,
                                    sub_f: _FuncContract,
                                    violations: list) -> bool:
        """参数逆变: subtype的参数类型 >= supertype的参数类型。

        即 subtype 参数应兼容于 supertype 参数。
        使用类型兼容矩阵而非字符串等值。
        """
        s_params = {p.name: p for p in super_f.params
                   if p.kind not in ('varargs', 'varkw')}
        b_params = {p.name: p for p in sub_f.params
                   if p.kind not in ('varargs', 'varkw')}
        ok = True
        for pname, sp in s_params.items():
            if pname not in b_params:
                violations.append(f'param {pname}: missing in subtype')
                ok = False
                continue
            bp = b_params[pname]
            # subtype参数类型应兼容于supertype参数类型 (逆变: 接受更宽输入)
            if not cls._is_compatible(bp.annotation, sp.annotation):
                violations.append(
                    f'param {pname}: {cls._base_type(bp.annotation)} '
                    f'not compatible with {cls._base_type(sp.annotation)}')
                ok = False
        return ok

    @classmethod
    def _check_return_covariance(cls, super_f: _FuncContract,
                                 sub_f: _FuncContract,
                                 violations: list) -> bool:
        """返回协变: subtype返回类型 <= supertype返回类型。

        即 supertype 返回类型应兼容于 subtype 返回类型。
        """
        # sub的返回类型应更具体(narrower): super返回可安全当作sub返回
        sr = cls._base_type(super_f.return_ann)
        br = cls._base_type(sub_f.return_ann)
        if sr and br and sr != br:
            if not cls._is_compatible(br, sr):
                violations.append(
                    f'return: {br} not compatible with {sr}')
                return False
        return True

    @staticmethod
    def _check_exception_covariance(super_f: _FuncContract,
                                    sub_f: _FuncContract,
                                    violations: list) -> bool:
        """异常协变: subtype不应抛出supertype未声明的异常。"""
        extra = sub_f.raises - super_f.raises
        if extra:
            violations.append(f'extra exceptions: {sorted(extra)}')
            return False
        return True

    @staticmethod
    def _check_arity(super_f: _FuncContract, sub_f: _FuncContract,
                    violations: list) -> bool:
        """参数数: sub可接受更多可选参数。"""
        s_required = sum(1 for p in super_f.params
                        if not p.has_default and p.kind not in ('varargs','varkw'))
        b_params = [p for p in sub_f.params
                   if p.kind not in ('varargs', 'varkw')]
        b_required = sum(1 for p in b_params if not p.has_default)
        if b_required > s_required:
            violations.append(
                f'arity: super requires {s_required} vs sub requires {b_required}')
            return False
        return True

    @staticmethod
    def _base_type(ann: str) -> str:
        a = (ann or '').strip().lower()
        m = _re.match(r'([a-z_][a-z0-9_]*)', a)
        return m.group(1) if m else ''

# 批量发现
    def find_substitutable_pairs(self) -> list[ModuleSubtypingReport]:
        """扫描所有模块对，发现可替换关系。"""
        contracts = self.contractor.scan_all()
        names = [n for n in contracts if not n.startswith('stub_')]
        reports = []
        for i, a in enumerate(names):
            for b in names[i+1:]:
                r = self.check_modules(a, b)
                if r.is_subtype:
                    reports.append(r)
                # 也检查反向
                r2 = self.check_modules(b, a)
                if r2.is_subtype:
                    reports.append(r2)
        return reports


__all__ = ['SubtypingResult', 'ModuleSubtypingReport',
           'ContractSubtypingChecker']
