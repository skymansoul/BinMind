# stub_invariant_miner.py — 跨模块合约不变量挖掘
# 从多个已实现桩的合约中挖掘共同模式（不变量），
# 用于验证新实现是否符合项目约定。
#
# 问题:
#   桩模块各自独立定义接口，但同一项目内的桩通常遵循隐含约定:
#     "所有 detect_* 函数返回 bool"
#     "所有 extract_* 函数的第一个参数是 bytes"
#     "所有 is_* 函数无副作用（不 raise）"
#   这些约定目前仅存在于开发者心智中，未被形式化。
#   当新生成的实现违反这些约定时，没有自动检测机制。
#
# 方法:
#   1. 扫描全部已实现模块的合约，提取函数级模式
#   2. 按函数名前缀分组 (detect_, extract_, parse_, is_, has_, get_, ...)
#   3. 对每组挖掘统计不变量:
#      a) 返回类型一致性 (>80% 成员返回同一类型 → 不变量)
#      b) 第一参数类型一致性
#      c) 异常声明模式
#   4. 对给定函数检查是否违反已知不变量
#
# 区别于 MINES:
#   MINES 从 API 运行时日志推断数据库级不变量用于异常检测。
#   本模块从静态合约中挖掘命名+类型级不变量用于实现验证。
import os as _os
import re as _re
from collections import Counter as _Ctr, defaultdict as _dd
from dataclasses import dataclass as _dc, field as _field

from modules.stubs.stub_contract import (
    FuncContract as _FuncContract,
    StubContractor as _StubContractor,
)


@_dc
class MinedInvariant:
    """一条挖掘的不变量。"""
    group: str = ''               # 函数名前缀组
    category: str = ''            # return_type | first_param_type | raises_pattern
    invariant: str = ''           # 可读描述
    confidence: float = 0.0       # 组成员一致率
    member_count: int = 0         # 组成员数
    violating_funcs: list = _field(default_factory=list)


@_dc
class InvariantViolation:
    """一条不变量违反记录。"""
    func_name: str
    module_name: str
    invariant: MinedInvariant
    expected: str = ''
    actual: str = ''


class InvariantMiner:
    """跨模块合约不变量挖掘器。

    不变量挖掘规则:
      - 组规模 ≥ 3 → 开始挖掘
      - 一致性 ≥ 80% → 标记为不变量
      - 一致性 ≥ 95% → 标记为强不变量
    """

    MIN_GROUP_SIZE = 3
    CONFIDENCE_THRESHOLD = 0.8

    # 常见函数名前缀
    PREFIX_PATTERN = _re.compile(
        r'^(detect|extract|parse|is_|has_|get_|set_|check_|'
        r'validate|verify|analyze|scan|find|search|match|'
        r'generate|create|build|compute|calc|process|'
        r'encode|decode|encrypt|decrypt|hash|sign|verify_|'
        r'load|save|read|write|open|close|'
        r'convert|transform|filter|map|reduce|merge|split)'
    )

    def __init__(self, stubs_dir: str = None):
        if stubs_dir is None:
            stubs_dir = _os.path.dirname(_os.path.abspath(__file__))
        self.stubs_dir = stubs_dir
        self.contractor = _StubContractor(stubs_dir=stubs_dir)

    def mine(self) -> list[MinedInvariant]:
        """挖掘全部不变量。"""
        groups = self._group_by_prefix()
        invariants = []

        for prefix, funcs in groups.items():
            if len(funcs) < self.MIN_GROUP_SIZE:
                continue

            # 返回类型一致性
            ret_types = _Ctr(f.return_ann for f in funcs if f.return_ann)
            if ret_types:
                top_ret, top_count = ret_types.most_common(1)[0]
                conf = top_count / len(funcs)
                if conf >= self.CONFIDENCE_THRESHOLD:
                    invariants.append(MinedInvariant(
                        group=prefix,
                        category='return_type',
                        invariant=f'{prefix}* functions return {top_ret}',
                        confidence=round(conf, 2),
                        member_count=len(funcs),
                        violating_funcs=[
                            f'{fc.name}' for fc in funcs
                            if fc.return_ann and fc.return_ann != top_ret
                        ],
                    ))

            # 第一参数类型一致性
            first_params = []
            for f in funcs:
                native = [p for p in f.params
                         if p.kind not in ('varargs', 'varkw')]
                if native and native[0].annotation:
                    first_params.append(native[0].annotation)
            if first_params:
                param_ctr = _Ctr(first_params)
                top_p, top_pc = param_ctr.most_common(1)[0]
                pconf = top_pc / len(funcs)
                if pconf >= self.CONFIDENCE_THRESHOLD:
                    invariants.append(MinedInvariant(
                        group=prefix,
                        category='first_param_type',
                        invariant=f'{prefix}* first param is {top_p}',
                        confidence=round(pconf, 2),
                        member_count=len(funcs),
                    ))

            # raises 模式: 多数函数声明同一异常
            raises_all = []
            for f in funcs:
                raises_all.extend(f.raises)
            if raises_all:
                rctr = _Ctr(raises_all)
                top_r, top_rc = rctr.most_common(1)[0]
                rconf = top_rc / len(funcs)
                if rconf >= 0.5:
                    invariants.append(MinedInvariant(
                        group=prefix,
                        category='raises_pattern',
                        invariant=f'{prefix}* commonly raises {top_r}',
                        confidence=round(rconf, 2),
                        member_count=len(funcs),
                    ))

        invariants.sort(key=lambda i: -i.confidence)
        return invariants

    def check(self, fc: _FuncContract) -> list[InvariantViolation]:
        """检查单个函数是否违反已知不变量。"""
        invariants = self.mine()
        violations = []

        for inv in invariants:
            prefix = inv.group
            if not fc.name.startswith(prefix):
                continue

            if inv.category == 'return_type':
                expected = inv.invariant.split()[-1]
                if fc.return_ann and fc.return_ann != expected:
                    violations.append(InvariantViolation(
                        func_name=fc.name, module_name='',
                        invariant=inv, expected=expected,
                        actual=fc.return_ann))

            elif inv.category == 'first_param_type':
                expected = inv.invariant.split('is ')[-1]
                native = [p for p in fc.params
                         if p.kind not in ('varargs', 'varkw')]
                if native and native[0].annotation:
                    if native[0].annotation != expected:
                        violations.append(InvariantViolation(
                            func_name=fc.name, module_name='',
                            invariant=inv, expected=expected,
                            actual=native[0].annotation))

        return violations

    def _group_by_prefix(self) -> dict[str, list[_FuncContract]]:
        """按函数名前缀分组。"""
        contracts = self.contractor.scan_all()
        groups = _dd(list)

        for mod_name, contract in contracts.items():
            if mod_name.startswith('stub_'):
                continue
            for fc in contract.functions:
                m = self.PREFIX_PATTERN.match(fc.name)
                if m:
                    groups[m.group(1)].append(fc)

        return dict(groups)

    def invariant_report(self,
                         invariants: list[MinedInvariant] = None) -> str:
        if invariants is None:
            invariants = self.mine()
        lines = ['# 跨模块合约不变量', '',
                 '| 前缀组 | 类别 | 不变量 | 置信度 | 成员数 |',
                 '|--------|------|--------|-------:|-------:|']
        for inv in invariants:
            lines.append(
                f'| {inv.group} | {inv.category} | {inv.invariant} | '
                f'{inv.confidence:.0%} | {inv.member_count} |')
        return '\n'.join(lines)


__all__ = ['MinedInvariant', 'InvariantViolation', 'InvariantMiner']
