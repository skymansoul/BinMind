# stub_conflict_detector.py — 跨桩合约冲突检测
# 检测不同桩模块间同名函数但签名不兼容的冲突。
# 当两个模块都导出同名符号但参数/返回类型不同时，
# 同时 import 两者的下游模块将遇到运行时错误。
#
# 方案:
#   1. 扫描全部桩模块的导出符号（public_api_names）
#   2. 找到被多个模块导出的同名符号
#   3. 比较签名兼容性:
#      a) 参数数量不同 → 潜在冲突
#      b) 返回类型不同 → 高风险冲突
#      c) 参数类型不同 → 潜在冲突
#   4. 输出冲突矩阵: (符号名, 模块A签名, 模块B签名, 风险等级)
import os as _os
from collections import defaultdict as _dd
from dataclasses import dataclass as _dc, field as _field

from modules.stubs.stub_contract import (
    StubContractor as _StubContractor,
    FuncContract as _FuncContract,
)


@_dc
class SymbolConflict:
    """单条跨模块符号冲突。"""
    symbol_name: str
    modules: list = _field(default_factory=list)  # [(module, signature)]
    risk: str = 'low'       # high | medium | low
    detail: str = ''


class ConflictDetector:
    """跨桩合约冲突检测器。

    风险判定:
      HIGH   — 返回类型不同 + 参数签名相同
               → 下游代码使用返回值时静默类型错误
      MEDIUM — 参数数量或类型不同
               → from X import * 时后者覆盖前者
      LOW    — 仅参数默认值不同
               → 行为差异但非阻断
    """

    def __init__(self, stubs_dir: str = None):
        if stubs_dir is None:
            stubs_dir = _os.path.dirname(_os.path.abspath(__file__))
        self.stubs_dir = stubs_dir
        self.contractor = _StubContractor(stubs_dir=stubs_dir)

    def detect(self) -> list[SymbolConflict]:
        contracts = self.contractor.scan_all()
        # {symbol_name: [(module, func_contract)]}
        symbol_map = _dd(list)

        for mod_name, contract in contracts.items():
            if mod_name.startswith('stub_'):
                continue
            for fc in contract.functions:
                # 跳过私有函数
                if fc.name.startswith('_'):
                    continue
                symbol_map[fc.name].append((mod_name, fc))

        conflicts = []
        for sym, entries in symbol_map.items():
            if len(entries) < 2:
                continue

            # 比较每对模块的签名
            for i in range(len(entries)):
                for j in range(i + 1, len(entries)):
                    mod_a, fc_a = entries[i]
                    mod_b, fc_b = entries[j]
                    risk, detail = self._compare(fc_a, fc_b)
                    if risk != 'none':
                        conflicts.append(SymbolConflict(
                            symbol_name=sym,
                            modules=[
                                (mod_a, self._render_sig(fc_a)),
                                (mod_b, self._render_sig(fc_b)),
                            ],
                            risk=risk,
                            detail=detail,
                        ))

        conflicts.sort(key=lambda c: {'high': 0, 'medium': 1, 'low': 2}[c.risk])
        return conflicts

    @staticmethod
    def _compare(a: _FuncContract, b: _FuncContract) -> tuple[str, str]:
        """比较两个同名函数的签名兼容性。"""
        params_a = [p for p in a.params if p.kind not in ('varargs', 'varkw')]
        params_b = [p for p in b.params if p.kind not in ('varargs', 'varkw')]

        ret_diff = (a.return_ann != b.return_ann and
                   a.return_ann and b.return_ann)
        param_count_diff = len(params_a) != len(params_b)

        # HIGH: 返回类型不同 + 参数一致 → 调用方静默类型错误
        if ret_diff and not param_count_diff:
            same_params = all(
                pa.annotation == pb.annotation
                for pa, pb in zip(params_a, params_b))
            if same_params:
                return ('high',
                       f'返回类型冲突: {a.return_ann} vs {b.return_ann} '
                       f'(相同参数签名)')

        # MEDIUM: 参数差异
        if param_count_diff:
            return ('medium',
                   f'参数数不同: {len(params_a)} vs {len(params_b)}')
        if ret_diff:
            return ('medium',
                   f'返回类型不同: {a.return_ann} vs {b.return_ann}')

        # LOW: 仅默认值或注解差异
        for pa, pb in zip(params_a, params_b):
            if pa.has_default != pb.has_default:
                return ('low',
                       f'参数 {pa.name} 默认值不一致')
            if pa.annotation != pb.annotation:
                return ('low',
                       f'参数 {pa.name} 类型注解不一致: '
                       f'{pa.annotation} vs {pb.annotation}')

        return ('none', '')

    @staticmethod
    def _render_sig(fc: _FuncContract) -> str:
        parts = []
        for p in fc.params:
            piece = p.name
            if p.annotation:
                piece += f':{p.annotation}'
            parts.append(piece)
        sig = f'({",".join(parts)})'
        if fc.return_ann:
            sig += f'->{fc.return_ann}'
        return sig


__all__ = ['SymbolConflict', 'ConflictDetector']
