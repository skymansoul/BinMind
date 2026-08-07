# 路径守卫收集器 — 从汇编中提取cmp+jcc对目标寄存器的区间约束
"""路径守卫收集器 — 独立于可行性检查的指令级条件提取。

负责从x86_64汇编中识别以下模式并将其转化为GuardCondition:
  - cmp reg, N; ja/jbe/jg/jle/je/jne → 区间约束
  - test reg, reg; jz/jnz → 零/非零约束
  - and reg, mask → 位掩码约束

这些guard条件随后由PathFeasibilityChecker验证一致性。
分离收集与检查的职责: 收集器只关心指令模式匹配，
不关心多个guard之间是否矛盾。
"""

import re
import logging
from typing import List, Optional, Tuple

_log = logging.getLogger(__name__)

# 从heap_path_sensitivity导入共享数据类型
# 避免循环导入: 这些类型定义在heap_path_sensitivity中
# 运行时通过延迟导入解决
_GuardKind = None
_GuardCondition = None


def _init_types():
    """延迟导入共享类型，避免启动时的循环依赖。"""
    global _GuardKind, _GuardCondition
    if _GuardKind is None:
        from .heap_path_sensitivity import GuardKind, GuardCondition
        _GuardKind = GuardKind
        _GuardCondition = GuardCondition


class PathGuardCollector:
    """在汇编指令窗口中收集对特定寄存器的路径守卫条件。

    仅从cmp/test/and指令中提取直接作用于target_reg的约束。
    不分析间接约束（如cmp [rbp-8], N where [rbp-8] = target_reg）。
    这个保守策略避免过度约束（宁可保留FP也不误杀TP）。
    """

    _CMP_PAT = re.compile(
        r'\bcmp\s+(\w+),?\s*(0x[0-9a-f]+|\d+|\w+)', re.I)
    _TEST_PAT = re.compile(
        r'\btest\s+(\w+),?\s*(\w+)', re.I)
    _JCC_PAT = re.compile(
        r'\b(j[a-z]+)\s+', re.I)
    _AND_PAT = re.compile(
        r'\band\s+(\w+),?\s*(0x[0-9a-f]+|\d+)', re.I)

    _JCC_TO_KIND = {
        'ja': None, 'jae': None, 'jb': None, 'jbe': None,
        'jg': None, 'jge': None, 'jl': None, 'jle': None,
        'je': None, 'jz': None, 'jne': None, 'jnz': None,
        'jna': None, 'jnae': None,
    }
    # 此map在_init_types后填充

    _SIGNED_JCC = {'jg', 'jge', 'jl', 'jle'}

    def __init__(self):
        _init_types()
        if self._JCC_TO_KIND.get('ja') is None:
            self._JCC_TO_KIND = {
                'ja': _GuardKind.CMP_JA, 'jae': _GuardKind.CMP_JA,
                'jb': _GuardKind.CMP_JBE, 'jbe': _GuardKind.CMP_JBE,
                'jg': _GuardKind.CMP_JG, 'jge': _GuardKind.CMP_JG,
                'jl': _GuardKind.CMP_JLE, 'jle': _GuardKind.CMP_JLE,
                'je': _GuardKind.CMP_JE, 'jz': _GuardKind.CMP_JE,
                'jne': _GuardKind.CMP_JNE, 'jnz': _GuardKind.CMP_JNE,
                'jna': _GuardKind.CMP_JBE, 'jnae': _GuardKind.CMP_JA,
            }

    def collect(self, asm_lines: List[str],
                target_reg: str,
                trace_range: Tuple[int, int]) -> List:
        """收集对target_reg的所有路径守卫条件。"""
        guards = []
        start, end = trace_range
        start = max(start, 0)
        end = min(end, len(asm_lines))

        for i in range(start, end):
            line = asm_lines[i].strip().lower().replace(',', ' ')

            # cmp target_reg, X → 检查jcc
            cmp_m = self._CMP_PAT.search(line)
            if cmp_m:
                reg = cmp_m.group(1)
                if reg == target_reg or self._reg_aliases(reg, target_reg):
                    operand = cmp_m.group(2)
                    bound = self._parse_operand(operand)
                    if bound is not None:
                        guard = self._find_jcc_after(asm_lines, i, target_reg, bound)
                        if guard:
                            guards.append(guard)
                    continue

            # test target_reg, target_reg
            test_m = self._TEST_PAT.search(line)
            if test_m:
                r1, r2 = test_m.group(1), test_m.group(2)
                if r1 == target_reg and r1 == r2:
                    guard = self._find_jcc_after(asm_lines, i, target_reg, 0)
                    if guard:
                        guards.append(guard)
                    continue

            # and target_reg, mask
            and_m = self._AND_PAT.search(line)
            if and_m:
                reg = and_m.group(1)
                if reg == target_reg or self._reg_aliases(reg, target_reg):
                    v = and_m.group(2)
                    mask = int(v, 16) if v.lower().startswith('0x') else int(v)
                    guards.append(_GuardCondition(
                        reg=target_reg, kind=_GuardKind.AND_MASK,
                        bound=mask, line=i))
                continue

        return guards

    def _find_jcc_after(self, asm_lines, cmp_idx, target_reg, bound):
        """在cmp/test之后找第一个条件跳转并构造GuardCondition。"""
        for j in range(cmp_idx + 1, min(cmp_idx + 5, len(asm_lines))):
            line = asm_lines[j].strip().lower()
            jcc_m = self._JCC_PAT.search(line)
            if jcc_m:
                jcc = jcc_m.group(1)
                kind = self._JCC_TO_KIND.get(jcc)
                if kind:
                    return _GuardCondition(
                        reg=target_reg, kind=kind, bound=bound,
                        line=j, is_signed=jcc in self._SIGNED_JCC)
                break
            if re.search(r'\b(call|jmp|ret)\b', line):
                break
        return None

    @staticmethod
    def _parse_operand(op: str) -> Optional[int]:
        try:
            if op.lower().startswith('0x'):
                return int(op, 16)
            return int(op)
        except ValueError:
            return None

    @staticmethod
    def _reg_aliases(r1: str, r2: str) -> bool:
        alias_map = {
            'al': 'rax', 'ah': 'rax', 'ax': 'rax', 'eax': 'rax',
            'dil': 'rdi', 'di': 'rdi', 'edi': 'rdi',
            'sil': 'rsi', 'si': 'rsi', 'esi': 'rsi',
            'dl': 'rdx', 'dh': 'rdx', 'dx': 'rdx', 'edx': 'rdx',
            'cl': 'rcx', 'ch': 'rcx', 'cx': 'rcx', 'ecx': 'rcx',
            'r8b': 'r8', 'r8w': 'r8', 'r8d': 'r8',
            'r9b': 'r9', 'r9w': 'r9', 'r9d': 'r9',
        }
        return alias_map.get(r1, r1) == alias_map.get(r2, r2)
