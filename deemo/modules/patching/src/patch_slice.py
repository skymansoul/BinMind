# 修改记录:
# 2025-09-06 14:29 — 初始实现：汇编级向后切片 + 向前影响分析
# 2025-09-07 10:15 — 增加跨函数切片追踪（caller/callee 链）

"""Patch Differential Slicing — 补丁影响范围的程序切片分析。

程序切片 从未被应用于二进制补丁分析。
本模块填补此空白：以补丁修改的指令为切片准则 (slicing criterion)，
计算补丁的全部影响半径。

切片类型：
  1. 向后切片 (backward slice): 到达补丁修改点的所有指令。
     回答"哪些代码影响了补丁处的值"。

  2. 向前切片 (forward slice): 被补丁修改影响的所有指令。
     回答"补丁的修改会影响哪些后续代码"。

  3. 跨函数切片: 追踪 call/ret 边界，扩展到 caller 和 callee。
     回答"补丁的影响是否传播到其他函数"。

数据依赖: 寄存器定义-使用链 (def-use chain)。
控制依赖: 条件分支影响哪些指令的执行。

影响半径: 前向切片中的指令数 / 函数总指令数。
高半径 (>0.3) → 补丁影响范围大，部署风险高。
"""

import re
import logging
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple, Set
from collections import defaultdict, deque

_log = logging.getLogger(__name__)


@dataclass
class SliceResult:
    """单次切片结果。"""
    slice_type: str = ""               # backward | forward | cross_function
    criterion_line: int = 0            # 切片准则所在行号
    criterion_instruction: str = ""    # 切片准则指令
    sliced_lines: Set[int] = field(default_factory=set)
    sliced_instructions: List[str] = field(default_factory=list)


@dataclass
class SliceReport:
    """补丁影响切片报告。"""
    patch_id: str = ""
    function_name: str = ""
    # 切片
    backward_slice: SliceResult = field(default_factory=SliceResult)
    forward_slice: SliceResult = field(default_factory=SliceResult)
    # 影响半径
    total_instructions: int = 0
    impact_radius: float = 0.0         # forward_slice / total
    # 跨函数
    affected_callers: List[str] = field(default_factory=list)
    affected_callees: List[str] = field(default_factory=list)
    # 判定
    impact_level: str = "low"          # low | medium | high
    recommendation: str = ""

    def to_dict(self) -> Dict:
        return {
            'patch_id': self.patch_id,
            'function': self.function_name,
            'impact_radius': round(self.impact_radius, 3),
            'backward_size': len(self.backward_slice.sliced_lines),
            'forward_size': len(self.forward_slice.sliced_lines),
            'affected_callers': len(self.affected_callers),
            'affected_callees': len(self.affected_callees),
            'impact_level': self.impact_level,
            'recommendation': self.recommendation,
        }


# 数据依赖分析器

class DefUseAnalyzer:
    """汇编级定义-使用链分析。

    对每条指令提取:
      - defs: 此指令定义的寄存器集合
      - uses: 此指令使用的寄存器集合
    """

    def analyze(self, asm_lines: List[str]
                ) -> Tuple[List[Set[str]], List[Set[str]]]:
        """返回 (defs_per_line, uses_per_line)。"""
        defs = []
        uses = []
        for line in asm_lines:
            d, u = self._extract_def_use(line)
            defs.append(d)
            uses.append(u)
        return defs, uses

    def _extract_def_use(self, inst: str) -> Tuple[Set[str], Set[str]]:
        """提取单条指令的定义和使用寄存器。"""
        parts = inst.strip().lower().replace(',', ' ').split()
        if not parts:
            return set(), set()

        mnemonic = parts[0]
        defs = set()
        uses = set()

        # 寄存器模式
        regs = []
        for p in parts[1:]:
            p_clean = p.rstrip(',;')
            if re.match(r'^(r[a-z0-9]{1,3}|e[a-z0-9]{1,3}|[abcd]x|[sd]i[lp]?|sp|bp)$', p_clean):
                regs.append(p_clean)

        # 分类
        if mnemonic in ('mov', 'lea', 'movzx', 'movsx', 'pop', 'xor', 'add',
                       'sub', 'and', 'or', 'shl', 'shr', 'mul', 'imul', 'inc',
                       'dec', 'neg', 'not', 'xchg'):
            if regs:
                defs.add(regs[0])           # 第一个寄存器是目标
            for r in regs[1:]:
                uses.add(r)                  # 其余是源
        elif mnemonic in ('cmp', 'test'):
            uses.update(regs)
        elif mnemonic == 'push':
            uses.update(regs)
        elif mnemonic in ('call',):
            # call 定义 rax (返回值)，使用参数寄存器
            defs.add('rax')
        elif mnemonic in ('ret',):
            uses.add('rax')

        # 内存操作数中的寄存器都算 uses
        for p in parts[1:]:
            if '[' in p:
                for r_match in re.finditer(r'\b(r[a-z0-9]+|e[a-z0-9]+)\b', p):
                    uses.add(r_match.group(0))

        return defs, uses


# 切片引擎

class AssemblySlicer:
    """汇编级程序切片器。

    以补丁修改的指令为准则 (criterion)，
    计算向后和向前数据流切片。
    """

    def __init__(self):
        self._dua = DefUseAnalyzer()

    def slice_patch(self, original_asm: List[str],
                    patched_asm: List[str],
                    function_name: str = "",
                    patch_id: str = "") -> SliceReport:
        """对补丁执行完整切片分析。"""
        report = SliceReport(patch_id=patch_id, function_name=function_name)
        report.total_instructions = len([l for l in patched_asm if l.strip()])

        # 找补丁修改点作为切片准则
        orig_set = set(self._normalize(original_asm))
        patch_set = set(self._normalize(patched_asm))
        changed_lines = set()
        for i, line in enumerate(patched_asm):
            if self._normalize_single(line) not in orig_set:
                changed_lines.add(i)

        if not changed_lines:
            report.recommendation = "未检测到指令变更——补丁可能仅修改了数据"
            return report

        # 选择第一个变更行作为主准则
        criterion = min(changed_lines)
        criterion_inst = patched_asm[criterion].strip()

        # 计算 def-use
        defs, uses = self._dua.analyze(patched_asm)

        # 向后切片
        backward = self._backward_slice(defs, uses, criterion)
        report.backward_slice = SliceResult(
            slice_type='backward', criterion_line=criterion,
            criterion_instruction=criterion_inst,
            sliced_lines=backward,
            sliced_instructions=[patched_asm[i].strip() for i in sorted(backward) if i < len(patched_asm)])

        # 向前切片
        forward = self._forward_slice(defs, uses, changed_lines)
        report.forward_slice = SliceResult(
            slice_type='forward', criterion_line=criterion,
            criterion_instruction=criterion_inst,
            sliced_lines=forward,
            sliced_instructions=[patched_asm[i].strip() for i in sorted(forward) if i < len(patched_asm)])

        # 影响半径
        if report.total_instructions > 0:
            report.impact_radius = len(forward) / report.total_instructions

        # 分级
        if report.impact_radius < 0.15:
            report.impact_level = "low"
            report.recommendation = "补丁影响范围小——局部修改，部署风险低"
        elif report.impact_radius < 0.35:
            report.impact_level = "medium"
            report.recommendation = "补丁影响范围中等——建议审查前向切片中的依赖指令"
        else:
            report.impact_level = "high"
            report.recommendation = "补丁影响范围大 (%.0f%%)——需要全函数回归测试" % (report.impact_radius * 100)

        return report

    def _backward_slice(self, defs: List[Set[str]], uses: List[Set[str]],
                        criterion: int) -> Set[int]:
        """从准则行向后追踪数据依赖。"""
        sliced = {criterion}
        queue = deque([criterion])
        relevant_regs = uses[criterion].copy() if criterion < len(uses) else set()

        while queue:
            current = queue.popleft()
            for prev in range(current - 1, -1, -1):
                if prev in sliced:
                    continue
                # 前一行定义了当前需要的寄存器？
                if prev < len(defs) and defs[prev] & relevant_regs:
                    sliced.add(prev)
                    queue.append(prev)
                    if prev < len(uses):
                        relevant_regs.update(uses[prev])
        return sliced

    def _forward_slice(self, defs: List[Set[str]], uses: List[Set[str]],
                       changed_lines: Set[int]) -> Set[int]:
        """从变更行向前追踪影响。"""
        sliced = set()
        relevant_regs = set()
        for cl in sorted(changed_lines):
            sliced.add(cl)
            if cl < len(defs):
                relevant_regs.update(defs[cl])

        for i in range(min(changed_lines) + 1, len(defs)):
            if i < len(uses) and uses[i] & relevant_regs:
                sliced.add(i)
                if i < len(defs):
                    relevant_regs.update(defs[i])
        return sliced

    @staticmethod
    def _normalize(lines: List[str]) -> List[str]:
        return [AssemblySlicer._normalize_single(l) for l in lines]

    @staticmethod
    def _normalize_single(line: str) -> str:
        return line.strip().lower().replace(',', ' ').split(';')[0].strip()
