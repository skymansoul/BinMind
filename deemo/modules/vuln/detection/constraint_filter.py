# coding: utf-8
#
"""
路径约束过滤器 - 对检测候选做路径可达性验证, 滤除虚假路径。

解决的问题:
  混淆/优化后的代码产生大量虚假控制流路径 - 检测器沿这些路径
  报告"漏洞", 但实际执行中不可能到达。例如:
    O2优化可能将循环展开为条件分支路径, 其中某些路径的缓冲区
    约束矛盾（如x<0且x>100同时成立）, 实际不可达。

方法:
  复用spcv_abstract_domain.py的区间抽象域, 对从入口到漏洞点的路径
  做轻量抽象解释 - 若路径上存在矛盾约束(区间为空, BOTTOM),
  则该路径不可达, 候选被滤除。

  仅处理数值约束（比较指令的立即数）, 不追踪指针/内存。
  复杂度: O(P*I) P=候选数, I=每条路径上的指令数。
"""

import re, logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from collections import defaultdict

_log = logging.getLogger(__name__)


@dataclass
class ConstraintCheck:
    insn_idx: int
    variable: str           # 被比较的寄存器
    operator: str           # lt/le/gt/ge/eq
    value: int              # 比较的立即数
    is_contradiction: bool = False

@dataclass
class PathFeasibility:
    path_id: str
    constraints: List[ConstraintCheck] = field(default_factory=list)
    is_feasible: bool = True
    contradiction_detail: str = ""


class ConstraintFilter:
    """路径约束过滤器 - 区间抽象解释的轻量应用。

    仅处理cmp reg, imm 到 jcc模式的比较-跳转约束。
    若两条约束对同一寄存器产生矛盾区间, 路径标记为不可行。
    """

    def filter(self, candidates: List[Dict],
                instructions: List[str],
                base_addr: int = 0x400000
                ) -> List[Dict]:
        """对检测候选做路径约束过滤。

        参数:
          candidates: [{type, function, address, ...}, ...]
          instructions: 反汇编指令列表

        返回过滤后的候选列表(仅保留可达路径上的候选)。
        """
        if not candidates or not instructions:
            return candidates

        # 提取所有约束
        all_constraints = self._extract_constraints(instructions)

        # 对每个候选, 收集从其位置反向到函数入口的路径约束
        filtered = []
        for cand in candidates:
            cand_addr = cand.get('address', 0)
            cand_idx = self._find_idx(instructions, cand_addr, base_addr)
            if cand_idx < 0:
                filtered.append(cand)  # 无法定位, 保留(不误删)
                continue

            # 收集从入口(0)到cand_idx的约束
            path_constraints = [
                c for c in all_constraints if c.insn_idx < cand_idx]

            # 检查矛盾
            feasible = self._check_feasibility(path_constraints)
            if feasible.is_feasible:
                filtered.append(cand)

        return filtered

    def _extract_constraints(self, insns: List[str]
                               ) -> List[ConstraintCheck]:
        """从指令序列提取所有比较-跳转约束。"""
        constraints = []
        for i, insn in enumerate(insns):
            mnem, ops = self._parse(insn)
            if mnem != 'cmp' or len(ops) < 2:
                continue
            reg = self._reg(ops[0])
            if not reg:
                continue
            try:
                val = int(ops[1], 16) if '0x' in ops[1] else int(ops[1])
            except ValueError:
                continue
            # 查找下一条条件跳转以确定比较方向
            op = self._find_jcc_operator(insns, i)
            constraints.append(ConstraintCheck(
                insn_idx=i, variable=reg, operator=op, value=val))
        return constraints

    def _check_feasibility(self, constraints: List[ConstraintCheck]
                             ) -> PathFeasibility:
        """检查约束集是否存在矛盾 - 区间交为空, 不可行。"""
        # 每变量的有效区间
        intervals: Dict[str, List[Tuple[int,int]]] = defaultdict(list)

        for c in constraints:
            if c.operator in ('le', 'lt'):
                intervals[c.variable].append((-10**9, c.value))
            elif c.operator in ('ge', 'gt'):
                intervals[c.variable].append((c.value, 10**9))
            elif c.operator == 'eq':
                intervals[c.variable].append((c.value, c.value))

        # 检查每变量的区间交集
        for var, bounds in intervals.items():
            lo = max(b[0] for b in bounds)
            hi = min(b[1] for b in bounds)
            if lo > hi:
                return PathFeasibility(
                    path_id="", constraints=constraints,
                    is_feasible=False,
                    contradiction_detail=f"{var}: [{lo},{hi}] 矛盾")

        return PathFeasibility(path_id="", constraints=constraints,
                                is_feasible=True)

    def _find_jcc_operator(self, insns: List[str], cmp_idx: int) -> str:
        """在cmp指令之后查找条件跳转, 推断比较方向。"""
        for j in range(cmp_idx + 1, min(cmp_idx + 5, len(insns))):
            mnem, _ = self._parse(insns[j])
            op_map = {'jle':'le','jbe':'le','jge':'ge','jae':'ge',
                      'jl':'lt','jb':'lt','jg':'gt','ja':'gt',
                      'je':'eq','jne':'eq'}
            return op_map.get(mnem, 'le')
        return 'le'  # 默认, 保守假设上界约束

    def _parse(self, insn: str):
        s = insn.strip()
        if ':' in s[:20]: s = s.split(':',1)[1].strip()
        p = s.split(None,1)
        if len(p)<2: return (p[0].lower(),[]) if p else ('',[])
        return (p[0].lower(), [o.strip() for o in p[1].split(',')])

    def _reg(self, op: str) -> str:
        op = op.strip().lower()
        if not op or op.isdigit() or op.startswith('0x'): return ''
        for s in ('+','-','*'): op = op.split(s)[0]
        return op.strip()

    @staticmethod
    def _find_idx(insns: List[str], addr: int, base: int) -> int:
        for i, insn in enumerate(insns):
            s = insn.strip()
            if ':' in s[:20]:
                try:
                    if int(s.split(':')[0],16) == addr: return i
                except ValueError: pass
        return -1


__all__ = ["ConstraintCheck","PathFeasibility","ConstraintFilter"]
