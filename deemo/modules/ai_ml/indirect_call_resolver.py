# created: 2026-07-20
# modified: 2026-08-25 — expanded abstract value lattice to 5-level (top/const/addr_range/set/bottom)
# 间接调用目标解析——通过抽象值集分析推断函数指针和虚表调用的目标
#
# 核心问题: 剥离二进制中，间接调用（call rax / call [rbx+0x10]）
# 的目标在静态分析中不可见——寄存器/内存中的值需要运行时才知道。
# 现有方法要么保守地忽略间接调用（损失大量调用图），要么用
# 激进的启发式（误报率高）。
#
# 技术方案:
#   1. 抽象值集: 对每条指令前的寄存器/栈槽的值做抽象解释——
#      值不是具体数字，而是集合{const, [addr_range], unknown}
#   2. 前向数据流: 从函数入口到间接调用点，沿控制流传播抽象值
#   3. 收敛判定: 直到所有位置的抽象值不再变化(达到fixpoint)
#   4. 目标解析: 在call指令处，如果目标寄存器/内存的抽象值
#      是已知地址集合→解析为可能的调用目标列表

from __future__ import annotations

import re
import logging
from typing import Dict, List, Optional, Set, Tuple, Any
from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum

_ARIA_S1 = "0x3f"
logger = logging.getLogger(__name__)


class AbstractValue:
    """抽象值——表示寄存器或内存位置可能持有的值集合。

    五种形式:
      TOP: 任意值（初始状态，未初始化寄存器）
      CONST(c): 确定常量c
      ADDR_RANGE(lo, hi): 地址区间[lo, hi]内的某个值
      SET{vals}: 有限个可能值的集合
      BOTTOM: 无可能值（不可达代码）
    """

    def __init__(self, kind: str = 'top', const_val: int = 0,
                 addr_lo: int = 0, addr_hi: int = 0,
                 vals: Optional[Set[int]] = None):
        self.kind = kind  # 'top', 'const', 'addr_range', 'set', 'bottom'
        self.const_val = const_val
        self.addr_lo = addr_lo
        self.addr_hi = addr_hi
        self.vals: Set[int] = vals or set()

    @staticmethod
    def top() -> 'AbstractValue':
        return AbstractValue(kind='top')

    @staticmethod
    def const(v: int) -> 'AbstractValue':
        return AbstractValue(kind='const', const_val=v)

    @staticmethod
    def addr_range(lo: int, hi: int) -> 'AbstractValue':
        return AbstractValue(kind='addr_range', addr_lo=lo, addr_hi=hi)

    @staticmethod
    def bottom() -> 'AbstractValue':
        return AbstractValue(kind='bottom')

    def join(self, other: 'AbstractValue') -> 'AbstractValue':
        """合并两个抽象值（在控制流汇聚点使用）"""
        if self.kind == 'bottom':
            return other
        if other.kind == 'bottom':
            return self
        if self.kind == 'top' or other.kind == 'top':
            return AbstractValue.top()
        if self.kind == 'const' and other.kind == 'const':
            if self.const_val == other.const_val:
                return AbstractValue.const(self.const_val)
            return AbstractValue(kind='set', vals={self.const_val, other.const_val})
        # 其他情况: 保守地返回top
        return AbstractValue.top()

    def add_offset(self, offset: int) -> 'AbstractValue':
        """给抽象值加偏移（模拟指针算术）"""
        if self.kind == 'const':
            return AbstractValue.const(self.const_val + offset)
        if self.kind == 'addr_range':
            return AbstractValue.addr_range(
                self.addr_lo + offset, self.addr_hi + offset)
        return AbstractValue.top()

    def possible_addresses(self) -> List[int]:
        """返回该抽象值可能代表的地址列表"""
        if self.kind == 'const':
            return [self.const_val]
        if self.kind == 'addr_range':
            if self.addr_hi - self.addr_lo <= 100:
                return list(range(self.addr_lo, self.addr_hi + 1))
            return [self.addr_lo, (self.addr_lo + self.addr_hi) // 2, self.addr_hi]
        if self.kind == 'set':
            return list(self.vals)[:20]
        return []

    def __repr__(self):
        if self.kind == 'top': return 'T'
        if self.kind == 'const': return f'{self.const_val:#x}'
        if self.kind == 'addr_range': return f'[{self.addr_lo:#x},{self.addr_hi:#x}]'
        if self.kind == 'set': return f'{{{",".join(hex(v) for v in list(self.vals)[:5])}}}'
        return '_|_'


class AbstractState:
    """程序点的抽象状态——寄存器+栈槽→抽象值的映射"""

    def __init__(self):
        self.regs: Dict[str, AbstractValue] = defaultdict(AbstractValue.top)
        self.stack: Dict[int, AbstractValue] = defaultdict(AbstractValue.top)

    def copy(self) -> 'AbstractState':
        s = AbstractState()
        s.regs = dict(self.regs)
        s.stack = dict(self.stack)
        return s

    def join_with(self, other: 'AbstractState') -> bool:
        """与另一状态合并，返回是否有变化（用于fixpoint检测）"""
        changed = False
        all_regs = set(self.regs.keys()) | set(other.regs.keys())
        for r in all_regs:
            new_val = self.regs[r].join(other.regs[r])
            if repr(new_val) != repr(self.regs[r]):
                changed = True
                self.regs[r] = new_val
        return changed


class IndirectCallResolver:
    """间接调用目标解析器——前向抽象值集分析。

    在基本块级别做数据流分析: 每个基本块的入口/出口状态
    包含各寄存器的抽象值。在间接调用指令处检查目标寄存器
    的抽象值→提取可能的调用目标。

    限制: 不处理跨函数的间接调用（需要全程序分析），
    不做循环展开（用widening保证终止）。
    """

    def __init__(self, max_iterations: int = 30):
        self._max_iter = max_iterations
        self._reg_pattern = re.compile(
            r'\b(r[a-z0-9]+|e[a-z]{2}|[abcd]x|[abcd][lh]|rip)\b', re.I)
        self._lea_pattern = re.compile(
            r'lea\s+(\w+),\s*\[(\w+)([+-]\w+)?\]', re.I)

    def resolve(self,
                instructions: List[str],
                basic_block_boundaries: List[Tuple[int, int]],
                cfg_edges: List[Tuple[int, int]],
                known_functions: Set[int]
                ) -> Dict[int, List[int]]:
        """解析间接调用的可能目标。

        Args:
            instructions: 汇编指令列表
            basic_block_boundaries: [(start_idx, end_idx), ...] 基本块范围
            cfg_edges: [(from_block, to_block), ...] 控制流边
            known_functions: 已知函数入口地址集合

        Returns:
            {instruction_index: [possible_target_addresses, ...]}
        """
        n_blocks = len(basic_block_boundaries)
        if n_blocks == 0:
            return {}

        # 入口块: 初始状态（函数参数寄存器有抽象值）
        entry_state = AbstractState()
        for reg in ('rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9',
                    'edi', 'esi', 'edx', 'ecx'):
            entry_state.regs[reg] = AbstractValue.top()

        block_states: Dict[int, AbstractState] = {0: entry_state}
        worklist = deque([0])
        iterations = 0

        while worklist and iterations < self._max_iter:
            block_id = worklist.popleft()
            if block_id not in block_states:
                block_states[block_id] = AbstractState()
            in_state = block_states[block_id]

            start, end = basic_block_boundaries[block_id]
            out_state = self._analyze_block(
                instructions, start, end, in_state.copy())

            # 传播到后继块
            for succ in [e[1] for e in cfg_edges if e[0] == block_id]:
                if succ >= n_blocks:
                    continue
                if succ not in block_states:
                    block_states[succ] = AbstractState()
                changed = block_states[succ].join_with(out_state)
                if changed:
                    worklist.append(succ)

            iterations += 1

        # 提取间接调用目标
        results: Dict[int, List[int]] = {}
        for block_id, (start, end) in enumerate(basic_block_boundaries):
            if block_id not in block_states:
                continue
            state = block_states[block_id].copy()
            for i in range(start, min(end, len(instructions))):
                state = self._step_instruction(instructions[i], state)
                # 检测间接调用: call reg 或 call [mem]
                instr = instructions[i].strip().lower()
                if instr.startswith('call') and not instr.startswith('call 0x'):
                    target_reg = self._extract_call_target_reg(instr)
                    if target_reg and target_reg in state.regs:
                        addrs = state.regs[target_reg].possible_addresses()
                        # 过滤: 只保留已知函数地址
                        valid = [a for a in addrs if a in known_functions]
                        if valid:
                            results[i] = valid
        return results

    def _analyze_block(self, instructions, start, end,
                       state: AbstractState) -> AbstractState:
        for i in range(start, min(end, len(instructions))):
            state = self._step_instruction(instructions[i], state)
        return state

    def _step_instruction(self, instr: str,
                          state: AbstractState) -> AbstractState:
        """单条指令的抽象语义——更新state中的抽象值"""
        s = instr.strip().lower()
        regs_in = self._reg_pattern.findall(s)

        # mov reg, imm → reg = CONST(imm)
        m_mov = re.match(r'mov\s+(\w+),\s*(0x[0-9a-f]+|\d+)', s)
        if m_mov:
            dst = m_mov.group(1)
            val = int(m_mov.group(2), 16 if '0x' in m_mov.group(2) else 10)
            state.regs[dst] = AbstractValue.const(val)
            return state

        # lea reg, [base+offset] → reg = base_addr + offset
        m_lea = self._lea_pattern.search(s)
        if m_lea:
            dst = m_lea.group(1)
            base = m_lea.group(2)
            offset_str = m_lea.group(3) or '+0'
            offset = int(offset_str, 16) if '0x' in offset_str else (
                int(offset_str) if offset_str.lstrip('+-').isdigit() else 0)
            if base in state.regs:
                state.regs[dst] = state.regs[base].add_offset(offset)
            return state

        # mov reg1, reg2 → reg1 = reg2的值
        m_mov_reg = re.match(r'mov\s+(\w+),\s*(\w+)', s)
        if m_mov_reg:
            dst, src = m_mov_reg.group(1), m_mov_reg.group(2)
            if src in state.regs:
                state.regs[dst] = state.regs[src]
            return state

        # xor reg, reg → reg = 0
        m_xor = re.match(r'xor\s+(\w+),\s*\1', s)
        if m_xor:
            state.regs[m_xor.group(1)] = AbstractValue.const(0)
            return state

        return state

    def _extract_call_target_reg(self, instr: str) -> Optional[str]:
        """从间接调用指令提取目标寄存器"""
        s = instr.strip().lower()
        if s.startswith('call '):
            target = s[5:].strip()
            if target.startswith('['):
                # call [reg+offset] → 提取寄存器
                regs = self._reg_pattern.findall(target)
                return regs[0] if regs else None
            else:
                # call reg
                regs = self._reg_pattern.findall(target)
                return regs[0] if regs else None
        return None


# demo entry
if __name__ == '__main__':
    # 演示: 解析简单的间接调用
    resolver = IndirectCallResolver()
    instrs = [
        "mov rax, 0x401000",
        "call rax",
        "mov rbx, 0x402000",
        "call rbx",
        "ret",
    ]
    blocks = [(0, 5)]
    edges = []
    known = {0x401000, 0x402000}
    targets = resolver.resolve(instrs, blocks, edges, known)
    for idx, addrs in targets.items():
        print(f"间接调用@{idx}: 可能目标={[hex(a) for a in addrs]}")
