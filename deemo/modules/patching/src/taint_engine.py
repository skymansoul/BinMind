# 创建: 2026-07-16 09:30
# 轻量静态污点传播引擎 — 值域抽象替代纯正则检测

"""轻量污点传播引擎。

传统污点追踪（如 libdft, Triton）维护每字节的污点标签，开销大、
对间接调用和内存别名处理复杂。

本引擎采用 Mango 的值分析思路：
  不追踪"此字节是否被用户控制"，而是追踪"此寄存器的值域是什么"。
  污点被建模为"值域包含外部输入"。
  当值域退化为常量（如经过 cmp/and 净化后），自动去污。

值域表示：
  Interval(low, high): 整数区间，unknown 表示 [INT_MIN, INT_MAX]
  Pattern(regex): 字符串模式，如 "[0-9a-f]+" 表示已被净化

传播规则：
  mov dst, src     → dst.domain = src.domain
  add dst, imm     → dst.domain = dst.domain + imm
  and dst, mask    → dst.domain = dst.domain & mask (收窄)
  cmp dst, bound   → 不改变值域，但记录约束到路径条件

与 Mango 的差异：
  Mango 使用 Mangodfa（自定义数据流框架），本引擎使用
  基本块级别的摘要传播——精度稍低但对混淆更鲁棒。
"""

import re
import struct
import logging
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple, Set, Union
from enum import Enum

_log = logging.getLogger(__name__)


class DomainKind(str, Enum):
    UNKNOWN = "unknown"        # 完全未知值域
    INTERVAL = "interval"      # [low, high] 整数区间
    PATTERN = "pattern"        # 正则模式（字符串）
    CONSTANT = "constant"      # 单一常量值
    TAINTED = "tainted"        # 明确标记为外部输入


@dataclass
class ValueDomain:
    """值的抽象域。"""
    kind: DomainKind = DomainKind.UNKNOWN
    low: int = -2**63
    high: int = 2**63 - 1
    pattern: str = ""
    constant_value: int = 0
    is_tainted: bool = False
    source_location: str = ""   # 污点来源标识

    def constrain(self, op: str, rhs: 'ValueDomain') -> 'ValueDomain':
        """对值域施加约束后返回新值域。"""
        result = ValueDomain(kind=self.kind, low=self.low, high=self.high,
                            pattern=self.pattern, is_tainted=self.is_tainted)

        if rhs.kind == DomainKind.CONSTANT:
            c = rhs.constant_value
            if op == 'lt':
                result.high = min(result.high, c - 1)
            elif op == 'le':
                result.high = min(result.high, c)
            elif op == 'gt':
                result.low = max(result.low, c + 1)
            elif op == 'ge':
                result.low = max(result.low, c)
            elif op == 'eq':
                result.low = c; result.high = c; result.kind = DomainKind.CONSTANT
                result.constant_value = c
            elif op == 'and':
                if c > 0 and (c & (c - 1)) == 0:
                    result.high = min(result.high, c)
                    result.low = 0
        return result


@dataclass
class TaintState:
    """单点的污点状态——寄存器 + 内存的抽象值域。"""
    regs: Dict[str, ValueDomain] = field(default_factory=dict)
    memory: Dict[int, ValueDomain] = field(default_factory=dict)

    def copy(self) -> 'TaintState':
        return TaintState(regs=dict(self.regs), memory=dict(self.memory))


# 污点传播核心

class TaintEngine:
    """基于值域的轻量污点传播引擎。

    输入：汇编指令行列表 + 初始污点标记。
    输出：每个基本块的最终污点状态（寄存器/内存值域）。

    传播按基本块粒度进行——块内逐指令传播，块间在 CFG 边上合并。
    """

    # 外部输入入口 (source)
    _SOURCE_PATTERNS = [
        (re.compile(r'\bcall\s+read\b', re.I), 'rdi', 'read() fd'),
        (re.compile(r'\bcall\s+recv\b', re.I), 'rdi', 'recv() socket'),
        (re.compile(r'\bcall\s+fgets\b', re.I), 'rdi', 'fgets() buffer'),
        (re.compile(r'\bcall\s+scanf\b', re.I), 'rdi', 'scanf() input'),
        (re.compile(r'\bcall\s+recvfrom\b', re.I), 'rdi', 'recvfrom()'),
        (re.compile(r'\bcall\s+getenv\b', re.I), 'rax', 'getenv()'),
        (re.compile(r'\bcall\s+argv\b', re.I), 'rax', 'argv[]'),
    ]

    def __init__(self):
        self._state = TaintState()

    def propagate_block(self, instructions: List[str],
                        initial_state: TaintState = None) -> TaintState:
        """在基本块内逐指令传播污点。"""
        state = (initial_state or self._state).copy()

        for inst in instructions:
            stripped = inst.strip().lower().replace(',', ' ')
            if not stripped or stripped.startswith(';'):
                continue

            parts = stripped.split()
            if not parts:
                continue

            mnemonic = parts[0]

            # 检测 source
            for pat, target_reg, src_desc in self._SOURCE_PATTERNS:
                if pat.search(stripped):
                    state.regs[target_reg] = ValueDomain(
                        kind=DomainKind.TAINTED, is_tainted=True,
                        source_location=src_desc)

            # mov dst, src → dst = src
            if mnemonic in ('mov', 'movzx', 'movsx', 'lea'):
                dst, src = self._parse_dst_src(parts)
                if dst and src:
                    # 内存写入: mov [reg+off], src → 若src被污染，标记内存
                    if '[' in dst:
                        resolved = self._resolve_operand(src, state)
                        if resolved.is_tainted:
                            mem_addr = self._resolve_mem_addr(dst, state)
                            if mem_addr >= 0:
                                state.memory[mem_addr] = resolved
                    else:
                        state.regs[dst] = self._resolve_operand(src, state)

            # 算术运算
            elif mnemonic in ('add', 'sub', 'inc', 'dec'):
                dst, src = self._parse_dst_src(parts)
                if dst in state.regs:
                    d = state.regs[dst]
                    if src:
                        rhs = self._resolve_operand(src, state)
                        if rhs.kind == DomainKind.CONSTANT and d.kind == DomainKind.INTERVAL:
                            delta = rhs.constant_value
                            if mnemonic == 'sub':
                                delta = -delta
                            d.low += delta; d.high += delta
                    state.regs[dst] = d

            # 位掩码 → 收窄值域
            elif mnemonic in ('and',):
                dst, src = self._parse_dst_src(parts)
                if dst in state.regs and src:
                    rhs = self._resolve_operand(src, state)
                    state.regs[dst] = state.regs[dst].constrain('and', rhs)

            # 比较 → 更新路径约束（不改变当前值域）
            elif mnemonic in ('cmp', 'test'):
                pass  # 约束由 PathAnalyzer 在分支处处理

            # call → 将参数传给被调函数，返回值 taint
            elif mnemonic in ('call',):
                for param_reg in ['rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9']:
                    if param_reg in state.regs and state.regs[param_reg].is_tainted:
                        state.regs['rax'] = ValueDomain(
                            kind=DomainKind.TAINTED, is_tainted=True,
                            source_location='call arg propagation')
                        break

        return state

    def mark_source(self, reg: str, source_desc: str = ""):
        """手动标记寄存器为污点源。"""
        self._state.regs[reg] = ValueDomain(
            kind=DomainKind.TAINTED, is_tainted=True, source_location=source_desc)

    def get_state(self) -> TaintState:
        return self._state.copy()

# 辅助

    def _parse_dst_src(self, parts: List[str]) -> Tuple[Optional[str], Optional[str]]:
        if len(parts) >= 3:
            return parts[1].rstrip(','), parts[2]
        elif len(parts) >= 2:
            return parts[1].rstrip(','), None
        return None, None

    def _resolve_mem_addr(self, mem_operand: str, state: TaintState) -> int:
        """解析内存操作数 [reg+off] 为近似地址。"""
        mem_operand = mem_operand.strip().lstrip('[').rstrip(']')
        parts = mem_operand.replace('+', ' ').replace('-', ' -').split()
        base = 0
        for p in parts:
            p = p.strip()
            if not p:
                continue
            if re.match(r'^(r[a-z0-9]+|e[a-z0-9]+)$', p.lower()):
                if p.lower() in state.regs:
                    d = state.regs[p.lower()]
                    if d.kind == DomainKind.CONSTANT:
                        base += d.constant_value
            elif re.match(r'^-?[\dxabcdef]+$', p, re.I):
                try:
                    base += int(p, 16) if p.lower().startswith('0x') else int(p)
                except ValueError:
                    pass
        return base if base != 0 else -1

    def _resolve_operand(self, op: str, state: TaintState) -> ValueDomain:
        """将操作数解析为值域。"""
        op = op.rstrip(',;').strip()
        # 寄存器
        if re.match(r'^(r[a-z0-9]{1,3}|e[a-z0-9]{1,3}|[abcd]x|[sd]i[lp]?)$', op.lower()):
            return state.regs.get(op.lower(), ValueDomain())
        # 立即数
        m = re.match(r'^(0x[0-9a-f]+|\d+)$', op, re.I)
        if m:
            v = int(m.group(1), 16) if m.group(1).lower().startswith('0x') else int(m.group(1))
            return ValueDomain(kind=DomainKind.CONSTANT, constant_value=v, low=v, high=v)
        return ValueDomain()
