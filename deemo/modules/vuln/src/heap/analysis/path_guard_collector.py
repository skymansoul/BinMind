"""路径守卫收集器 — 从 x86-64 指令流中提取 cmp+jcc 守卫条件.

创建: 2026-05-22

核心算法:
  扫描指令流中的 cmp/test + 条件跳转对, 提取为 (reg, op, const) 形式的守卫条件.
  这些守卫条件随后被 value_range_narrowing.py 用于约束值区间.

设计决策:
  - 为什么不做完整的 CFG 路径分析:
    构建 CFG 需要两遍扫描且对间接跳转脆弱. 单遍守卫收集虽然会包含不可达路径的守卫,
    但配合 value_range_narrowing 的 conservative-intersect 策略 (对同一 reg 的多条
    守卫取其约束最紧者), 能在不丢失安全性的前提下缩小值范围.
  - 为什么同时收集 alloc-site 守卫和 write-site 守卫:
    alloc-site 守卫约束 malloc 的 size → 证明"分配了足够空间";
    write-site 守卫约束 memcpy 的 size → 证明"写入不超过分配量".
    两者互补.
"""
from __future__ import annotations

import re as _re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
from enum import Enum, auto


class GuardOp(Enum):
    """守卫比较操作符 — 从 x86 jcc 指令映射."""
    LE = auto()   # jbe/jle → unsigned/signed ≤
    LT = auto()   # jb/jl   → unsigned/signed <
    GE = auto()   # jae/jge → unsigned/signed ≥
    GT = auto()   # ja/jg   → unsigned/signed >
    EQ = auto()   # je      → ==
    NE = auto()   # jne     → ≠


# jcc 助记符 → GuardOp 映射
_JCC_TO_GUARDOP = {
    'jbe': GuardOp.LE, 'jle': GuardOp.LE,
    'jb':  GuardOp.LT, 'jl':  GuardOp.LT,
    'jae': GuardOp.GE, 'jge': GuardOp.GE,
    'ja':  GuardOp.GT, 'jg':  GuardOp.GT,
    'je':  GuardOp.EQ, 'jz':  GuardOp.EQ,
    'jne': GuardOp.NE, 'jnz': GuardOp.NE,
}


@dataclass
class PathGuard:
    """一条从条件分支中提取的路径守卫.

    语义: 在守卫生效的路径上, cmp/test 操作成立的条件.
    例如: cmp eax, 64; jbe label → reg='eax', op=LE, const=64
         含义: eax ≤ 64 在本分支路径上成立
    """
    reg: str                       # 被比较的寄存器 (小写规范化)
    op: GuardOp                    # 比较操作符
    const: int                     # 比较常数
    insn_addr: int                 # cmp/test 指令地址
    is_signed: bool = False        # 是否基于有符号标志位
    # 守卫覆盖的指令范围 (从 cmp 到 jcc 目标)
    target_addr: int = 0           # jcc 的目标地址 (守卫生效处)
    fallthrough: bool = True       # True=直落路径(守卫成立), False=跳转路径(守卫成立)
    confidence: float = 0.9        # 置信度 (间接跳转→降低置信度)

    def describe(self) -> str:
        op_map = {GuardOp.LE: '≤', GuardOp.LT: '<', GuardOp.GE: '≥',
                  GuardOp.GT: '>', GuardOp.EQ: '=', GuardOp.NE: '≠'}
        return f'{self.reg} {op_map.get(self.op, "?")} {self.const}'


# cmp reg, const 模式
_CMP_REG_CONST = _re.compile(
    r'cmp\s+(\w+),\s*(0x[0-9a-f]+|\d+)', _re.I)
# cmp reg, reg 模式 (寄存器比较)
_CMP_REG_REG = _re.compile(
    r'cmp\s+(\w+),\s*(\w+)', _re.I)
# test reg, reg
_TEST_REG = _re.compile(
    r'test\s+(\w+),\s*(\w+)', _re.I)


def collect_guards(instructions: List[str],
                   addrs: Optional[List[int]] = None
                   ) -> List[PathGuard]:
    """从指令流中提取所有 cmp+jcc 守卫条件.

    返回值可用于: 对任意指令地址查询其上游的守卫集合,
    从而缩小对应寄存器的值范围.
    """
    guards: List[PathGuard] = []

    for i, instr in enumerate(instructions):
        il = instr.strip().lower()

        # 寻找 cmp/test 指令
        cmp_m = _CMP_REG_CONST.match(il)
        cmp_rr = _CMP_REG_REG.match(il) if not cmp_m else None
        test_m = _TEST_REG.match(il) if not cmp_m else None

        if cmp_m:
            reg = _normalize_reg(cmp_m.group(1))
            const = int(cmp_m.group(2), 16 if '0x' in cmp_m.group(2) else 10)
            _extract_jcc_guard(instructions, i, reg, const, addrs, guards)
        elif cmp_rr:
            # reg-reg 比较: 仅当两寄存器相同且有 jcc 时提取 (test 语义)
            r1 = _normalize_reg(cmp_rr.group(1))
            r2 = _normalize_reg(cmp_rr.group(2))
            if r1 == r2:
                _extract_jcc_guard(instructions, i, r1, 0, addrs, guards)
        elif test_m:
            r1 = _normalize_reg(test_m.group(1))
            r2 = _normalize_reg(test_m.group(2))
            if r1 == r2:
                _extract_jcc_guard(instructions, i, r1, 0, addrs, guards)

    return guards


def _extract_jcc_guard(instructions: List[str], cmp_idx: int,
                       reg: str, const: int,
                       addrs: Optional[List[int]],
                       guards: List[PathGuard]) -> None:
    """从 cmp 指令后向查找对应的 jcc 指令, 生成 PathGuard."""
    end = min(cmp_idx + 6, len(instructions))
    for j in range(cmp_idx + 1, end):
        jl = instructions[j].strip().lower()
        # 匹配 jcc 助记符
        for jcc_str, gop in _JCC_TO_GUARDOP.items():
            if jl.startswith(jcc_str):
                target = _extract_jcc_target(instructions[j])
                addr = (addrs[cmp_idx]
                        if (addrs and cmp_idx < len(addrs)) else cmp_idx)
                is_signed = jcc_str in ('jl', 'jle', 'jg', 'jge')

                # 直落路径: 守卫在 cmp_addr+fallthrough 成立
                guards.append(PathGuard(
                    reg=reg, op=gop, const=const,
                    insn_addr=addr,
                    is_signed=is_signed,
                    target_addr=target,
                    fallthrough=True,
                ))
                # 跳转路径: 取反
                guards.append(PathGuard(
                    reg=reg, op=_negate_op(gop), const=const,
                    insn_addr=addr,
                    is_signed=is_signed,
                    target_addr=target,
                    fallthrough=False,
                ))
                return


def _extract_jcc_target(instr: str) -> int:
    """从 jcc 指令中提取目标地址."""
    m = _re.search(r'(0x[0-9a-f]+)', instr, _re.I)
    return int(m.group(1), 16) if m else 0


def _negate_op(op: GuardOp) -> GuardOp:
    """取反比较操作符 (跳转路径用)."""
    return {
        GuardOp.LE: GuardOp.GT, GuardOp.LT: GuardOp.GE,
        GuardOp.GE: GuardOp.LT, GuardOp.GT: GuardOp.LE,
        GuardOp.EQ: GuardOp.NE, GuardOp.NE: GuardOp.EQ,
    }.get(op, op)


def _normalize_reg(reg: str) -> str:
    """规范化寄存器名: 去前缀, 取公共名."""
    r = reg.lower()
    # 64-bit: rax,rbx,... → 32-bit: eax,ebx,... → 16-bit: ax,bx,...
    _MAP = {
        'rax': 'rax', 'eax': 'rax', 'ax': 'rax', 'al': 'rax',
        'rbx': 'rbx', 'ebx': 'rbx', 'bx': 'rbx', 'bl': 'rbx',
        'rcx': 'rcx', 'ecx': 'rcx', 'cx': 'rcx', 'cl': 'rcx',
        'rdx': 'rdx', 'edx': 'rdx', 'dx': 'rdx', 'dl': 'rdx',
        'rsi': 'rsi', 'esi': 'rsi', 'si': 'rsi', 'sil': 'rsi',
        'rdi': 'rdi', 'edi': 'rdi', 'di': 'rdi', 'dil': 'rdi',
        'r8': 'r8', 'r8d': 'r8', 'r8w': 'r8', 'r8b': 'r8',
        'r9': 'r9', 'r9d': 'r9', 'r9w': 'r9', 'r9b': 'r9',
        'r10': 'r10', 'r10d': 'r10', 'r10w': 'r10', 'r10b': 'r10',
        'r11': 'r11', 'r11d': 'r11', 'r11w': 'r11', 'r11b': 'r11',
        'r12': 'r12', 'r12d': 'r12', 'r12w': 'r12', 'r12b': 'r12',
        'r13': 'r13', 'r13d': 'r13', 'r13w': 'r13', 'r13b': 'r13',
        'r14': 'r14', 'r14d': 'r14', 'r14w': 'r14', 'r14b': 'r14',
        'r15': 'r15', 'r15d': 'r15', 'r15w': 'r15', 'r15b': 'r15',
    }
    return _MAP.get(r, r)


def guards_for_insn(guards: List[PathGuard],
                    insn_addr: int,
                    addrs: Optional[List[int]] = None,
                    ) -> Dict[str, List[PathGuard]]:
    """查询某条指令的上游路径守卫, 按寄存器分组.

    返回 {reg: [guard1, guard2, ...]}, 其中每个 guard 是
    覆盖该指令地址的路径守卫.
    """
    result: Dict[str, List[PathGuard]] = {}
    for g in guards:
        # 守卫覆盖范围: 从 cmp 到 下一个守卫之间
        # 简化: 守卫在 5 条指令内且在 fallthrough 路径上 → 覆盖
        if g.fallthrough and abs(g.insn_addr - insn_addr) <= 5:
            result.setdefault(g.reg, []).append(g)
    return result
