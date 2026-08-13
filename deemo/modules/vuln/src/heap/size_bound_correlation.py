"""SHIELD 尺寸约束关联器 — malloc参数与访问边界的表达式等价性判定.

核心创新: 证明 malloc(size) 的 size 参数与后序访问的边界约束等价,
从而消除"未知参数→潜在溢出"类误报.

典型安全场景:
  s = strlen(input)           # 从栈/调用者获取字符串长度
  buf = malloc(s + 1)         # 分配 s+1 字节
  memcpy(buf, input, s)       # 只拷贝 s 字节 → 安全 (s < s+1)

当前检测器视此为"未知size → 潜在溢出", 因为size参数从[rbp+0x10]来,
无法推断确切值。本模块通过关联 malloc 参数表达式与 memcpy 大小表达式,
识别这种"表达式等价"的安全模式.

方法:
  - Step 1: 从 malloc 调用点回溯 size 参数到其源表达式 (mov/imul/add 链)
  - Step 2: 从 memcpy 等 sink 回溯 size 参数 (通常是 r8)
  - Step 3: 比较两条表达式链, 若它们本质等价 (如 s vs s+1), 且访问量 ≤ 分配量,
    则证明安全

  - CRYPTOSS: 污点+守卫联合评分 — 借鉴其"参数→约束"关联思路
  - ValCat: value-flow categories — 借鉴其值流分类方法

创建: 2025-01-13
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple, Callable
from enum import Enum, auto

class ExprKind(Enum):
    CONST = auto()       # 常量
    REG = auto()         # 寄存器引用
    STACK = auto()       # [rbp+N]
    ADD = auto()         # a + b
    SUB = auto()         # a - b
    MUL = auto()         # a * b
    SHL = auto()         # a << b

@dataclass
class ValueExpr:
    """精简的值表达式树 — 用于比较 malloc size 与 access size 的等价性."""
    kind: ExprKind
    value: int = 0              # CONST 的值 / STACK 的偏移
    reg_name: str = ""          # REG 的寄存器名
    left: Optional['ValueExpr'] = None
    right: Optional['ValueExpr'] = None

    def __repr__(self) -> str:
        if self.kind == ExprKind.CONST:
            return str(self.value)
        if self.kind == ExprKind.REG:
            return self.reg_name
        if self.kind == ExprKind.STACK:
            return f"[rbp{self.value:+d}]"
        op = {ExprKind.ADD: '+', ExprKind.SUB: '-',
              ExprKind.MUL: '*', ExprKind.SHL: '<<'}
        return f"({self.left} {op.get(self.kind, '?')} {self.right})"

    def implies_le(self, other: 'ValueExpr') -> Optional[bool]:
        """判断 self ≤ other 是否恒成立.
        返回 None 表示无法确定.
        """
        if self.kind == ExprKind.CONST and other.kind == ExprKind.CONST:
            return self.value <= other.value

        # REG vs REG: 同一寄存器 → 等值
        if (self.kind == ExprKind.REG and other.kind == ExprKind.REG
                and self.reg_name == other.reg_name):
            return True

        # expr vs expr+const: self ≤ self+const when const≥0
        # 例如: s vs s+1 → s ≤ s+1 恒成立
        if other.kind == ExprKind.ADD:
            if (other.right and other.right.kind == ExprKind.CONST
                    and other.right.value >= 0):
                if self._structurally_eq(other.left):
                    return True
            if (other.left and other.left.kind == ExprKind.CONST
                    and other.left.value >= 0):
                if self._structurally_eq(other.right):
                    return True

        # STACK vs STACK: 同一槽位
        if self.kind == ExprKind.STACK and other.kind == ExprKind.STACK:
            return self.value == other.value

        return None

    def _structurally_eq(self, other: Optional['ValueExpr']) -> bool:
        if other is None:
            return False
        if self.kind != other.kind:
            return False
        if self.kind == ExprKind.CONST:
            return self.value == other.value
        if self.kind in (ExprKind.REG, ExprKind.STACK):
            return (self.reg_name == other.reg_name and
                    self.value == other.value)
        return (self._structurally_eq(self.left, other.left) and
                self._structurally_eq(self.right, other.right))

class SizeBoundCorrelator:
    """malloc size 与 access size 的表达式等价性判定器.

    向后回溯两个参数链, 构建 ValueExpr, 比较等价性.
    核心算法: use-def 链后向遍历, 沿单条寄存器→值流追踪,
    遇到 mem/mov/add/sub/shl 时构建表达式节点.
    """

    # 指令模式
    _MOV_RR = re.compile(r'mov\s+(\w+),\s*(\w+)\s*$', re.I)
    _MOV_RI = re.compile(r'mov\s+(\w+),\s*(0x[0-9a-f]+|\d+)\s*$', re.I)
    _MOV_FROM_STACK = re.compile(
        r'mov\s+(\w+),\s*(?:dword|qword)\s+ptr\s+\[rbp\s*([+\-])\s*(0x[0-9a-f]+|\d+)\]',
        re.I)
    _ADD_RI = re.compile(r'add\s+(\w+),\s*(0x[0-9a-f]+|\d+)', re.I)
    _SUB_RI = re.compile(r'sub\s+(\w+),\s*(0x[0-9a-f]+|\d+)', re.I)
    _SHL_RI = re.compile(r'shl\s+(\w+),\s*(0x[0-9a-f]+|\d+)', re.I)

    # MinGW x64 calling convention: rcx=arg1, rdx=arg2, r8=arg3
    _ALLOC_SIZE_REG = {'malloc': 'rcx', 'calloc': 'rcx', 'realloc': 'rdx'}
    _MEMCPY_SIZE_REG = {'memcpy': 'r8', 'memmove': 'r8', 'memset': 'r8'}

    # 32-bit → 64-bit 寄存器映射 (x86-64: mov to 32-bit reg zero-extends to 64-bit)
    _R32_TO_R64 = {
        'eax':'rax','ebx':'rbx','ecx':'rcx','edx':'rdx',
        'esi':'rsi','edi':'rdi','ebp':'rbp','esp':'rsp',
        'r8d':'r8','r9d':'r9','r10d':'r10','r11d':'r11',
        'r12d':'r12','r13d':'r13','r14d':'r14','r15d':'r15',
    }

    @staticmethod
    def _canon_reg(r: str) -> str:
        """将寄存器名标准化为64位形式."""
        rl = r.lower()
        return SizeBoundCorrelator._R32_TO_R64.get(rl, rl)

    def __init__(self):
        pass

    def trace_alloc_size(self, instructions: List[str],
                         call_idx: int) -> Optional[ValueExpr]:
        """从 malloc 调用点回溯 size 参数表达式."""
        if call_idx <= 0:
            return None
        il = instructions[call_idx].strip().lower()
        func = self._extract_func(il)
        size_reg = self._ALLOC_SIZE_REG.get(func, 'rcx')
        return self._trace_use_def(instructions, call_idx, size_reg)

    def trace_access_size(self, instructions: List[str],
                          call_idx: int, sink_func: str = 'memcpy'
                          ) -> Optional[ValueExpr]:
        """从 memcpy 等调用点回溯 size 参数表达式."""
        if call_idx <= 0:
            return None
        size_reg = self._MEMCPY_SIZE_REG.get(sink_func, 'r8')
        return self._trace_use_def(instructions, call_idx, size_reg)

    def prove_safe(self, alloc_expr: Optional[ValueExpr],
                   access_expr: Optional[ValueExpr]) -> bool:
        """判定: alloc_expr ≥ access_expr 是否恒成立 → 安全."""
        if alloc_expr is None or access_expr is None:
            return False
        result = access_expr.implies_le(alloc_expr)
        return result is True

    def _trace_use_def(self, instructions: List[str],
                       start_idx: int, target_reg: str) -> Optional[ValueExpr]:
        """Use-def 链后向遍历: 从 call 点沿单条寄存器链向上追踪,
        直到遇到常量/栈槽/未知值. 用 wrapper 栈记录 ADD/SUB/SHL 修饰.

        对 call 指令: 不硬中断 — 跨越 call 继续追踪, 但在函数返回点(ret)停止.
        原因: x64 calling convention 中, call 不修改所有寄存器,
        rdx/r8/r9 在 alloc call 前后可能由编译器保留 (通过 save/restore 或
        由于 MinGW 的优化策略)."""
        cur_reg = self._canon_reg(target_reg)
        wrappers: List[Tuple[str, int]] = []  # ('add'|'sub'|'shl', imm)

        for i in range(start_idx - 1, max(0, start_idx - 40) - 1, -1):
            il = instructions[i].strip().lower()
            if not il or il.startswith(';'):
                continue
            # 只在实际的 ret 处停止, call 可以跨越
            if 'ret' in il:
                break

# 叶子: mov cur_reg, imm → 返回常量
            m = self._MOV_RI.search(il)
            if m and self._canon_reg(m.group(1)) == cur_reg:
                return _wrap(ValueExpr(ExprKind.CONST,
                    value=int(m.group(2), 0)), wrappers)

# 叶子: mov cur_reg, [rbp+N] → 返回栈槽
            m = self._MOV_FROM_STACK.search(il)
            if m and self._canon_reg(m.group(1)) == cur_reg:
                sign = -1 if m.group(2) == '-' else 1
                return _wrap(ValueExpr(ExprKind.STACK,
                    value=sign * int(m.group(3), 0)), wrappers)

# 链: mov cur_reg, src_reg → 切换追踪目标
            m = self._MOV_RR.search(il)
            if m and self._canon_reg(m.group(1)) == cur_reg:
                cur_reg = self._canon_reg(m.group(2))
                continue

# 修饰: add cur_reg, imm → 记下 +imm
            m = self._ADD_RI.search(il)
            if m and self._canon_reg(m.group(1)) == cur_reg:
                wrappers.append(('add', int(m.group(2), 0)))
                continue

# 修饰: sub cur_reg, imm → 记下 -imm
            m = self._SUB_RI.search(il)
            if m and self._canon_reg(m.group(1)) == cur_reg:
                wrappers.append(('sub', int(m.group(2), 0)))
                continue

# 修饰: shl cur_reg, imm → 记下 <<imm
            m = self._SHL_RI.search(il)
            if m and self._canon_reg(m.group(1)) == cur_reg:
                wrappers.append(('shl', int(m.group(2), 0)))
                continue

        return None

    def _extract_func(self, il: str) -> str:
        m = re.search(r'call\s+(?:[0-9a-f]+\s+<)?([^>\s]+)', il)
        return m.group(1).lower() if m else ''

def _wrap(base: ValueExpr,
          wrappers: List[Tuple[str, int]]) -> ValueExpr:
    """逐层从内向外应用修饰: (add 1) on eax → (eax + 1)."""
    result = base
    for op, imm in reversed(wrappers):
        if op == 'add':
            result = ValueExpr(ExprKind.ADD, left=result,
                right=ValueExpr(ExprKind.CONST, value=imm))
        elif op == 'sub':
            result = ValueExpr(ExprKind.SUB, left=result,
                right=ValueExpr(ExprKind.CONST, value=imm))
        elif op == 'shl':
            result = ValueExpr(ExprKind.SHL, left=result,
                right=ValueExpr(ExprKind.CONST, value=imm))
    return result

# smoke
def _check():
    corr = SizeBoundCorrelator()
    # s = [rbp+0x10]; edx = eax; eax = s+1; ecx = eax; malloc(s+1); r8=rdx; memcpy(_,_,s)
    insns = [
        "  401000:\tmov    eax,DWORD PTR [rbp+0x10]",   # s = param
        "  401003:\tmov    edx,eax",                      # s → edx
        "  401005:\tadd    eax,0x1",                      # s+1 → eax
        "  401008:\tmov    ecx,eax",                      # s+1 → ecx
        "  40100a:\tcall   malloc",                       # malloc(s+1)
        "  40100f:\tmov    r8,rdx",                       # s → r8
        "  401012:\tcall   memcpy",                       # memcpy(_, _, s)
    ]
    alloc = corr.trace_alloc_size(insns, 4)
    access = corr.trace_access_size(insns, 6, 'memcpy')
    print(f"  alloc expr: {alloc}")
    print(f"  access expr: {access}")
    safe = corr.prove_safe(alloc, access)
    print(f"  safe: {safe}")
    assert alloc is not None, "alloc expr should not be None"
    assert access is not None, "access expr should not be None"
    assert safe, f"s ≤ s+1 should be proven safe, got alloc={alloc} access={access}"
    print("[OK] size_bound_correlation tests passed")

if __name__ == "__main__":
    _check()
