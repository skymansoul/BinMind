"""整数溢出检测 — 共享类型/常量/正则.

创建: 2026-05-24
"""
from __future__ import annotations

import re as _re
from dataclasses import dataclass
from enum import Enum, auto


class OverflowType(Enum):
    """整数溢出子类型."""
    LARGE_IMM64 = auto()       # 64-bit 大立即数 → alloc
    TRUNCATION = auto()         # 64→32bit 截断 → alloc
    SIGNED_IDX = auto()         # 有符号索引溢出 (INT_MAX+const)
    SUSPICIOUS_SIZE = auto()    # 可疑分配大小 (0xFF...)
    MUL_OVERFLOW = auto()       # 乘法结果溢出


@dataclass
class IntOverflowFinding:
    """单次整数溢出发现."""
    insn_addr: int
    function_name: str
    description: str
    overflow_type: OverflowType
    alloc_site: int = 0
    alloc_size: int = 0
    computed_size: int = 0
    confidence: float = 0.5
    size_source: str = ""


# 常量

_MAX_UINT32 = 0xFFFFFFFF
_MAX_INT32 = 0x7FFFFFFF

# 可疑分配大小 — 接近溢出边界的值
_SUSPICIOUS_VALS = {
    0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFF,
    0xFFFFFFFE, 0x7FFFFFFF, 0x3FFFFFFF,
    0xFFFFFFFFFFFF,
}

# alloc 函数名 — 大小写不敏感匹配
_ALLOC_FUNCS = {'malloc', 'calloc', 'realloc', '_malloc', 'HeapAlloc'}

# 正则 (预编译)

# movabs rax, 0xNNNNNNNN — 64位立即数 (opcode 48 b8)
MOVABS64 = _re.compile(r'movabs\s+(r\w\w),\s*(0x[0-9a-f]+)', _re.I)

# mov DWORD PTR [rbp±N], imm — 栈上存储32位立即数
MOV_STACK_DWORD = _re.compile(
    r'mov\s+dword\s+ptr\s+\[rbp\s*([+\-])\s*(0x[0-9a-f]+|\d+)\]'
    r'\s*,\s*(0x[0-9a-f]+|\d+)', _re.I)

# mov WORD PTR [rbp±N], imm — 栈上存储16位立即数
MOV_STACK_WORD = _re.compile(
    r'mov\s+word\s+ptr\s+\[rbp\s*([+\-])\s*(0x[0-9a-f]+|\d+)\]'
    r'\s*,\s*(0x[0-9a-f]+|\d+)', _re.I)

# add DWORD PTR [rbp±N], const — 栈上加法
ADD_STACK_DWORD = _re.compile(
    r'add\s+dword\s+ptr\s+\[rbp\s*([+\-])\s*(0x[0-9a-f]+|\d+)\]'
    r'\s*,\s*(0x[0-9a-f]+|\d+)', _re.I)

# mov reg, DWORD PTR [rbp±N] — 从栈加载
MOV_REG_FROM_STACK = _re.compile(
    r'mov\s+(e\w\w),\s*dword\s+ptr\s+\[rbp\s*([+\-])\s*(0x[0-9a-f]+|\d+)\]',
    _re.I)

# mov reg, imm32 — 32位立即数赋值
MOV_REG_IMM = _re.compile(
    r'mov\s+(\w+),\s*(0x[0-9a-f]+|\d+)', _re.I)

# mov r64, imm64 — 64位寄存器带64位立即数
MOV_R64_IMM64 = _re.compile(
    r'mov\s+(r\w\w),\s*(0x[0-9a-f]{8,16})', _re.I)

# imul reg, [rbp±N] — 从栈取乘数
IMUL_STACK = _re.compile(
    r'imul\s+(\w+),\s*(dword|word)\s+ptr\s+\[rbp\s*([+\-])\s*(0x[0-9a-f]+|\d+)\]',
    _re.I)

# mov dword [rbp±N], eax — 32-bit 截断存储
MOV_STACK_EAX = _re.compile(
    r'mov\s+dword\s+ptr\s+\[rbp\s*([+\-])\s*(0x[0-9a-f]+|\d+)\]'
    r'\s*,\s*eax', _re.I)

# mov WORD PTR [rbp±N], ax — 16-bit 截断存储
MOV_STACK_AX = _re.compile(
    r'mov\s+word\s+ptr\s+\[rbp\s*([+\-])\s*(0x[0-9a-f]+|\d+)\]'
    r'\s*,\s*ax', _re.I)

# imul reg, reg, const — 立即数乘法
IMUL_IMM = _re.compile(r'imul\s+(\w+),\s*(\w+),\s*(0x[0-9a-f]+|\d+)', _re.I)
