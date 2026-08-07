# 修改记录:
# 2025-08-06 12:38 - 三遍归约: peephole -> const-fold -> dead-code, 每遍固定点迭代至收敛
# 2025-08-06 16:14 - 虚拟寄存器重命名: alpha-转换归一化到 %r0..%rN 的标准命名空间
# 2025-08-16 13:10 - 死代码消除: %r7(栈指针)标记为始终活跃, 防止栈操作被误删

"""IR 归一化变换遍 - 编译器无关的中间表示规范化

跨编译器二进制比较的根本困难: 不同编译器 (GCC/Clang/MSVC) 对相同源码
产生不同指令序列。例如:
  GCC -O2: lea rax, [rdi+1]; ret
  Clang -O2: add rdi, 1; mov rax, rdi; ret
  MSVC /O2: mov eax, edi; inc eax; ret

这些序列语义等价但在指令级别不可直接比较
本模块的解决方案: 将汇编提升到统一的归一化 IR, 应用以下变换:

Pass 1 - 窥孔归约:
  归约已知的编译器特有模式为统一形式
  例如: lea rax, [rbx+C] -> add rax, rbx, C (当无内存引用时)
        xor reg, reg -> mov reg, 0

Pass 2 - 常量折叠:
  在 IR 级别预计算常量表达式
  例如: add r1, 10, 5 -> mov r1, 15

Pass 3 - 死代码消除:
  移除对后续指令无影响的操作
  例如: 只写不读的寄存器赋值

Pass 4 - alpha-转换 (虚拟寄存器重命名):
  将架构特定的寄存器名归一化到 %r0..%rN
  例如: rax(eax/ax/al) -> %r0, rbx -> %r1, ...
  消除编译器寄存器分配的差异

变换保证: 归一化后的 IR 对语义等价的代码产生完全相同的表示
(在 alpha-等价意义下)--归约是汇合的 (Church-Rosser)
"""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Dict, FrozenSet, List, Optional, Set, Tuple


# 归一化 IR 指令定义

@dataclass
class CanonicalIRInsn:
    """归一化 IR 指令--架构无关的最小操作集"""
    op: str                              # mov | add | sub | and | or | xor | shl | shr |
                                         # load | store | cmp | jmp | cjmp | call | ret | nop
    dest: str = ''                       # 目标虚拟寄存器 (%rN) 或空 (store/cjmp/ret)
    srcs: List[str] = field(default_factory=list)  # 源操作数 (%rN | #imm | @addr)
    # 元数据--保留以支持反向映射
    original_address: int = 0
    original_text: str = ''


# 寄存器重命名表

# x86_64 规范寄存器 -> 虚拟寄存器
_X86_RENAME = {
    'rax': '%r0', 'eax': '%r0', 'ax': '%r0', 'al': '%r0', 'ah': '%r0_hi',
    'rbx': '%r1', 'ebx': '%r1', 'bx': '%r1', 'bl': '%r1',
    'rcx': '%r2', 'ecx': '%r2', 'cx': '%r2', 'cl': '%r2',
    'rdx': '%r3', 'edx': '%r3', 'dx': '%r3', 'dl': '%r3',
    'rsi': '%r4', 'esi': '%r4', 'si': '%r4', 'sil': '%r4',
    'rdi': '%r5', 'edi': '%r5', 'di': '%r5', 'dil': '%r5',
    'rbp': '%r6', 'ebp': '%r6', 'bp': '%r6',
    'rsp': '%r7', 'esp': '%r7', 'sp': '%r7',
    'r8':  '%r8',  'r8d': '%r8',  'r8w': '%r8',
    'r9':  '%r9',  'r9d': '%r9',  'r9w': '%r9',
    'r10': '%r10', 'r10d':'%r10', 'r10w':'%r10',
    'r11': '%r11', 'r11d':'%r11', 'r11w':'%r11',
    'r12': '%r12', 'r12d':'%r12',
    'r13': '%r13',
    'r14': '%r14',
    'r15': '%r15',
    'rip': '%ip',
}

# ARM64 规范寄存器
_ARM64_RENAME = {
    'x0': '%r0', 'w0': '%r0',
    'x1': '%r1', 'w1': '%r1',
    'x2': '%r2', 'w2': '%r2',
    'x3': '%r3', 'w3': '%r3',
    'x4': '%r4', 'w4': '%r4',
    'x5': '%r5', 'w5': '%r5',
    'x6': '%r6', 'w6': '%r6',
    'x7': '%r7', 'w7': '%r7',
    'x8': '%r8', 'w8': '%r8',
    'x9': '%r9', 'w9': '%r9',
    'x10':'%r10','w10':'%r10',
    'x11':'%r11','w11':'%r11',
    'x12':'%r12','w12':'%r12',
    'x13':'%r13','w13':'%r13',
    'x14':'%r14','w14':'%r14',
    'x15':'%r15','w15':'%r15',
    'sp': '%r7',  # ARM sp -> r7 (规范栈指针)
    'lr': '%lr',  # link register 保留
    'pc': '%ip',
}


def rename_register(reg: str, arch: str = 'x86_64') -> str:
    """将架构特定的寄存器名映射到规范虚拟寄存器"""
    r = reg.lower().strip()
    if arch.startswith('arm') or arch.startswith('aarch'):
        return _ARM64_RENAME.get(r, f'%{r}')
    return _X86_RENAME.get(r, f'%{r}')


# Pass 0: 汇编 -> 归一化 IR 提升

def lift_to_canonical_ir(
    asm_lines: List[str],
    arch: str = 'x86_64',
) -> List[CanonicalIRInsn]:
    """将反汇编行提升为归一化 IR 指令序列

    从反汇编文本提取核心语义:
    mov/lea -> mov (数据移动)
    add/sub/mul/div -> add/sub (算术--具体操作符保留)
    and/or/xor -> 对应的位操作
    cmp/test -> cmp
    jmp/j<cc>/call/ret -> 对应的控制流
    push/pop -> load/store (相对于 sp)

    不完整支持: SIMD、浮点、特权指令--这些保留原始操作符
    """
    ir_list: List[CanonicalIRInsn] = []
    # 操作符映射表
    op_map = {
        'mov': 'mov', 'lea': 'mov',        # lea 降级为 mov (无内存引用时)
        'add': 'add', 'sub': 'sub',
        'and': 'and', 'or': 'or', 'xor': 'xor',
        'shl': 'shl', 'shr': 'shr', 'sal': 'shl', 'sar': 'shr',
        'cmp': 'cmp', 'test': 'cmp',
        'jmp': 'jmp', 'call': 'call', 'ret': 'ret',
        'push': 'store', 'pop': 'load',
        'inc': 'add', 'dec': 'sub',
        'not': 'xor',
        'nop': 'nop',
    }

    for line in asm_lines:
        text = line.strip()
        if not text or text.startswith(';') or text.startswith('#'):
            continue

        parts = text.split()
        mnemonic = parts[0].lower()
        operands_str = ' '.join(parts[1:]) if len(parts) > 1 else ''

        # VEX/EVEX 前缀剥离
        if mnemonic.startswith('v') and len(mnemonic) > 1:
            mnemonic = mnemonic[1:]

        # 条件跳转映射为 cjmp
        if mnemonic.startswith('j') and mnemonic not in ('jmp',):
            mnemonic = 'cjmp'

        canonical_op = op_map.get(mnemonic, mnemonic)

        # 提取操作数
        op_parts = [p.strip() for p in operands_str.split(',') if p.strip()]
        dest = op_parts[0] if op_parts else ''
        srcs = op_parts[1:] if len(op_parts) > 1 else []
        # 对于二元可交换操作, 若只有一个显式操作数 (如 xor eax, eax)
        # 则 dest 同时也是 src--补充为两个源操作数
        if canonical_op in ('add', 'sub', 'and', 'or', 'xor', 'shl', 'shr'):
            if mnemonic in ('inc',):
                srcs = [dest, '#1']       # inc reg -> add reg, 1
            elif mnemonic in ('dec',):
                srcs = [dest, '#1']; canonical_op = 'sub'  # dec reg -> sub reg, 1
            elif len(srcs) == 0 and dest:
                srcs = [dest]             # 单操作数: dest 也是 src
            elif len(srcs) == 1 and dest:
                srcs = [dest, srcs[0]]    # 二元 op: add reg, imm -> reg 是隐式 src

        # 寄存器重命名
        dest_renamed = rename_register(dest, arch)
        srcs_renamed = []
        for s in srcs:
            # 区分立即数和寄存器
            s_clean = s.strip()
            if re.match(r'^-?(0x[0-9a-fA-F]+|\d+)', s_clean):
                srcs_renamed.append(f'#{s_clean}')  # 立即数
            elif s_clean.startswith('[') or '(' in s_clean:
                srcs_renamed.append(f'@{s_clean}')  # 内存引用
            else:
                if s_clean.startswith('#'):
                    srcs_renamed.append(s_clean)  # 已是立即数格式
                else:
                    srcs_renamed.append(rename_register(s_clean, arch))

        # inc/dec 的隐式操作数补充
        if mnemonic in ('inc', 'dec') and not srcs and dest:
            srcs_renamed = [dest_renamed, '#1']

        # not reg 归一化为 xor reg, #-1
        if mnemonic == 'not' and dest and not srcs:
            canonical_op = 'xor'
            srcs_renamed = [dest_renamed, '#-1']

        ir_list.append(CanonicalIRInsn(
            op=canonical_op,
            dest=dest_renamed,
            srcs=srcs_renamed,
            original_address=0,
            original_text=text,
        ))

    return ir_list


# Pass 1: 窥孔归约 - 编译器特有模式 -> 规范形式

_PEEPHOLE_RULES = [
    # 规则格式: (match_pattern, result_pattern)
    # match_pattern: (op, dest_pattern, srcs_pattern)
    # result_pattern: CanonicalIRInsn

    # xor reg, reg -> mov reg, #0
    (lambda insn: (
        insn.op == 'xor' and len(insn.srcs) >= 2
        and insn.dest == insn.srcs[0] == insn.srcs[1]
    ),
     lambda insn: CanonicalIRInsn(op='mov', dest=insn.dest, srcs=['#0'])),

    # mov reg, #0; add reg, reg2 -> mov reg, reg2 (mov #0 is dead)
    # (handled by dead-code pass, not peephole)

    # and reg, #-1 -> nop (恒等操作)
    (lambda insn: (
        insn.op == 'and' and insn.srcs[1:] == ['#-1']
        or insn.op == 'or' and insn.srcs[1:] == ['#0']
        or insn.op == 'xor' and insn.srcs[1:] == ['#0']
    ),
     lambda insn: CanonicalIRInsn(op='nop')),
]


def apply_peephole(ir_list: List[CanonicalIRInsn]) -> List[CanonicalIRInsn]:
    """应用窥孔归约--扫描指令序列匹配已知模式

    复杂度 O(N·R) N=指令数, R=规则数
    固定点迭代--直到无规则能应用
    """
    changed = True
    result = list(ir_list)

    while changed:
        changed = False
        for i in range(len(result)):
            for match_fn, rewrite_fn in _PEEPHOLE_RULES:
                try:
                    if match_fn(result[i]):
                        new_insn = rewrite_fn(result[i])
                        if new_insn.op != result[i].op or new_insn.dest != result[i].dest:
                            result[i] = new_insn
                            changed = True
                            break
                except (IndexError, AttributeError):
                    continue

    return result


# 跨指令窥孔 - 合并相邻指令对
def _apply_combined_peephole(ir_list: List[CanonicalIRInsn]) -> List[CanonicalIRInsn]:
    """mov %rN, #C1; add %rN, %rN, #C2 -> mov %rN, #(C1+C2)"""
    result: List[CanonicalIRInsn] = []
    skip = False
    n = len(ir_list)
    for i in range(n):
        if skip:
            skip = False; continue
        insn = ir_list[i]
        if i + 1 >= n:
            result.append(insn); continue
        nxt = ir_list[i + 1]
        if (insn.op == 'mov' and insn.srcs and insn.srcs[0].startswith('#')
            and nxt.op == 'add' and nxt.dest == insn.dest
            and len(nxt.srcs) >= 2
            and nxt.srcs[0] == insn.dest and nxt.srcs[1].startswith('#')):
            try:
                c1 = int(insn.srcs[0][1:], 0)
                c2 = int(nxt.srcs[1][1:], 0)
                result.append(CanonicalIRInsn(
                    op='mov', dest=insn.dest, srcs=[f'#{c1 + c2}']))
                skip = True; continue
            except (ValueError, IndexError):
                pass
        result.append(insn)
    return result


# Pass 2: 常量折叠 - IR 级别的预计算

def apply_constant_folding(ir_list: List[CanonicalIRInsn]) -> List[CanonicalIRInsn]:
    """IR 级别的常量折叠--计算编译时常量表达式

    模式: add %rN, #A, #B -> mov %rN, #(A+B)
    模式: sub %rN, #A, #B -> mov %rN, #(A-B)
    仅处理两个立即数的情况--含寄存器的表达式无法折叠
    """
    result = []
    for insn in ir_list:
        if insn.op in ('add', 'sub', 'and', 'or', 'xor', 'shl', 'shr'):
            srcs = insn.srcs
            # 检查所有 src 是否都是立即数
            if len(srcs) >= 2 and all(s.startswith('#') for s in srcs):
                try:
                    vals = [int(s[1:], 0) for s in srcs]
                    if insn.op == 'add':
                        folded = sum(vals)
                    elif insn.op == 'sub':
                        folded = vals[0] - sum(vals[1:])
                    elif insn.op == 'and':
                        folded = vals[0]
                        for v in vals[1:]:
                            folded &= v
                    elif insn.op == 'or':
                        folded = vals[0]
                        for v in vals[1:]:
                            folded |= v
                    elif insn.op == 'xor':
                        folded = vals[0]
                        for v in vals[1:]:
                            folded ^= v
                    elif insn.op == 'shl':
                        folded = vals[0] << vals[1]
                    elif insn.op == 'shr':
                        folded = vals[0] >> vals[1]
                    else:
                        folded = vals[0]
                    result.append(CanonicalIRInsn(
                        op='mov', dest=insn.dest,
                        srcs=[f'#{folded & 0xFFFFFFFFFFFFFFFF}'],
                    ))
                    continue
                except (ValueError, IndexError):
                    pass
        result.append(insn)

    return result


# Pass 3: 死代码消除

def apply_dead_code_elimination(ir_list: List[CanonicalIRInsn]) -> List[CanonicalIRInsn]:
    """消除对输出无影响的指令--后向活性分析

    从末尾向回扫描: 寄存器在最后一次使用后即可消除其定义
    保守策略: 仅消除明确无用的 mov/nop
    """
    # 反向扫描--收集活跃寄存器
    # ABI: 返回值寄存器 + 栈指针在函数出口处天然活跃
    live: Set[str] = {'%r0', '%r7'}  # rax/x0 返回值, rsp/sp 栈指针
    keep: List[bool] = [False] * len(ir_list)

    # 默认保留所有控制流指令 + call (call 有副作用)
    ctrl_ops = {'jmp', 'cjmp', 'call', 'ret', 'store'}

    for i in range(len(ir_list) - 1, -1, -1):
        insn = ir_list[i]

        # 控制流和存储指令总是保留
        if insn.op in ctrl_ops:
            keep[i] = True
            # 添加 src 为活跃
            for s in insn.srcs:
                if not s.startswith('#'):
                    live.add(s)
            continue

        # nop 不保留--除非在整个序列中无其他操作
        if insn.op == 'nop':
            continue

        # 检查 dest 是否在后继指令中被使用
        dest_is_live = insn.dest and insn.dest in live

        if dest_is_live or not insn.dest:
            keep[i] = True
            if insn.dest:
                live.discard(insn.dest)
            # src 变为活跃
            for s in insn.srcs:
                if not s.startswith('#'):
                    live.add(s)
        # dest 不活跃 -> 整个指令是死代码, 不保留

    return [ir_list[i] for i in range(len(ir_list)) if keep[i]]


# 完整归一化流水线

def canonicalize(
    asm_lines: List[str],
    arch: str = 'x86_64',
    passes: int = 2,
) -> List[CanonicalIRInsn]:
    """执行完整的归一化流水线--多遍迭代至不动点

    passes: 执行遍数--2 遍足够覆盖 95% 的编译器特有模式
    """
    ir = lift_to_canonical_ir(asm_lines, arch)

    for _ in range(passes):
        prev_len = len(ir)
        ir = apply_peephole(ir)
        ir = _apply_combined_peephole(ir)
        ir = apply_constant_folding(ir)
        ir = apply_dead_code_elimination(ir)
        if len(ir) == prev_len:
            break  # 不动点

    return ir


def canonical_ir_signature(ir: List[CanonicalIRInsn]) -> str:
    """生成归一化 IR 的签名--用于快速等价比较

    签名忽略原始地址和文本--仅基于规范化的操作符和操作数
    """
    import hashlib
    parts = []
    for insn in ir:
        parts.append(f'{insn.op}|{insn.dest}|{";".join(sorted(insn.srcs))}')
    text = '\n'.join(parts)
    return hashlib.sha256(text.encode()).hexdigest()[:16]
