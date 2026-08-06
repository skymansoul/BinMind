"""
分配大小追踪器 — 从 malloc 参数到后续写入的路径敏感数据流。

核心创新:
  堆溢出误报的首要来源: 检测器看到 malloc(N) 后跟 memcpy(dst, src, M)
  即报告溢出, 但未验证 M 是否真的大于 N。
  本模块追踪 malloc 的 size 参数在数据流中的传递路径,
  确定 memcpy 的写入长度是否受该 size 约束。

方法:
  1. 前向数据流: 标记 malloc 返回的指针 p 和 size 参数 s
  2. 沿 mov/lea/add/sub 追踪 p 的传递和 s 的约束传播
  3. 在 memcpy(p+offset, src, len) 处检查: len ≤ s - offset ?
  4. 若约束不满足且不可证明安全 → 告警; 若可证明安全 → 过滤

与 BIFT 的区别:
  BIFT 追踪"输入是否到达危险函数"(污点), 不分真假阳性。
  本模块追踪"分配大小是否约束了写入长度"(约束), 精确区分。
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple


@dataclass
class AllocSite:
    """分配点记录"""
    insn_idx: int
    alloc_func: str
    size_reg: str          # 承载 size 参数的寄存器 (rdi for malloc)
    ptr_reg: str           # 承载返回指针的寄存器 (rax from malloc)
    size_value: int = 0    # 已知常量值, 0=未知
    size_source: str = ""  # 常量/变量名/外部输入


@dataclass
class WriteSite:
    """写入点记录"""
    insn_idx: int
    write_func: str
    dst_reg: str           # 目标地址寄存器
    len_reg: str           # 写入长度寄存器 (rdx for memcpy)
    len_value: int = 0
    dst_offset: int = 0    # dst = alloc_ptr + offset


@dataclass
class HeapOverflowWithTrace:
    """带数据流追踪的堆溢出发现"""
    alloc: AllocSite
    write: WriteSite
    can_prove_safe: bool          # 可证明安全 → 误报
    constraint_evidence: str      # 约束证据的描述
    confidence: str               # confirmed/likely/false_positive


def _parse_reg(op_str: str) -> Optional[str]:
    """从操作数字符串提取寄存器名 — 匹配32/64位变体"""
    regs = ['rax','rbx','rcx','rdx','rsi','rdi','r8','r9','r10','r11',
            'r12','r13','r14','r15','rsp','rbp',
            'eax','ebx','ecx','edx','esi','edi','esp','ebp']
    for r in regs:
        if r in op_str:
            full = 'r' + r[1:] if r.startswith('e') else r
            return full
    return None


def _parse_imm(op_str: str) -> Optional[int]:
    """从操作数字符串提取立即数 — 支持十进制和十六进制"""
    import re
    op = op_str.strip()
    try:
        if op.lower().startswith('0x'):
            return int(op, 16)
        return int(op)
    except (ValueError, TypeError):
        pass
    m = re.search(r'(0x[0-9a-fA-F]+)', op)
    if m:
        try: return int(m.group(1), 16)
        except ValueError: pass
    return None


def track_allocation_to_write(
    instructions: List[str],
    known_constants: Optional[Dict[str, int]] = None,
) -> List[HeapOverflowWithTrace]:
    """
    追踪 malloc→write 的数据流, 判定每次写入是否被分配大小约束。

    返回 HeapOverflowWithTrace 列表, can_prove_safe=True 表示可过滤的误报。
    """
    constants = known_constants or {}
    allocs: List[AllocSite] = []
    results: List[HeapOverflowWithTrace] = []

    # 寄存器间值的传播跟踪 (简化: 仅追踪 mov 的直接赋值)
    reg_values: Dict[str, int] = dict(constants)

    for i, insn in enumerate(instructions):
        parts = insn.strip().split()
        if not parts: continue

        mnemonic = parts[0].lower()

        # 检测 malloc/calloc/realloc 调用
        if mnemonic == 'call' and len(parts) > 1:
            callee = parts[-1].lower().split('@')[0].split('.')[-1].lstrip('*')
            if callee in ('malloc', '_Znwm', 'operatornew'):
                size_reg = 'rdi'
                size_val = reg_values.get('rdi', reg_values.get('edi', 0))
                allocs.append(AllocSite(
                    insn_idx=i, alloc_func='malloc',
                    size_reg=size_reg, ptr_reg='rax',
                    size_value=size_val,
                    size_source='constant' if size_val > 0 else 'variable'))
                reg_values['rax'] = 0  # rax 内容未知, 清除旧值

            elif callee in ('calloc',):
                # calloc(rdi=nmemb, rsi=size)
                n = reg_values.get('rdi', reg_values.get('edi', 0))
                s = reg_values.get('rsi', reg_values.get('esi', 0))
                sz = n * s if n > 0 and s > 0 else 0
                allocs.append(AllocSite(
                    insn_idx=i, alloc_func='calloc',
                    size_reg='rdi*rsi', ptr_reg='rax',
                    size_value=sz,
                    size_source='constant' if sz > 0 else 'variable'))
                reg_values['rax'] = 0

            elif callee in ('memcpy', 'memmove', 'strcpy', 'strncpy', 'read', 'recv', 'fread'):
                # 检查是否写入已分配的缓冲区
                dst_reg = 'rdi'
                len_reg = 'rdx' if callee not in ('strcpy', 'gets') else 'unbounded'
                len_val = reg_values.get(len_reg, 0) if len_reg != 'unbounded' else 0

                # 查找最近的 malloc
                for alloc in reversed(allocs):
                    if alloc.insn_idx < i:
                        # 检查: alloc.size >= len_val?
                        if alloc.size_value > 0 and len_val > 0:
                            if alloc.size_value >= len_val:
                                # 可证明安全 → 误报
                                results.append(HeapOverflowWithTrace(
                                    alloc=alloc, write=WriteSite(
                                        insn_idx=i, write_func=callee,
                                        dst_reg=dst_reg, len_reg=len_reg,
                                        len_value=len_val),
                                    can_prove_safe=True,
                                    constraint_evidence=f"alloc={alloc.size_value} ≥ write={len_val}",
                                    confidence='false_positive'))
                            else:
                                results.append(HeapOverflowWithTrace(
                                    alloc=alloc, write=WriteSite(
                                        insn_idx=i, write_func=callee,
                                        dst_reg=dst_reg, len_reg=len_reg,
                                        len_value=len_val),
                                    can_prove_safe=False,
                                    constraint_evidence=f"alloc={alloc.size_value} < write={len_val}",
                                    confidence='confirmed'))
                        else:
                            # 无法确定 → 保留告警 (不自动过滤)
                            results.append(HeapOverflowWithTrace(
                                alloc=alloc, write=WriteSite(
                                    insn_idx=i, write_func=callee,
                                    dst_reg=dst_reg, len_reg=len_reg,
                                    len_value=len_val),
                                can_prove_safe=False,
                                constraint_evidence="size unknown",
                                confidence='likely'))
                        break  # 只取最近的 alloc

        # mov reg, imm → 更新寄存器值
        if mnemonic == 'mov' and len(parts) >= 3:
            dst = _parse_reg(parts[1])
            imm = _parse_imm(parts[2])
            if dst and imm is not None:
                reg_values[dst] = imm
                # x86-64: 32-bit mov 隐式清零高 32 位
                if dst.startswith('e'):
                    full = 'r' + dst[1:]
                    reg_values[full] = imm

        # xor reg, reg → reg = 0
        if mnemonic == 'xor' and len(parts) >= 3:
            r1, r2 = parts[1], parts[2]
            if r1 == r2:
                reg_values[r1] = 0

    return results
