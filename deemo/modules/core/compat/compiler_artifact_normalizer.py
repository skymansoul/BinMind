# 编译器产物归一化器 — 消除不同编译器在二进制 CFG 中的结构差异。
#
# 同一源码函数经不同编译器/优化级别编译后, 基本块数量可相差 2-5 倍。
# 这些差异对 GNN 漏洞检测是噪声——模型应关注代码语义而非编译器偏好。
# 本模块在 CFG 层面做归一化: 循环展开折叠 + 惯用法替换 + 寄存器类映射。
#
# 与 VexIR2Vec 互补: VEX 消除架构差异, 本模块消除编译器差异。
# VexIR2Vec — VEX-IR 归一化
# MulCPI — GNN 编译器识别 99.3%

import re
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass, field


@dataclass
class BasicBlock:
    """归一化内部块——仅含结构特征, 不依赖具体反汇编器。"""
    address: int
    instructions: List[str] = field(default_factory=list)
    successors: List[int] = field(default_factory=list)
    predecessors: List[int] = field(default_factory=list)
    instruction_count: int = 0
    is_unrolled: bool = False
    normalized_instructions: List[str] = field(default_factory=list)


@dataclass
class NormalizationReport:
    """归一化操作的统计报告。"""
    unrolled_loops_detected: int = 0
    unrolled_blocks_merged: int = 0
    compiler_idioms_normalized: int = 0
    registers_renamed: int = 0
    blocks_before: int = 0
    blocks_after: int = 0


# 循环展开检测 — GCC -O3 / Clang -O2 常见模式
# 立即数递增检测基于: 展开循环中每次迭代的立即数偏移以固定步长增加

_IMM_RE = re.compile(r'(?:0x[0-9a-fA-F]+|\b\d+\b)')


def _has_incrementing_immediates(blocks_in_group, min_ratio=0.6):
    """检查一组块中是否存在以固定步长递增的立即数——循环展开的特征。"""
    all_imms = []
    for b in blocks_in_group:
        imms = []
        for insn in b.instructions:
            found = _IMM_RE.findall(insn)
            imms.extend(int(v, 16) if v.lower().startswith('0x') else int(v)
                       for v in found)
        all_imms.append(imms)

    if not all_imms or min(len(ims) for ims in all_imms) == 0:
        return False

    min_len = min(len(ims) for ims in all_imms)
    if min_len == 0:
        return False

    constant_deltas, total_pairs = 0, 0
    for pos in range(min_len):
        ref_delta = None
        for i in range(len(all_imms) - 1):
            if pos < len(all_imms[i]) and pos < len(all_imms[i + 1]):
                delta = abs(all_imms[i + 1][pos] - all_imms[i][pos])
                if ref_delta is None:
                    ref_delta = delta
                total_pairs += 1
                if delta == ref_delta and delta > 0:
                    constant_deltas += 1

    return total_pairs > 0 and (constant_deltas / total_pairs) >= min_ratio


def _detect_unrolled_loop(blocks, min_repetitions=3, max_insn_variance=1):
    """检测连续且结构相同的块组——循环展开的产物。

    判定标准: N>=min_repetitions, 指令数差异<=max_insn_variance,
    出度相同, 且存在固定步长递增的立即数。
    """
    sorted_addrs = sorted(blocks.keys())
    groups, i = [], 0
    while i < len(sorted_addrs) - min_repetitions + 1:
        group = [sorted_addrs[i]]
        j = i + 1
        while j < len(sorted_addrs):
            prev, curr = blocks[group[-1]], blocks[sorted_addrs[j]]
            if abs(prev.instruction_count - curr.instruction_count) > max_insn_variance:
                break
            if len(prev.successors) != len(curr.successors):
                break
            group.append(sorted_addrs[j])
            j += 1
        if len(group) >= min_repetitions and _has_incrementing_immediates(
            [blocks[a] for a in group]
        ):
            groups.append(group)
            i = j
        else:
            i += 1
    return groups


# 编译器惯用法归一化 — MSVC lea+test+je 和 GCC cmov 链

def _normalize_msvc_zero_check(insns):
    """归一化 MSVC /O2 的 lea reg,[reg+0]; test reg,reg; je target。

    lea 在此模式下是冗余的零扩展——移除后语义等价。
    """
    count, result = 0, []
    lea_pat = re.compile(r'lea\s+(\w+),\s*\[\1\s*[+]\s*0\]', re.IGNORECASE)
    for i, insn in enumerate(insns):
        m = lea_pat.search(insn.strip())
        if m and i + 1 < len(insns):
            reg = m.group(1)
            if re.search(r'test\s+' + re.escape(reg) + r',\s*' + re.escape(reg),
                        insns[i + 1].strip(), re.IGNORECASE):
                count += 1
                continue
        result.append(insn)
    return result, count


_CMOV_RE = re.compile(r'cmov(?:e|ne|g|ge|l|le|a|ae|b|be)\s+', re.IGNORECASE)


def _normalize_cmov_chain(insns):
    """GCC -O3 cmov 条件链——在 CFG 中无分支但语义等价于条件跳转。"""
    count = sum(1 for insn in insns if _CMOV_RE.match(insn.strip()))
    return insns, count


# 寄存器分配归一化 — 将具体寄存器映射至抽象类别, 消除编译器寄存器偏好差异
# x86-64 的 R8-R15 和 R8D-R15D 在 GCC 和 MSVC 中的使用偏好不同

_REG_CLASS = {
    'eax': 'GPR32', 'ebx': 'GPR32', 'ecx': 'GPR32', 'edx': 'GPR32',
    'esi': 'GPR32', 'edi': 'GPR32', 'ebp': 'GPR32', 'esp': 'GPR32',
    'r8d': 'GPR32', 'r9d': 'GPR32', 'r10d': 'GPR32', 'r11d': 'GPR32',
    'r12d': 'GPR32', 'r13d': 'GPR32', 'r14d': 'GPR32', 'r15d': 'GPR32',
    'rax': 'GPR64', 'rbx': 'GPR64', 'rcx': 'GPR64', 'rdx': 'GPR64',
    'rsi': 'GPR64', 'rdi': 'GPR64', 'rbp': 'GPR64', 'rsp': 'GPR64',
    'r8': 'GPR64', 'r9': 'GPR64', 'r10': 'GPR64', 'r11': 'GPR64',
    'r12': 'GPR64', 'r13': 'GPR64', 'r14': 'GPR64', 'r15': 'GPR64',
    'xmm0': 'SSE128', 'xmm1': 'SSE128', 'xmm2': 'SSE128', 'xmm3': 'SSE128',
    'xmm4': 'SSE128', 'xmm5': 'SSE128', 'xmm6': 'SSE128', 'xmm7': 'SSE128',
    'eflags': 'FLAGS', 'rflags': 'FLAGS',
}
_SORTED_REGS = sorted(_REG_CLASS.items(), key=lambda x: -len(x[0]))


def _normalize_registers(insns):
    """将指令中的具体寄存器替换为抽象类别——消除编译器寄存器分配偏好的差异。"""
    count, result = 0, []
    for insn in insns:
        norm = insn
        for rn, rc in _SORTED_REGS:
            pat = re.compile(r'\b' + re.escape(rn) + r'\b', re.IGNORECASE)
            new, subs = pat.subn(rc, norm)
            if subs > 0:
                count += subs
                norm = new
        result.append(norm)
    return result, count


# 主归一化流程 — 三阶段流水线: 展开折叠 → 惯用法替换 → 寄存器归一化

def normalize_cfg(blocks, enable_unroll_detection=True,
                  enable_idiom_normalization=True,
                  enable_register_normalization=True):
    """编译器产物归一化主入口。

    blocks 为 {address: BasicBlock} 的函数 CFG 基本块集合,
    各 enable_* 开关控制归一化阶段; 返回 (归一化后的 blocks,
    NormalizationReport), 原始 blocks 不被修改。
    """
    report = NormalizationReport(blocks_before=len(blocks))

    # 深拷贝——避免修改调用方的数据
    norm = {}
    for addr, bb in blocks.items():
        norm[addr] = BasicBlock(
            address=bb.address,
            instructions=list(bb.instructions),
            successors=list(bb.successors),
            predecessors=list(bb.predecessors),
            instruction_count=bb.instruction_count,
            is_unrolled=bb.is_unrolled,
            normalized_instructions=list(
                bb.normalized_instructions or bb.instructions
            ),
        )

    # 阶段 1: 循环展开折叠
    if enable_unroll_detection:
        for group in _detect_unrolled_loop(norm):
            report.unrolled_loops_detected += 1
            report.unrolled_blocks_merged += len(group) - 1
            keeper = group[0]
            norm[keeper].is_unrolled = True
            norm[keeper].normalized_instructions = (
                norm[keeper].instructions[:3] +
                [f'# [unrolled x{len(group)}]']
            )
            for addr in group[1:]:
                for succ in norm[addr].successors:
                    if succ in norm:
                        norm[succ].predecessors = [
                            keeper if p == addr else p
                            for p in norm[succ].predecessors
                        ]
                if addr in norm:
                    del norm[addr]

    # 阶段 2: 编译器惯用法归一化
    if enable_idiom_normalization:
        for addr, bb in list(norm.items()):
            insns = list(bb.normalized_instructions or bb.instructions)
            insns, mc = _normalize_msvc_zero_check(insns)
            insns, cc = _normalize_cmov_chain(insns)
            if mc + cc > 0:
                report.compiler_idioms_normalized += mc + cc
                norm[addr].normalized_instructions = insns

    # 阶段 3: 寄存器分配归一化
    if enable_register_normalization:
        for addr, bb in norm.items():
            insns = list(bb.normalized_instructions or bb.instructions)
            insns, rc = _normalize_registers(insns)
            if rc > 0:
                report.registers_renamed += rc
                norm[addr].normalized_instructions = insns

    report.blocks_after = len(norm)
    return norm, report
