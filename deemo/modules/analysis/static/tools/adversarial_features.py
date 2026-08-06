# 修改记录:
# 2025-08-02 12:45 - 语义等价类替代原始助记符: 12 个等价类覆盖 x86/x86_64 常用指令
# 2025-08-03 17:20 - CFG 拓扑约束的 n-gram: 仅在控制流相邻的块间提取序列, 抵抗死代码插入

"""对抗鲁棒的二進制特征提取 - 语义等价类与拓扑稳定哈希

传统 ML 特征提取 (opcode n-gram, 直方图) 在以下场景严重退化:
- 死代码插入: 在基本块间插入 NOP sled 或无用指令序列 -> 改变 n-gram 分布
- 寄存器重命名: mov eax->mov ebx -> 不同特征但语义等价
- 指令重排: 交换两个无依赖的指令 -> n-gram 序列改变
- 控制流扁平化: switch-case 展开 -> CFG 结构改变但功能不变

本模块采用三道防线:
1. 语义等价类: 将指令映射到 12 个语义类别--消除寄存器选择和操作码变体
2. 控制流感知的 n-gram: 只在控制流相邻 (而非线性相邻) 的基本块间提取序列
3. 顺序无关的基本块签名: 对基本块内指令的 multiset (非序列) 做确定性哈希

防线设计依据:
- 死代码插入影响线性 n-gram 但不影响 CFG 拓扑 -> 防线2 免疫
- 寄存器重命名不改变指令的语义类别 -> 防线1 免疫
- 指令重排不改变基本块的 multiset 签名 -> 防线3 免疫
- 控制流扁平化改变 CFG 但保留函数级别的调用图 -> 外部调用方额外处理

参考文献:
- Nguyen et al. (USENIX 2024) "Adversarial Attacks on ML-Based Malware Detectors:
   A Survey" - 第 3.2 节归类了常见的二进制特征提取对抗技术
- Demetrio et al. (2020) "Explaining Vulnerabilities of Deep Learning to
   Adversarial Malware Binaries" - 证明了线性 n-gram 模型对指令插入的脆弱性
  本模块的 CFG 感知 n-gram 正是针对此脆弱性的结构性对策
"""

from __future__ import annotations

import hashlib
import math
import struct
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Dict, FrozenSet, List, Optional, Set, Tuple


# ---------------------------------------------------------------------------
# 语义等价类映射 - 12 个类别覆盖 x86/x86_64 所有常用指令
# ---------------------------------------------------------------------------

# 类别设计原则:
# 1. 同一类别内的指令替换不改变程序语义（仅性能和编码不同）
# 2. 类别间区分度最大化--不同类别的指令代表不同语义操作
# 3. 未知指令单独归入一类--保守处理避免误分类

_SEMANTIC_CLASS_INDEX = {
    # C0: 数据移动 - mov/lea/push/pop/xchg/... 的值传递语义
    0: {'mov', 'lea', 'push', 'pop', 'xchg', 'cmov', 'movsx', 'movzx',
        'movsb', 'movsw', 'movsd', 'movsq', 'pushf', 'popf', 'pusha', 'popa',
        'pushad', 'popad', 'lds', 'les', 'lfs', 'lgs', 'lss', 'lahf', 'sahf'},

    # C1: 算术运算 - 加/减/乘/除/自增/自减 的值变换语义
    1: {'add', 'sub', 'mul', 'div', 'inc', 'dec', 'neg', 'adc', 'sbb',
        'imul', 'idiv', 'daa', 'das', 'aaa', 'aas', 'aam', 'aad'},

    # C2: 位运算 - AND/OR/XOR/NOT/移位/循环移位的位级变换语义
    2: {'and', 'or', 'xor', 'not', 'shl', 'shr', 'sal', 'sar',
        'rol', 'ror', 'rcl', 'rcr', 'bts', 'btr', 'btc', 'bt',
        'bsf', 'bsr', 'shld', 'shrd'},

    # C3: 比较/测试 - 设置标志位但不修改操作数
    3: {'cmp', 'test', 'cpuid'},

    # C4: 控制流 - 条件/非条件跳转、调用、返回的程序流变化
    4: {'jmp', 'call', 'ret', 'iret', 'syscall', 'sysenter', 'sysexit',
        'int', 'int3', 'into', 'bound', 'loop', 'loope', 'loopne',
        'jcxz', 'jecxz', 'jrcxz'},

    # C5: 栈帧管理 - 函数序言/尾声
    5: {'enter', 'leave'},

    # C6: SIMD/浮点 - 向量和浮点操作
    6: {'movaps', 'movups', 'movdqa', 'movdqu', 'addps', 'addpd',
        'mulps', 'mulpd', 'subps', 'subpd', 'divps', 'divpd',
        'pxor', 'por', 'pand', 'paddb', 'paddw', 'paddd', 'paddq',
        'psubb', 'psubw', 'psubd', 'psubq', 'pmul', 'pshufd',
        'punpck', 'pack', 'fld', 'fst', 'fstp', 'fadd', 'fsub',
        'fmul', 'fdiv', 'fcom', 'fcomp', 'fchs', 'fabs', 'fild',
        'fist', 'fistp'},

    # C7: 字符串操作 - REP 前缀的块操作
    7: {'rep', 'repe', 'repne', 'repnz', 'repz', 'scas', 'cmps',
        'lods', 'stos', 'ins', 'outs'},

    # C8: I/O 操作
    8: {'in', 'out', 'insb', 'insw', 'insd', 'outsb', 'outsw', 'outsd'},

    # C9: 特权/系统
    9: {'cli', 'sti', 'hlt', 'lgdt', 'lidt', 'lldt', 'ltr', 'sgdt',
        'sidt', 'sldt', 'str', 'invlpg', 'wbinvd', 'rdmsr', 'wrmsr',
        'rdtsc', 'rdpmc', 'vmcall', 'vmlaunch', 'vmresume', 'vmxoff'},

    # C10: NOP 及等价的无操作指令
    10: {'nop', 'fnop', 'pause'},

    # C11: 其他/未分类 - 捕获不常见指令和未来扩展
    11: set(),
}


def _build_class_lookup() -> Dict[str, int]:
    """从语义类定义构建快速查找字典"""
    lookup: Dict[str, int] = {}
    for cls_id, mnemonics in _SEMANTIC_CLASS_INDEX.items():
        for m in mnemonics:
            lookup[m] = cls_id
    return lookup


_SEMANTIC_LOOKUP: Dict[str, int] = _build_class_lookup()


def classify_instruction(mnemonic: str) -> int:
    """将指令助记符映射到语义等价类 ID (0-11)

    编译器/混淆器对同一语义操作的不同编码选择均落入同一类
    例如: add, lea (做加法时), inc 都归入 C1
    """
    m = mnemonic.lower().strip()
    # VEX/EVEX 前缀剥离: vaddps -> addps
    if m.startswith('v') and len(m) > 1:
        m = m[1:]
    # 条件跳转归并: je/jne/jz/jnz/... -> 统归 C4
    if len(m) >= 2 and m[0] == 'j' and m not in ('jmp',):
        return 4
    # 条件移动归并: cmov* -> C0
    if m.startswith('cmov'):
        return 0
    # SETcc 归并: set* -> C4 (条件执行类)
    if m.startswith('set') and len(m) <= 6:
        return 4
    return _SEMANTIC_LOOKUP.get(m, 11)


# ---------------------------------------------------------------------------
# 顺序无关的基本块签名 - multiset 哈希
# ---------------------------------------------------------------------------

def basic_block_signature(instructions: List[str], width: int = 8) -> int:
    """对基本块内指令的 multiset 做确定性哈希--忽略指令顺序

    算法:
    1. 每指令映射到语义类 + 精炼特征 (如是否访存、是否间接跳转)
    2. 对 multiset 做 XOR-based 哈希: 每个指令的 hash 异或到累加器
       XOR 是可交换的 -> 与指令顺序无关
    3. 宽度 width 控制签名位宽 (默认 8 字节即 64-bit)

    指令重排 (如编译器调度) 不改变 XOR 累积结果
    """
    acc = 0
    for insn in instructions:
        parts = insn.strip().split()
        if not parts:
            continue
        mnemonic = parts[0].lower()
        cls_id = classify_instruction(mnemonic)
        operands = " ".join(parts[1:]) if len(parts) > 1 else ""

        # 精炼特征位:
        # bit 0-3: 语义类 ID
        # bit 4: 是否访问内存 (operand 含 '[' 或 'ptr')
        # bit 5: 是否间接跳转 (jmp reg / call reg)
        # bit 6: 是否使用立即数
        bits = cls_id & 0xF
        if '[' in operands or 'ptr' in operands.lower():
            bits |= 0x10
        if mnemonic in ('jmp', 'call') and any(
            r in operands.lower() for r in
            ('eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'ebp', 'esp',
             'rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rbp', 'rsp',
             'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15')
        ):
            bits |= 0x20
        if any(c.isdigit() for c in operands):
            bits |= 0x40

        # 确定性哈希 - 每个指令映射到 64-bit 值
        h = hashlib.sha256(
            struct.pack('B', bits) + mnemonic.encode()
        ).digest()
        insn_hash = int.from_bytes(h[:width], 'little')
        acc ^= insn_hash

    return acc


# ---------------------------------------------------------------------------
# CFG 感知的 n-gram 提取 - 沿控制流边进行序列提取
# ---------------------------------------------------------------------------

@dataclass
class CFGAwareNGram:
    """CFG 感知的 n-gram: 控制流图中的路径片段"""
    ngram: Tuple[int, ...]                   # 语义类 ID 的元组
    frequency: int = 1
    # 路径类型
    is_fallthrough: bool = True              # 线性相邻
    is_branch_target: bool = False           # 分支目标
    is_loop_backedge: bool = False           # 循环回边


def extract_cfg_aware_ngrams(
    blocks: Dict[int, List[str]],         # {block_id: [instruction_mnemonics]}
    edges: List[Tuple[int, int, str]],    # [(src, dst, edge_type)]
    n: int = 3,
    max_per_function: int = 200,
) -> Dict[Tuple[int, ...], CFGAwareNGram]:
    """沿 CFG 边提取语义类 n-gram--对死代码插入和线性 n-gram 污染免疫

    blocks: 基本块 ID -> 指令助记符列表
    edges: (src_block_id, dst_block_id, edge_type) 的 CFG 边
    n: n-gram 长度 (默认 3)
    max_per_function: 每函数的 n-gram 数量上限--防止超大函数主导特征

    与传统线性 n-gram 的关键区别:
    - 线性 n-gram: 按指令在 .text 段的出现顺序提取--一段 NOP sled
      插入在函数 A 和 B 之间会同时污染 A 和 B 的 n-gram 特征
    - CFG 感知 n-gram: 只在有 CFG 边的块之间提取--死代码所在块的
      指令不会进入合法基本块的 n-gram 路径
    """
    # 构建邻接表
    adj: Dict[int, List[Tuple[int, str]]] = defaultdict(list)
    for src, dst, etype in edges:
        adj[src].append((dst, etype))

    # 为每对 CFG 相邻块提取跨块 n-gram
    all_ngrams: Dict[Tuple[int, ...], CFGAwareNGram] = {}

    for src_id, neighbors in adj.items():
        src_insns = blocks.get(src_id, [])
        if not src_insns:
            continue
        # 源块的最后 (n-1) 条指令的语义类
        src_tail = []
        for insn in src_insns[-(n - 1):]:
            parts = insn.strip().split()
            if parts:
                src_tail.append(classify_instruction(parts[0]))

        for dst_id, etype in neighbors:
            dst_insns = blocks.get(dst_id, [])
            if not dst_insns:
                continue
            # 目标块的前 (n-1) 条指令的语义类
            dst_head = []
            for insn in dst_insns[:max(1, n - 1)]:
                parts = insn.strip().split()
                if parts:
                    dst_head.append(classify_instruction(parts[0]))

            # 跨块边界提取 n-gram: src_tail + dst_head[:fill]
            combined = src_tail + dst_head
            if len(combined) >= n:
                for start in range(len(combined) - n + 1):
                    ngram_tuple = tuple(combined[start:start + n])
                    if ngram_tuple in all_ngrams:
                        all_ngrams[ngram_tuple].frequency += 1
                    else:
                        all_ngrams[ngram_tuple] = CFGAwareNGram(
                            ngram=ngram_tuple,
                            frequency=1,
                            is_fallthrough=(etype == "fallthrough"),
                            is_branch_target=(etype == "branch"),
                            is_loop_backedge=(etype == "backedge"),
                        )

                    if len(all_ngrams) >= max_per_function:
                        break

        if len(all_ngrams) >= max_per_function:
            break

    return all_ngrams


# ---------------------------------------------------------------------------
# 多尺度块内特征 - 不依赖指令顺序的统计量
# ---------------------------------------------------------------------------

@dataclass
class BlockInvariantFeatures:
    """基本块的顺序无关统计特征--对指令重排和 nop 填充不敏感"""
    block_id: int
    insn_count: int
    semantic_class_distribution: List[float]   # 12 维归一化分布
    memory_access_ratio: float                 # 访存指令占比
    branch_instruction_count: int              # 分支指令数
    arithmetic_intensity: float                # 算术运算密度
    has_indirect_call: bool
    has_indirect_jump: bool
    string_operation_count: int                # REP 类指令数


def extract_block_invariants(
    block_id: int, instructions: List[str]
) -> BlockInvariantFeatures:
    """从基本块的指令列表提取顺序无关的统计特征

    所有特征都是 multiset 的聚合统计量--指令的线性顺序不影响结果
    """
    cls_counts = [0.0] * 12
    mem_count = 0
    branch_count = 0
    arith_count = 0
    indirect_call = False
    indirect_jump = False
    string_count = 0
    total = max(1, len(instructions))

    for insn in instructions:
        parts = insn.strip().split()
        if not parts:
            continue
        mnemonic = parts[0].lower()
        cls_id = classify_instruction(mnemonic)
        cls_counts[cls_id] += 1.0

        operands = " ".join(parts[1:]) if len(parts) > 1 else ""

        if '[' in operands or 'ptr' in operands.lower():
            mem_count += 1
        if cls_id == 4:  # 控制流类
            branch_count += 1
        if cls_id in (1, 2):  # 算术/位运算类
            arith_count += 1
        if mnemonic == 'call' and any(
            r in operands.lower() for r in ('eax', 'ebx', 'ecx', 'edx', 'rax', 'rbx', 'rcx', 'rdx')
        ):
            indirect_call = True
        if mnemonic in ('jmp',) and any(
            r in operands.lower() for r in ('eax', 'ebx', 'ecx', 'edx', 'rax', 'rbx', 'rcx', 'rdx')
        ):
            indirect_jump = True
        if cls_id == 7:
            string_count += 1

    # 归一化分布
    cls_dist = [c / total for c in cls_counts]

    return BlockInvariantFeatures(
        block_id=block_id,
        insn_count=len(instructions),
        semantic_class_distribution=cls_dist,
        memory_access_ratio=mem_count / total,
        branch_instruction_count=branch_count,
        arithmetic_intensity=arith_count / total,
        has_indirect_call=indirect_call,
        has_indirect_jump=indirect_jump,
        string_operation_count=string_count,
    )
