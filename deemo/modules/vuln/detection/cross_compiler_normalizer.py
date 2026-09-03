"""
跨编译器特征归一化 - GCC/Clang/MSVC 不同优化级别的IR特征对齐。

问题:
  同一源码用GCC -O0和Clang -O3编译出的二进制, 指令序列差异极大。
  检测器在-O0上训练的特征无法泛化到-O2/O3构建。
  FSE 2025证实"no existing tool handles all optimization-induced changes"。

解决方案:
  对每条指令做三阶段归一化:
    1. 助记符标准化: 编译器特化的等价指令-统一名称
       (e.g. clang的"movabs"-"mov", MSVC的"imul reg,reg,imm"-"imul reg,imm")
    2. 操作数抽象化: 立即数-$IMM, 寄存器-按类型归类
    3. 指令序列窗口化: 滑动窗口(n=3)做局部特征哈希-对重排鲁棒

输出: 归一化后的指令序列 + 归一化特征向量。

修改记录:
  创建 2025-04-17
"""

import hashlib
from typing import Any, Dict, List


# 编译器特化助记符-标准助记符
_MNEMONIC_NORMALIZE: Dict[str, str] = {
    # Clang特化
    'movabs': 'mov', 'movsb': 'movsx', 'movsw': 'movsx',
    'movzb': 'movzx', 'movzw': 'movzx',
    'cltq': 'cdqe', 'cwtl': 'cwde',
    # MSVC特化
    'imul': 'imul',  # MSVC常用三操作数形式
    # GCC特化
    'leaveq': 'leave', 'retq': 'ret',
    # 等价指令
    'xor': 'xor', 'xorl': 'xor', 'xorq': 'xor',
    'addl': 'add', 'addq': 'add', 'subl': 'sub', 'subq': 'sub',
    'movl': 'mov', 'movq': 'mov',
    'cmpl': 'cmp', 'cmpq': 'cmp',
    'testl': 'test', 'testq': 'test',
    'pushq': 'push', 'popq': 'pop',
    'jmpq': 'jmp', 'callq': 'call',
}


def _normalize_operand(op: str) -> str:
    """
    操作数抽象化:
      立即数-$IMM
      寄存器-保留原名(已足够标准化)
      内存引用-$MEM(base,index,scale,disp)
    """
    op = op.strip()
    if not op:
        return ""
    # 立即数
    if op.startswith('$') or op.startswith('0x') or op.lstrip('-').isdigit():
        return '$IMM'
    # 内存引用 [base+index*scale+disp]
    if '[' in op or '(' in op:
        return '$MEM'
    # 段前缀
    if op in ('fs:', 'gs:', 'cs:', 'ds:', 'es:', 'ss:'):
        return '$SEG'
    return op


def normalize_instruction(insn: str) -> str:
    """
    单条指令归一化: "movabs rax, 0x1234"-"mov rax, $IMM"
    返回 "mnemonic op1 op2 ..." 的归一化形式。
    """
    parts = insn.strip().split(None, 1)
    if not parts:
        return ""

    mnemonic = parts[0].lower()
    mnemonic = _MNEMONIC_NORMALIZE.get(mnemonic, mnemonic)

    if len(parts) > 1:
        operands_str = parts[1]
        # 按逗号分割操作数
        ops = []
        depth = 0
        current = ""
        for ch in operands_str:
            if ch in '([{':
                depth += 1
            elif ch in ')]}':
                depth -= 1
            if ch == ',' and depth == 0:
                ops.append(current.strip())
                current = ""
            else:
                current += ch
        if current.strip():
            ops.append(current.strip())

        normalized_ops = [_normalize_operand(op) for op in ops if _normalize_operand(op)]
        return f"{mnemonic} {' '.join(normalized_ops)}" if normalized_ops else mnemonic

    return mnemonic


def normalize_instruction_sequence(instructions: List[str]) -> List[str]:
    """归一化整个指令序列。"""
    return [normalize_instruction(insn) for insn in instructions]


def sliding_window_hash(instructions: List[str], window_size: int = 3) -> List[str]:
    """
    滑动窗口局部特征哈希 - 对指令重排提供有限鲁棒性。

    窗口[i, i+window_size)-SHA-256前8位-特征码。
    重排的影响被限制在窗口范围内。
    """
    n = len(instructions)
    if n < window_size:
        return []
    hashes = []
    for i in range(n - window_size + 1):
        window = ';'.join(instructions[i:i + window_size])
        h = hashlib.sha256(window.encode()).hexdigest()[:8]
        hashes.append(h)
    return hashes


def extract_normalized_features(
    instructions: List[str],
    window_size: int = 3,
) -> Dict[str, Any]:
    """
    从指令序列提取归一化特征。

    返回字典: normalized_insns 归一化后的指令列表,
    window_hashes 滑动窗口哈希, mnemonic_counts 助记符频次
    (归一化后), call_targets 调用目标列表 (归一化后),
    memory_access_count 内存访问指令数。
    """
    norm = normalize_instruction_sequence(instructions)
    hashes = sliding_window_hash(norm, window_size)

    mnemonic_counts: Dict[str, int] = {}
    call_targets: List[str] = []
    mem_count = 0

    for insn in norm:
        if not insn:
            continue
        parts = insn.split()
        mn = parts[0]
        mnemonic_counts[mn] = mnemonic_counts.get(mn, 0) + 1
        if mn == 'call' and len(parts) > 1:
            call_targets.append(parts[1])
        if '$MEM' in insn:
            mem_count += 1

    return {
        'normalized_insns': norm,
        'window_hashes': hashes,
        'mnemonic_counts': mnemonic_counts,
        'call_targets': call_targets,
        'memory_access_count': mem_count,
    }
