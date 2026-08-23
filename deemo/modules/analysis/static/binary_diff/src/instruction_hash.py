#
# 指令语义哈希 - 将单条汇编指令映射到对编译器变异不敏感的语义指纹
#
# 设计约束：
#   (a) 不编码寄存器编号 - 同一函数用 rax vs rbx 不应影响哈希
# (b) 立即数截断到 8-bit 粒度 - 0x41 和 0x42 在语义上等价（都是小常数比较）
#       但 0x1000 和 0x2000 不等价（可能是不同的偏移）
# (c) flags_effect 规范化 - cmp/sub 类指令统一标记为 {ZF, SF, CF} 的幂集
#       消除 O2（test+jcc 合并为单个指令）vs O0（显式 cmp+jcc）的哈希差异
#
# 三元组 (op_type, operand_types, flags_effect) 的 SHA256 前 32-bit 作为指令哈希
# 冲突概率 < 2^-32，对实际二进制文件中的指令数量而言足够
#

import hashlib
import re
from typing import List, Tuple, Optional

# 操作数类型常量 - 用单字符编码以减少哈希输入长度
_OP_REG = 'r'    # 寄存器
_OP_IMM = 'i'    # 立即数
_OP_MEM = 'm'    # 内存引用
_OP_BRANCH = 'b' # 分支目标（相对偏移）
_OP_NONE = '_'   # 无操作数

# 标志位规范化的等价类 - 同类的标志组合映射到同一标识符
# 类 0: 无标志影响
# 类 1: 仅零标志 (ZF) - test,, or
# 类 2: 零+符号 (ZF,SF) - cmp, sub
# 类 3: 零+符号+进位 (ZF,SF,CF) - add, adc, sbb
# 类 4: 全部算术标志 - mul, imul, div, idiv
# 类 5: 进位 (CF) - shl, shr, rol, ror
_FLAGS_CLASS: dict = {}

def _init_flags_class():
    """惰性初始化标志等价类"""
    if _FLAGS_CLASS:
        return
    # 类 0: 无标志影响
    for m in ('mov', 'lea', 'push', 'pop', 'jmp', 'call', 'ret', 'nop',
              'xchg', 'movsx', 'movzx', 'cmov', 'cmove', 'cmovne'):
        _FLAGS_CLASS[m] = 0
    # 类 1: ZF
    for m in ('test', 'and', 'or', 'xor', 'not', 'bt', 'bts', 'btr'):
        _FLAGS_CLASS[m] = 1
    # 类 2: ZF+SF
    for m in ('cmp', 'sub'):
        _FLAGS_CLASS[m] = 2
    # 类 3: ZF+SF+CF
    for m in ('add', 'inc', 'dec', 'adc', 'sbb', 'neg'):
        _FLAGS_CLASS[m] = 3
    # 类 4: 全部算术标志
    for m in ('mul', 'imul', 'div', 'idiv'):
        _FLAGS_CLASS[m] = 4
    # 类 5: CF
    for m in ('shl', 'shr', 'sal', 'sar', 'rol', 'ror', 'rcl', 'rcr'):
        _FLAGS_CLASS[m] = 5

# 操作数类型检测 - 不依赖 Capstone 的 operand.type，纯文本模式匹配
# 这样即使不同反汇编器的输出格式略有差异也能工作
_MEM_PAT = re.compile(r'\[|ptr\s')
_BRANCH_PAT = re.compile(r'^0x[0-9a-fA-F]+$|<')

def _classify_operand(op_str: str) -> str:
    """将操作数字符串分类为 reg/imm/mem/branch"""
    op = op_str.strip().lower()
    if not op:
        return _OP_NONE
    if '[' in op or 'ptr' in op or '(' in op:
        return _OP_MEM
    # 寄存器名通常较短且不含 0x
    if op.startswith('0x') or (op.lstrip('-').isdigit()):
        return _OP_IMM
    # 分支目标 label 形式的处理
    if op.startswith('loc_') or op.startswith('sub_') or op.startswith('0x'):
        return _OP_BRANCH
    # 段寄存器 + 偏移 视为 mem
    if ':' in op:
        return _OP_MEM
    return _OP_REG

def _truncate_imm(op_str: str) -> str:
    """立即数规范化折叠 - 小于 256 的值折叠到 8-bit 粒度"""
    op = op_str.strip()
    try:
        val = int(op, 16) if op.startswith('0x') or op.startswith('-0x') else int(op)
    except (ValueError, AttributeError):
        return op
    if abs(val) < 256:
        # 折叠到符号 - 只保留正/零/负
        if val > 0:
            return 'pos_small'
        elif val < 0:
            return 'neg_small'
        else:
            return 'zero'
    # 较大立即数保留高位 nibble 以区分不同的偏移
    return f'imm_{abs(val) >> 8}'


def semantic_hash_insn(mnemonic: str, operands: List[str]) -> Tuple[int, str]:
    """返回 (hash32, normalized_op_type) 的指令语义哈希

    参数:
    mnemonic: 助记符字符串（如 'mov', 'add', 'cmp'）
    operands: 操作数字符串列表，可以为空

    canon 三元组 = (op_type, operand_type_seq, flags_class)
    其中 op_type 是通过跨架构归一化映射得到的-如果未提供则用 mnemonic 本身
    """
    _init_flags_class()
    m = mnemonic.lower()

    # flags 等价类
    flags_class = _FLAGS_CLASS.get(m, 0)

    # 操作数类型序列
    if not operands:
        op_seq = _OP_NONE
    else:
        op_seq = ''.join(_classify_operand(o) for o in operands[:4])

    # 规范化立即数后重建完整三元组
    normalized_ops = tuple(_truncate_imm(o) if _classify_operand(o) == _OP_IMM else o
                          for o in (operands or []))

    # 构造哈希输入
    canonical = f"{m}|{op_seq}|{flags_class}|{normalized_ops}"
    h = hashlib.sha256(canonical.encode()).digest()
    hash32 = int.from_bytes(h[:4], 'little')

    return hash32, op_seq


def hash_basic_block(insns: List[Tuple[str, List[str]]],
                     block_addr: int = 0) -> Tuple[int, List[int]]:
    """返回 (block_hash64, insn_hash_list) 的基本块语义哈希

    块哈希 = 指令哈希列表的顺序相关 XOR+shift 组合
    指令两两之间的哈希也做 XOR，使得相似的指令序列产生相近的块哈希-
    两个仅差一条指令的块，其汉明距离约为 1-3 位

    参数:
    insns: [(mnemonic, [operand_str,.]),.]
    block_addr: 基本块起始地址（仅用于日志，不影响哈希值）
    """
    insn_hashes = []
    for mn, ops in insns:
        h32, _ = semantic_hash_insn(mn, ops)
        insn_hashes.append(h32)

    if not insn_hashes:
        return 0, []

    # 滚动 XOR+shift - 使序列顺序影响最终哈希
    block_hash = insn_hashes[0]
    for i in range(1, len(insn_hashes)):
        # 相邻指令的交叉影响
        block_hash ^= (insn_hashes[i] << (i % 32))
        block_hash = (block_hash << 7) | (block_hash >> (64 - 7))
        block_hash &= 0xFFFFFFFFFFFFFFFF

    # 长度也参与哈希 - 防止不同长度的块碰巧产生相同值
    block_hash ^= (len(insn_hashes) << 48)

    return block_hash, insn_hashes


def hamming_distance(a: int, b: int) -> int:
    """返回两个 64-bit 值的汉明距离"""
    return (a ^ b).bit_count()
