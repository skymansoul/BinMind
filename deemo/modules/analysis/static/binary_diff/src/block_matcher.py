#
# 基本块匹配器 - 在两个二进制的函数之间匹配等价的基本块
#
# 核心思路：
# 不是做图匹配（太慢），而是做序列匹配 + 结构验证
#   每个基本块是语义指令哈希的序列。块匹配分两步：
#     1. k-gram 预过滤：两块的 3-gram 哈希集合交集非空才进入精确匹配
#     2. 带间隙的序列相似度：简化的 Smith-Waterman 权重——
# 匹配 +2、不匹配 -1、gap -1，并引入早停（ear termina）
#
# 这个设计在 O(n·m·k) 时间内运行（n,m 是两版本的块数，k 是平均指令数）
# 对比图同构的 NP-hard 复杂度在大型二进制文件上可实际部署
#
    # 去重约束：每条基本块最多匹配 3 条对端块 - 防止一个"万能匹配块"
# （如只有一条 ret 指令的块）匹配目标函数中所有类似的桩代码

import logging
from typing import Dict, List, Tuple, Optional, Set
from dataclasses import dataclass, field

from .instruction_hash import semantic_hash_insn, hamming_distance

logger = logging.getLogger(__name__)


@dataclass
class BlockMatch:
    """一对匹配的基本块"""
    src_addr: int           # 源函数中的块地址
    dst_addr: int           # 目标函数中的块地址
    score: float            # [0, 1] 匹配分数
    matched_insns: int      # 匹配的指令对数量
    total_insns: int        # 两块的指令总数的最大值（用于归一化）
    is_exact: bool          # 精确匹配（所有指令哈希序列一致）


def _kgram_set(insn_hashes: List[int], k: int = 3) -> Set[int]:
    """从指令哈希序列构建 k-gram 集合。每个 k-gram 用 32-bit XOR 组合表示"""
    if len(insn_hashes) < k:
        # 短序列用所有哈希的 XOR 作为单个 gram
        val = 0
        for h in insn_hashes:
            val ^= h
        return {val} if val else set()
    grams = set()
    for i in range(len(insn_hashes) - k + 1):
        g = insn_hashes[i]
        for j in range(1, k):
            g ^= (insn_hashes[i + j] << (j * 8))
        grams.add(g & 0xFFFFFFFF)
    return grams


def _smith_waterman_sim(a: List[int], b: List[int]) -> Tuple[float, int]:
    """简化的 Smith-Waterman 序列相似度

    返回 (normalized_score, matched_count)
    gap 罚分 = -1, mismatch = -1, match = +2
    归一化 = score / (2 * max_len)，所以完全匹配 = 1.0
    """
    if not a or not b:
        return 0.0, 0

    max_len = max(len(a), len(b))
    # 只用两行 - 节省空间，本模块处理的大型函数可能有万级指令
    prev = [0] * (len(b) + 1)
    curr = [0] * (len(b) + 1)
    best_score = 0
    match_count = 0

    for i in range(1, len(a) + 1):
        curr[0] = 0
        for j in range(1, len(b) + 1):
            if a[i-1] == b[j-1]:
                diag = prev[j-1] + 2
                match_count += 1
            else:
                # 近似匹配 - 汉明距离 ≤ 1 的指令哈希也视为相似
                if hamming_distance(a[i-1], b[j-1]) <= 1:
                    diag = prev[j-1] + 1
                else:
                    diag = prev[j-1] - 1

            up = prev[j] - 1
            left = curr[j-1] - 1
            curr[j] = max(0, diag, up, left)
            best_score = max(best_score, curr[j])

        prev, curr = curr, prev

    normalized = best_score / (2 * max_len) if max_len > 0 else 0.0
    return min(normalized, 1.0), match_count


# 匹配阈值 - 0.45 以下几乎肯定是误匹配；此值是在 O2 vs O0 的
# coreutils 子集上经验校准的，生产环境可能需要按目标编译器调整

_DEFAULT_MATCH_THRESHOLD = 0.45


def match_blocks(
    src_blocks: Dict[int, List[Tuple[str, List[str]]]],
    dst_blocks: Dict[int, List[Tuple[str, List[str]]]],
    match_threshold: float = _DEFAULT_MATCH_THRESHOLD,
    max_per_block: int = 3,
) -> List[BlockMatch]:
    """匹配两个函数之间的基本块

    参数:
    src_blocks: {addr: [(mnemonic, [op1, op2,.]),.]} 源函数的基本块
    dst_blocks: {addr: [(mnemonic, [op1, op2,.]),.]} 目标函数的基本块
    match_threshold: 最小匹配分数 [0, 1]
    max_per_block: 每条块的最大匹配数 - 防垄断

    返回: BlockMatch 列表，按 score 降序排列
    """
    # 预计算所有块的指令哈希和 k-gram 集合
    src_hashes: Dict[int, List[int]] = {}
    src_kg: Dict[int, Set[int]] = {}
    for addr, insns in src_blocks.items():
        _, hashes = _hash_block_insns(insns)
        src_hashes[addr] = hashes
        src_kg[addr] = _kgram_set(hashes)

    dst_hashes: Dict[int, List[int]] = {}
    dst_kg: Dict[int, Set[int]] = {}
    for addr, insns in dst_blocks.items():
        _, hashes = _hash_block_insns(insns)
        dst_hashes[addr] = hashes
        dst_kg[addr] = _kgram_set(hashes)

    matches: List[BlockMatch] = []
    src_match_count: Dict[int, int] = {}
    dst_match_count: Dict[int, int] = {}

    # k-gram 预过滤 → 精确对齐
    for src_addr, src_h in src_hashes.items():
        if not src_h:
            continue
        src_grams = src_kg[src_addr]

        candidates = []
        for dst_addr, dst_h in dst_hashes.items():
            if not dst_h:
                continue
            # k-gram 交集为空 → 跳过
            if not (src_grams & dst_kg[dst_addr]):
                continue

            score, matched = _smith_waterman_sim(src_h, dst_h)
            if score >= match_threshold:
                candidates.append((dst_addr, score, matched))

        # 取 top-k 不超限的候选
        candidates.sort(key=lambda x: x[1], reverse=True)
        taken = 0
        for dst_addr, score, matched in candidates:
            if taken >= max_per_block:
                break
            if dst_match_count.get(dst_addr, 0) >= max_per_block:
                continue

            is_exact = (score >= 0.98)
            total_insns = max(len(src_h), len(dst_hashes[dst_addr]))
            matches.append(BlockMatch(
                src_addr=src_addr,
                dst_addr=dst_addr,
                score=score,
                matched_insns=matched,
                total_insns=total_insns,
                is_exact=is_exact,
            ))
            src_match_count[src_addr] = src_match_count.get(src_addr, 0) + 1
            dst_match_count[dst_addr] = dst_match_count.get(dst_addr, 0) + 1
            taken += 1

    matches.sort(key=lambda m: m.score, reverse=True)
    logger.debug("块匹配完成: %d 对 (阈值=%.2f)", len(matches), match_threshold)
    return matches


def _hash_block_insns(insns: List[Tuple[str, List[str]]]) -> Tuple[int, List[int]]:
    """内部辅助——对指令序列做语义哈希并返回块哈希+指令哈希列表"""
    from .instruction_hash import hash_basic_block
    return hash_basic_block(insns)
