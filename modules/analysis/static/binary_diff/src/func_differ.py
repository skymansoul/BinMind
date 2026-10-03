#
# 函数级差异 - 将块匹配提升到函数级编辑脚本
#
# 两个版本的同一函数之间产生以下编辑操作之一：
#   MODIFIED: 至少一个基本块被修改，但调用图上下文不变
#   BLOCKS_ADDED: 目标版本新增了基本块（可能是新分支路径或内联展开）
#   BLOCKS_REMOVED: 源版本的某些块在目标版本中消失（可能是死代码消除）
#   REFACTORED: 50%+ 的基本块改变但函数语义签名不变（调用相同子函数、相同栈帧大小）
# IDENT: 所有块的语义哈希一致
#
# diff_pipeline 是面向两个完整二进制文件的入口-它需要：
#   前置条件：两个二进制文件的反汇编输出（Capstone 或 r2 均可）
# 输出：按 漏洞利用abili 排序的 patch 列表

import logging
from typing import Dict, List, Tuple, Optional, Callable
from dataclasses import dataclass, field
from enum import Enum, auto

from .instruction_hash import semantic_hash_insn, hash_basic_block
from .block_matcher import match_blocks, BlockMatch

logger = logging.getLogger(__name__)


class EditOp(Enum):
    IDENTICAL = auto()
    MODIFIED = auto()
    BLOCKS_ADDED = auto()
    BLOCKS_REMOVED = auto()
    REFACTORED = auto()


@dataclass
class FuncDiffResult:
    """一个函数的差异结果"""
    func_name: str
    src_addr: int
    dst_addr: Optional[int]  # 如果目标中不存在匹配函数则为 None
    edit_op: EditOp
    similarity: float           # [0, 1] 块级 Jaccard 相似度
    matched_blocks: int
    total_src_blocks: int
    total_dst_blocks: int
    block_matches: List[BlockMatch] = field(default_factory=list)
    detail: str = ''            # 人类可读的差异描述


def _block_jaccard(matches: List[BlockMatch],
                   src_total: int, dst_total: int) -> float:
    """块级 Jaccard 相似度 = |匹配| / (|src| + |dst| - |匹配|)"""
    if src_total + dst_total == 0:
        return 1.0
    unique_matched = len(set((m.src_addr, m.dst_addr) for m in matches))
    return unique_matched / (src_total + dst_total - unique_matched)


def _classify_edit(similarity: float, matched: int,
                   src_n: int, dst_n: int,
                   shared_calls: int = 0, total_calls: int = 0) -> EditOp:
    """根据块级相似度和调用上下文分类编辑操作类型

    关键是 REFACTORED 的识别-当块变化大但调用图上下文不变时
    可能是重构（循环展开、内联/去内联等），而非安全修复
    """
    if similarity >= 0.98:
        return EditOp.IDENTICAL
    if src_n < dst_n and similarity > 0.3:
        return EditOp.BLOCKS_ADDED
    if src_n > dst_n and similarity > 0.3:
        return EditOp.BLOCKS_REMOVED
    if similarity < 0.5:
        # 如果调用图上下文保持不变但块变化大 → 重构
        if total_calls > 0 and shared_calls / total_calls >= 0.7:
            return EditOp.REFACTORED
    return EditOp.MODIFIED


def diff_functions(
    src_name: str,
    src_addr: int,
    src_blocks: Dict[int, List[Tuple[str, List[str]]]],
    dst_name: str,
    dst_addr: Optional[int],
    dst_blocks: Dict[int, List[Tuple[str, List[str]]]],
    src_calls: Optional[set] = None,
    dst_calls: Optional[set] = None,
) -> FuncDiffResult:
    """比较一个函数的两个版本

    参数:
    src_name, src_addr: 源函数名称和地址
    src_blocks: {addr: [(mnemonic, [ops.]),.]} 源函数的基本块
    dst_name, dst_addr: 目标函数名称和地址（可能为 None 如果未找到）
    dst_blocks: 目标函数的基本块
    src_calls, dst_calls: 被调用函数集合（用于 REFACTORED 检测）

    如果目标中不存在对应的函数，返回 BLOCKS_REMOVED 且 similari=0
    """
    if dst_addr is None or not dst_blocks:
        return FuncDiffResult(
            func_name=src_name, src_addr=src_addr, dst_addr=None,
            edit_op=EditOp.BLOCKS_REMOVED, similarity=0.0,
            matched_blocks=0, total_src_blocks=len(src_blocks),
            total_dst_blocks=0,
            detail="目标二进制中未找到对应函数",
        )

    src_n = len(src_blocks)
    dst_n = len(dst_blocks)

    # 自适应阈值：函数越大容差越低-大函数中匹配标准应更严格
    adaptive_threshold = 0.45 - min(src_n, dst_n) * 0.005
    adaptive_threshold = max(adaptive_threshold, 0.30)

    matches = match_blocks(src_blocks, dst_blocks, match_threshold=adaptive_threshold)
    similarity = _block_jaccard(matches, src_n, dst_n)

    # 调用图上下文比较
    shared_calls = 0
    total_calls = 0
    if src_calls is not None and dst_calls is not None:
        total_calls = len(src_calls | dst_calls)
        shared_calls = len(src_calls & dst_calls) if total_calls > 0 else 0

    edit_op = _classify_edit(similarity, len(matches), src_n, dst_n,
                              shared_calls, total_calls)

    # 构造人类可读的 detail
    if edit_op == EditOp.IDENTICAL:
        detail = "函数未变化"
    elif edit_op == EditOp.BLOCKS_ADDED:
        detail = f"新增 {dst_n - src_n} 个基本块（从 {src_n}→{dst_n}）"
    elif edit_op == EditOp.BLOCKS_REMOVED:
        detail = f"移除 {src_n - dst_n} 个基本块（从 {src_n}→{dst_n}）"
    elif edit_op == EditOp.REFACTORED:
        detail = f"重构-{src_n - len(matches)}/{src_n} 个块变化，但调用上下文不变"
    else:
        detail = f"{len(matches)}/{max(src_n, dst_n)} 个块匹配，{src_n - len(matches)} 个块变化"

    return FuncDiffResult(
        func_name=src_name, src_addr=src_addr, dst_addr=dst_addr,
        edit_op=edit_op, similarity=similarity,
        matched_blocks=len(matches),
        total_src_blocks=src_n, total_dst_blocks=dst_n,
        block_matches=matches, detail=detail,
    )


def diff_pipeline(
    src_functions: Dict[str, Tuple[int, Dict, Optional[set]]],
    dst_functions: Dict[str, Tuple[Optional[int], Dict, Optional[set]]],
    progress_callback: Optional[Callable[[int, int], None]] = None,
) -> List[FuncDiffResult]:
    """对两个二进制文件的所有函数做差异分析

    参数:
    src_functions: {name: (addr, {block_addr: insns}, calls_set)}
    dst_functions: {name: (addr_or_None, {block_addr: insns}, calls_set)}
    progress_回调: 可选回调 (current, total) 用于 CLI 进度显示

    返回 FuncDiffResult 列表-仅包含有差异的函数（edit_op!= IDENT）
    """
    results = []
    total = len(src_functions)

    for idx, (name, (src_addr, src_blocks, src_calls)) in enumerate(src_functions.items()):
        dst_info = dst_functions.get(name)
        if dst_info is not None:
            dst_addr, dst_blocks, dst_calls = dst_info
        else:
            dst_addr, dst_blocks, dst_calls = None, {}, set()

        result = diff_functions(
            name, src_addr, src_blocks,
            name, dst_addr, dst_blocks,
            src_calls, dst_calls,
        )

        if result.edit_op != EditOp.IDENTICAL:
            results.append(result)

        if progress_callback:
            progress_callback(idx + 1, total)

    logger.info("差异分析完成: %d/%d 个函数有变化", len(results), total)
    return results
