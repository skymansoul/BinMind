#
# Patch 分类器 —— 基于函数级差异推断补丁类型
#
# 分类粒度：
#   SECURITY_FIX: 安全修复 —— 增加边界检查、空指针检查、整数溢出检查、
#                 改变内存操作的大小参数、增加 canary 检查
#   FEATURE_CHANGE: 功能变更 —— 新增/移除调用、常量值变化
#   REFACTOR: 重构 —— 大量块变化但调用图不变
#   BUG_FIX: 非安全的普通 bug 修复 —— 小幅逻辑调整
#   UNKNOWN: 无法归类
#
# 核心启发式规则（由 diff 结果 + 指令模式匹配驱动）：
#   1. 分支条件中 cmp 操作数变大 + 函数块数不变 → 边界检查加固 → SECURITY_FIX
# 2. 新增 call 到 __栈_chk_fail → SECURITY_FIX
#   3. 新增对 0/nullptr 的比较分支 → SECURITY_FIX (空指针检查)
#   4. 移除对危险函数（system/popen/execve）的调用 → SECURITY_FIX
#   5. 仅常量变化 + 无新增检查 → FEATURE_CHANGE
#
# ref: 这些启发式与 Google Project Zero 的 "patch gap" 分析方法一脉相承
# 但 Project Zero 依赖人工审查，本项目将其自动化并量化可 exploitabili

import logging
from typing import List, Dict, Tuple, Optional, Set
from dataclasses import dataclass
from enum import Enum, auto

from .func_differ import FuncDiffResult, EditOp
from .block_matcher import BlockMatch

logger = logging.getLogger(__name__)


class PatchType(Enum):
    SECURITY_FIX = auto()
    BUG_FIX = auto()
    FEATURE_CHANGE = auto()
    REFACTOR = auto()
    UNKNOWN = auto()


@dataclass
class PatchClassification:
    """一个补丁的分类结果"""
    func_name: str
    patch_type: PatchType
    confidence: float     # [0, 1]
    evidence: List[str]   # 分类所依据的启发式证据
    diff_result: FuncDiffResult


# ==============================================================================
# 安全修复的启发式特征词表
# ==============================================================================

# 新增这些比较 → 大概率是安全加固（边界/空指针检查）
_BOUNDS_CHECK_INSNS = {'cmp', 'test', 'cmn', 'tst'}

# 调用这些函数表明栈保护被触发 → 安全修复
_SECURITY_CHECK_FUNCS = {
    '__stack_chk_fail', '__stack_chk_fail_local',
    '__fortify_fail', '__chk_fail', '__memcpy_chk',
    '__memset_chk', '__strcpy_chk', '__sprintf_chk',
    '_CxxThrowException', '__cxa_throw',
    '__assert_fail', '__assert_perror_fail',
}

# 移除这些函数的调用 → 可能是安全修复（去除危险行为）
_DANGEROUS_CALLEES = {
    'system', 'popen', 'execve', 'execvp', 'execl',
    'strcpy', 'strcat', 'sprintf', 'vsprintf', 'gets',
    'scanf', 'sscanf',
}


def _check_bounds_hardening(diff: FuncDiffResult,
                            src_blocks: Dict, dst_blocks: Dict) -> Tuple[bool, str]:
    """检测边界检查加固：cmp 立即数变大 + 紧随的 jcc 保持不变
    
    返回 (is_hardened, detail_str)
    """
    # 此段需要在块匹配之外做指令级比较——匹配块中找到 cmp/jcc 对的变化
    # 这里用简化的模式：寻找匹配块中新增的 cmp 指令
    if diff.edit_op not in (EditOp.MODIFIED, EditOp.BLOCKS_ADDED):
        return False, ''

    for match in diff.block_matches:
        src_insns = src_blocks.get(match.src_addr, [])
        dst_insns = dst_blocks.get(match.dst_addr, [])

        # 从 dst 中找到 src 中没有的 cmp/test 指令
        src_ops = {insn[0] for insn in src_insns}
        for mn, ops in dst_insns:
            if mn in _BOUNDS_CHECK_INSNS and mn not in src_ops:
                # 检查操作数中是否有"边界值"（常见于数组索引检查）
                for op_str in ops:
                    if '0x' in op_str or op_str.strip().isdigit():
                        return True, f"新增 {mn} 比较指令，疑似边界检查: 块 {hex(match.dst_addr)}"

    return False, ''


def _check_security_function_added(diff: FuncDiffResult,
                                   dst_blocks: Dict) -> Tuple[bool, str]:
    """检测是否新增了对安全相关函数的调用"""
    for addr, insns in dst_blocks.items():
        for mn, ops in insns:
            if mn == 'call' and ops:
                callee = ops[0].strip('<>"')
                # 取函数名的最后一部分（去掉 plt/imp 前缀）
                func_name = callee.split('.')[-1].split('@')[-1] if '.' in callee or '@' in callee else callee
                if func_name in _SECURITY_CHECK_FUNCS:
                    return True, f"新增安全函数调用: {func_name}"
    return False, ''


def _check_dangerous_call_removed(diff: FuncDiffResult,
                                  src_blocks: Dict, dst_blocks: Dict) -> Tuple[bool, str]:
    """检测是否移除了对危险函数的调用"""
    src_callees = set()
    dst_callees = set()
    for insns in src_blocks.values():
        for mn, ops in insns:
            if mn == 'call' and ops:
                src_callees.add(ops[0].strip('<>"').split('.')[-1])
    for insns in dst_blocks.values():
        for mn, ops in insns:
            if mn == 'call' and ops:
                dst_callees.add(ops[0].strip('<>"').split('.')[-1])

    removed = src_callees - dst_callees
    dangerous_removed = removed & _DANGEROUS_CALLEES
    if dangerous_removed:
        return True, f"移除危险函数调用: {', '.join(dangerous_removed)}"
    return False, ''


def classify_patch(diff: FuncDiffResult,
                   src_blocks: Dict = None,
                   dst_blocks: Dict = None) -> PatchClassification:
    """将函数差异归类为补丁类型
    
    参数:
    diff: 函数差异结果
    src_blocks: 源版本的基本块指令数据（用于指令级启发式）
    dst_blocks: 目标版本的基本块指令数据
    
    返回 PatchClassifica 包含类型、置信度和证据链
    """
    if src_blocks is None:
        src_blocks = {}
    if dst_blocks is None:
        dst_blocks = {}

    evidence = []
    security_score = 0.0

    # 启发式 1: 边界检查加固
    is_bound, msg = _check_bounds_hardening(diff, src_blocks, dst_blocks)
    if is_bound:
        evidence.append(msg)
        security_score += 0.35

    # 启发式 2: 安全函数调用增加
    is_sec_func, msg = _check_security_function_added(diff, dst_blocks)
    if is_sec_func:
        evidence.append(msg)
        security_score += 0.40

    # 启发式 3: 危险函数调用移除
    is_danger, msg = _check_dangerous_call_removed(diff, src_blocks, dst_blocks)
    if is_danger:
        evidence.append(msg)
        security_score += 0.25

    # 启发式 4: 基于编辑类型和相似度推断
    if diff.edit_op == EditOp.IDENTICAL:
        patch_type = PatchType.UNKNOWN
        confidence = 0.0
    elif diff.edit_op == EditOp.REFACTORED:
        patch_type = PatchType.REFACTOR
        confidence = 0.75 if security_score < 0.3 else 0.4
    elif security_score >= 0.35:
        patch_type = PatchType.SECURITY_FIX
        confidence = min(security_score, 0.95)
    elif diff.edit_op == EditOp.MODIFIED and diff.similarity > 0.7:
        patch_type = PatchType.BUG_FIX
        confidence = 0.5 + (diff.similarity - 0.7) * 1.5
    elif diff.edit_op == EditOp.BLOCKS_ADDED and security_score < 0.2:
        patch_type = PatchType.FEATURE_CHANGE
        confidence = 0.5
    else:
        patch_type = PatchType.UNKNOWN
        confidence = 0.3

    if not evidence:
        evidence.append(f"{diff.edit_op.name}: {diff.detail}")

    return PatchClassification(
        func_name=diff.func_name,
        patch_type=patch_type,
        confidence=round(confidence, 3),
        evidence=evidence,
        diff_result=diff,
    )
