"""
栈迁移难度评估 — 小工具可用性×寄存器约束×控制流完整性惩罚。

问题定义:
  栈缓冲区溢出 → 覆盖返回地址 → ROP 链。
  但当溢出空间不足时，需要"栈迁移" — 将 rsp 重定向到攻击者
  控制的缓冲区 (堆/全局变量/其他栈区域)。

  不同二进制提供不同的迁移小工具和约束:
    - pop rsp; ret  — 最直接的迁移 (需要2个qword: gadget addr + target addr)
    - leave; ret    — 需要控制 rbp (1个寄存器约束)
    - xchg esp, eax; ret — 需要控制 eax+已知的 eax 值
    - ENTER-based   — Linux 内核特化 (0x100ff 字节位移)

  本模块提供第一个栈迁移难度评估模型: 基于可用小工具类型、
  寄存器控制程度、缓冲区和 CFI 惩罚的综合评分。

参考:
  Linux kernel ENTER pivot: 0x100ff byte max displacement (2024 patchew)
  ebpf-stack-pivot-detection: 运行时检测 (2024-2025)
  ARCANIST (USENIX 2025): gadget chain synthesis 但无迁移评分

修改记录:
  2026-08-01 14:23 - 初始版本，四类迁移小工具 + CFI 惩罚模型
"""

import math
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple


class PivotGadgetType(Enum):
    POP_RSP = "pop_rsp"          # pop rsp; ret — 最优
    LEAVE_RET = "leave_ret"      # leave; ret — 需要 rbp 控制
    XCHG_ESP = "xchg_esp"        # xchg esp, eax; ret — 需要 eax 控制
    ENTER = "enter"              # ENTER imm16, imm8 — 内核特化
    JMP_REG = "jmp_reg"          # jmp reg — 间接跳转
    NONE = "none"                # 未找到可用的迁移小工具


# 小工具类型 → 基础难度 (0-10, 越低越难/越高越容易)
_PIVOT_BASE_DIFFICULTY: Dict[PivotGadgetType, float] = {
    PivotGadgetType.POP_RSP:   8.0,  # 最低难度 — 直接 RSP 控制
    PivotGadgetType.LEAVE_RET: 6.5,  # 中低难度 — 需 rbp 控制
    PivotGadgetType.XCHG_ESP:  4.5,  # 中等难度 — 需 eax+值控制
    PivotGadgetType.ENTER:     3.0,  # 中高难度 — 受限位移 + 内核特化
    PivotGadgetType.JMP_REG:   2.5,  # 高难度 — 间接跳转
    PivotGadgetType.NONE:      0.5,  # 无可用小工具 — 几乎不可能
}


@dataclass
class PivotDifficulty:
    """栈迁移难度评估。"""
    gadget_type: PivotGadgetType
    pivot_feasibility: float           # 0-10, 越高越可行
    register_constraints: List[str]    # 需要的寄存器控制
    buffer_adequacy: float             # 0-1, 缓冲区是否够大
    cfi_penalty: float                 # CFI/CET 惩罚分
    overall_difficulty: float          # 0-10, 越高越难
    mitigation_bypass_required: List[str] = field(default_factory=list)
    estimated_gadget_chain_length: int = 3


def _detect_pivot_gadgets(
    available_gadgets: Optional[List[Dict[str, str]]] = None,
    has_pop_rsp: bool = False,
    has_leave_ret: bool = False,
    has_xchg_esp: bool = False,
) -> PivotGadgetType:
    """从可用小工具集合中确定最佳迁移类型。"""
    gadgets_lower = ''
    if available_gadgets:
        gadgets_lower = ' '.join(
            g.get('instructions', '') for g in available_gadgets
        ).lower()

    if has_pop_rsp or 'pop rsp' in gadgets_lower or 'pop esp' in gadgets_lower:
        return PivotGadgetType.POP_RSP
    if has_leave_ret or ('leave' in gadgets_lower and 'ret' in gadgets_lower):
        return PivotGadgetType.LEAVE_RET
    if has_xchg_esp or 'xchg esp' in gadgets_lower or 'xchg eax, esp' in gadgets_lower:
        return PivotGadgetType.XCHG_ESP
    if 'enter' in gadgets_lower:
        return PivotGadgetType.ENTER

    # 间接跳转: jmp rax/rbx/rcx/rdx
    for reg in ('rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi'):
        if f'jmp {reg}' in gadgets_lower or f'call {reg}' in gadgets_lower:
            return PivotGadgetType.JMP_REG

    return PivotGadgetType.NONE


def _register_constraints(gtype: PivotGadgetType) -> List[str]:
    return {
        PivotGadgetType.POP_RSP: ['rsp (via overflow)'],
        PivotGadgetType.LEAVE_RET: ['rbp', 'rsp (via overflow)'],
        PivotGadgetType.XCHG_ESP: ['eax', 'rsp (via overflow)'],
        PivotGadgetType.ENTER: ['rsp (limited displacement)'],
        PivotGadgetType.JMP_REG: ['rax|rbx|rcx|rdx', 'rsp (via overflow)'],
        PivotGadgetType.NONE: [],
    }.get(gtype, [])


def _cfi_penalty(
    has_cfg: bool = False,
    has_cet_shadow_stack: bool = False,
    has_cet_ibt: bool = False,
    is_kernel: bool = False,
) -> float:
    """
    CFI/CET 惩罚 — 每种缓解增加迁移难度。

    CET Shadow Stack → 最强制约 (ret 必须匹配 call)。
    CET IBT → 间接跳转需要 ENDBR64。
    CFG → 间接调用受限。
    """
    penalty = 0.0
    if has_cfg:
        penalty += 1.5
    if has_cet_shadow_stack:
        penalty += 2.5
    if has_cet_ibt:
        penalty += 1.5
    if is_kernel:
        if has_cfg:
            penalty += 0.5  # 内核 CFI 额外惩罚
    return min(penalty, 6.0)


def assess_stack_pivot(
    available_gadgets: Optional[List[Dict[str, str]]] = None,
    has_pop_rsp: bool = False,
    has_leave_ret: bool = False,
    has_xchg_esp: bool = False,
    overflow_bytes: int = 0,
    chain_required_bytes: int = 96,
    has_cfg: bool = False,
    has_cet_shadow_stack: bool = False,
    has_cet_ibt: bool = False,
    is_kernel: bool = False,
) -> PivotDifficulty:
    """
    评估栈迁移的可行性和难度。

    overflow_bytes: 溢出缓冲区大小 (bytes)
    chain_required_bytes: 所需 ROP 链大小 (default 96 = ~12 qwords)
    """
    gtype = _detect_pivot_gadgets(
        available_gadgets, has_pop_rsp, has_leave_ret, has_xchg_esp
    )
    base_diff = _PIVOT_BASE_DIFFICULTY[gtype]
    regs = _register_constraints(gtype)

    # 缓冲区充足度
    buf_ratio = overflow_bytes / chain_required_bytes if chain_required_bytes > 0 else 1.0
    buffer_adequacy = min(buf_ratio / 2.0, 1.0) if buf_ratio >= 2.0 else buf_ratio

    # 缓冲区不足 → 必须迁移 → 难度取决于迁移小工具
    if buf_ratio >= 1.0:
        # 缓冲区足够 → 不需要迁移
        overall = 1.0 + _cfi_penalty(has_cfg, has_cet_shadow_stack, has_cet_ibt, is_kernel)
    else:
        # 必须迁移 → 难度 = 迁移难度 + CFI 惩罚
        difficulty = 10.0 - base_diff
        cfi = _cfi_penalty(has_cfg, has_cet_shadow_stack, has_cet_ibt, is_kernel)
        overall = difficulty + cfi + (1.0 - buffer_adequacy) * 3.0

    overall = round(max(0.0, min(10.0, overall)), 1)
    feasibility = round(max(0.0, 10.0 - overall), 1)

    bypasses = []
    if has_cet_shadow_stack:
        bypasses.append('CET Shadow Stack — 需要 call/ret 配对或 shadow stack 绕过')
    if has_cet_ibt:
        bypasses.append('CET IBT — 间接跳转目标需要 ENDBR64')
    if has_cfg:
        bypasses.append('CFG — 间接调用须指向 whitelist 目标')

    chain_len = 3 if buf_ratio >= 1.0 else (5 if buffer_adequacy > 0.5 else 8)

    return PivotDifficulty(
        gadget_type=gtype,
        pivot_feasibility=feasibility,
        register_constraints=regs,
        buffer_adequacy=round(buffer_adequacy, 2),
        cfi_penalty=round(_cfi_penalty(has_cfg, has_cet_shadow_stack, has_cet_ibt, is_kernel), 1),
        overall_difficulty=overall,
        mitigation_bypass_required=bypasses,
        estimated_gadget_chain_length=chain_len,
    )


def pivot_summary(pd: PivotDifficulty) -> Dict[str, Any]:
    """栈迁移评估摘要。"""
    if pd.overall_difficulty <= 2.0:
        verdict = 'trivial — 无需迁移或迁移极为简单'
    elif pd.overall_difficulty <= 4.0:
        verdict = 'easy — 标准迁移技术可达成'
    elif pd.overall_difficulty <= 6.0:
        verdict = 'moderate — 需要精心选择小工具和布局'
    elif pd.overall_difficulty <= 8.0:
        verdict = 'hard — 需要绕过 CFI 缓解措施'
    else:
        verdict = 'extreme — 在当前缓解下几乎不可行'

    return {
        'overall_difficulty': pd.overall_difficulty,
        'pivot_feasibility': pd.pivot_feasibility,
        'verdict': verdict,
        'gadget_type': pd.gadget_type.value,
        'register_constraints': pd.register_constraints,
        'buffer_adequacy': pd.buffer_adequacy,
        'cfi_penalty': pd.cfi_penalty,
        'mitigations_to_bypass': pd.mitigation_bypass_required,
        'estimated_chain_length': pd.estimated_gadget_chain_length,
    }
