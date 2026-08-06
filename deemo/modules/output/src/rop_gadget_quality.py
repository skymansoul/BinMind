"""
ROP 小工具质量评分 — 寄存器效应 × 副作用 × 语义分类 × 链兼容性。

问题定义:
  ROPgadget 和 ropper 输出成千上万条小工具 (gadget) 但只提供原始列表。
  利用者需要手工筛选高质量小工具 — 这是一个耗时且依赖经验的过程。
  本模块提供自动化的四维质量评分，输出排序后的优质小工具集合。

  四个维度:
    1. 寄存器效应 (register_effect): 该小工具修改/保存了哪些寄存器
       — 保存关键寄存器 → 高分；破坏栈指针 → 低分
    2. 副作用 (side_effects): 内存写入/分支/标志位修改
       — 无副作用 → 高分 (干净小工具)
    3. 语义分类 (semantic_class): 算术/加载/存储/系统调用/栈操作
       — 不同利用阶段需要不同类的小工具
    4. 链兼容性 (chain_compatibility): 该小工具能否无缝链接下一个
       — ret 结尾 + 栈增量已知 → 高分

  小工具质量分 (GQF) = w1×reg_score + w2×side_score
                       + w3×semantic_score + w4×chain_score

与现有工具的区分:
  ROPgadget/ropper: 查找小工具，不评分
  ARCANIST (USENIX 2025): 自动合成 gadget chain — 重量级, 需要符号执行
  本模块: 轻量启发式评分，报告阶段使用

参考:
  ARCANIST (Bailluet et al., USENIX 2025): automated gadget chain synthesis
  MAJORCA (arXiv 2021): multi-arch JOP/ROP chain assembler

修改记录:
  2026-08-02 16:34 - 初始版本，四维小工具质量模型
"""

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, FrozenSet, List, Optional, Set, Tuple


class GadgetClass(Enum):
    LOAD = "load"            # pop/mov from memory → 加载控制值
    STORE = "store"          # mov to memory → 写入原语
    ARITH = "arithmetic"     # add/sub/xor → 值计算
    SYSCALL = "syscall"      # syscall/int 0x80 → 系统调用
    STACK_PIVOT = "stack_pivot"  # xchg esp/mov rsp → 栈迁移
    JUMP = "jump"            # jmp/call → 间接控制转移
    NOP = "nop"              # ret only → 填充小工具
    OTHER = "other"


# 关键寄存器 — 在 ROP 链中通常承载重要值
_CRITICAL_REGS = frozenset({
    'rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rsp', 'rbp',
    'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15',
    'eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'esp', 'ebp',
})

# 破坏性指令 — 修改后降低小工具质量
_DESTRUCTIVE_INS = frozenset({
    'call', 'jmp', 'int', 'syscall', 'sysenter', 'ud2', 'hlt',
})

# x86/x64 指令 → 语义分类
_SEMANTIC_PATTERNS: List[Tuple[str, GadgetClass]] = [
    (r'\bpop\b', GadgetClass.LOAD),
    (r'\bmov\b.*\[', GadgetClass.LOAD),
    (r'\bmov\b.*\[.*\].*,', GadgetClass.STORE),
    (r'\b(add|sub|xor|and|or|shl|shr|mul|imul|div|idiv|neg|not|inc|dec)\b',
     GadgetClass.ARITH),
    (r'\b(syscall|int\s+0x80|sysenter)\b', GadgetClass.SYSCALL),
    (r'\b(xchg|mov)\b.*(esp|rsp)', GadgetClass.STACK_PIVOT),
    (r'\b(jmp|call)\b', GadgetClass.JUMP),
]


@dataclass
class GadgetQuality:
    """单个 ROP 小工具的四维质量评估。"""
    address: str                   # hex 地址
    instructions: str              # 指令序列文本
    register_score: float          # 0-1
    side_effect_score: float       # 0-1
    semantic_score: float          # 0-1
    chain_score: float             # 0-1
    gqf: float                     # 综合质量分 [0, 1]
    gadget_class: GadgetClass = GadgetClass.OTHER
    ends_with_ret: bool = True


def _parse_registers(insns: str) -> Set[str]:
    """从指令文本中提取涉及的寄存器。"""
    found = set()
    for token in re.findall(r'\b[a-z]{2,5}\b', insns.lower()):
        if token in _CRITICAL_REGS:
            found.add(token)
    return found


def _classify_gadget(insns: str) -> GadgetClass:
    """指令序列 → 语义分类。"""
    ins_lower = insns.lower()
    # 检查 ret-only
    stripped = ins_lower.strip()
    if stripped == 'ret' or stripped == 'retn':
        return GadgetClass.NOP
    for pattern, gclass in _SEMANTIC_PATTERNS:
        if re.search(pattern, ins_lower):
            return gclass
    return GadgetClass.OTHER


def score_gadget(
    address: str,
    instructions: str,
) -> GadgetQuality:
    """
    评估单个 ROP 小工具的质量。

    四维评分逻辑:
      register_score: pop 有用寄存器 → 高分；
                     破坏 rsp/ebp → 低分
      side_effect_score: 无 call/jmp/syscall → 高分
      semantic_score: 语义明确 (非 OTHER) → 高分
      chain_score: ret 结尾 + 栈增量可控 → 高分
    """
    ins_lower = instructions.lower().strip()
    regs = _parse_registers(instructions)
    gclass = _classify_gadget(instructions)

    # --- register_score ---
    has_pop = bool(re.search(r'\bpop\b', ins_lower))
    pops_useful = False
    for r in regs:
        if r not in ('rsp', 'esp', 'rbp', 'ebp') and has_pop:
            pops_useful = True
    destroys_stack = any(r in regs for r in ('rsp', 'esp'))

    if pops_useful and not destroys_stack:
        reg_score = 0.9
    elif pops_useful:
        reg_score = 0.5
    elif destroys_stack:
        reg_score = 0.2
    else:
        reg_score = 0.6

    # --- side_effect_score ---
    has_destructive = any(
        re.search(r'\b' + d + r'\b', ins_lower) for d in _DESTRUCTIVE_INS
    )
    # ret 不算破坏性，但 gadget 中间的 call/jmp 会破坏控制流
    side_score = 0.2 if has_destructive else 0.9

    # --- semantic_score ---
    if gclass == GadgetClass.OTHER:
        sem_score = 0.3
    elif gclass == GadgetClass.NOP:
        sem_score = 0.4  # filler 有用但不高价值
    elif gclass == GadgetClass.SYSCALL:
        sem_score = 0.95  # 系统调用小工具是最珍贵的
    elif gclass == GadgetClass.STACK_PIVOT:
        sem_score = 0.9
    else:
        sem_score = 0.7

    # --- chain_score ---
    ends_ret = ins_lower.endswith('ret') or ins_lower.endswith('retn')
    instr_count = len([i for i in instructions.split(';') if i.strip()])

    if ends_ret and instr_count <= 3:
        chain_score = 0.95  # 短+ret结尾 → 理想小工具
    elif ends_ret:
        chain_score = 0.7
    else:
        chain_score = 0.3  # 无ret → 需要额外小工具才能链接

    # 综合 (等权)
    gqf = round(0.25 * reg_score + 0.25 * side_score
                + 0.25 * sem_score + 0.25 * chain_score, 4)

    return GadgetQuality(
        address=address,
        instructions=instructions,
        register_score=round(reg_score, 2),
        side_effect_score=round(side_score, 2),
        semantic_score=round(sem_score, 2),
        chain_score=round(chain_score, 2),
        gqf=gqf,
        gadget_class=gclass,
        ends_with_ret=ends_ret,
    )


def score_gadgets(
    gadgets: List[Dict[str, str]],
    min_gqf: float = 0.3,
) -> List[GadgetQuality]:
    """
    批量评分 — 过滤低质量小工具并排序。

    gadgets: [{'address': '0x...', 'instructions': 'pop rdi; ret'}, ...]
    """
    results = []
    for g in gadgets:
        q = score_gadget(g.get('address', '0x0'), g.get('instructions', ''))
        if q.gqf >= min_gqf:
            results.append(q)
    results.sort(key=lambda q: q.gqf, reverse=True)
    return results


def gadget_class_summary(scored: List[GadgetQuality]) -> Dict[str, Any]:
    """小工具分类统计 + 利用阶段推荐。"""
    if not scored:
        return {'total': 0, 'classes': {}, 'exploit_readiness': 'insufficient'}

    from collections import Counter
    classes = Counter(g.gadget_class.value for g in scored)

    # 利用准备度: 需要至少 load+arith+syscall 三类
    needed = {'load', 'arithmetic', 'syscall'}
    has = {g.gadget_class.value for g in scored}
    readiness = 'ready' if needed.issubset(has) else (
        'partial' if len(has & needed) >= 2 else 'insufficient'
    )

    return {
        'total': len(scored),
        'max_gqf': max(g.gqf for g in scored),
        'class_distribution': dict(classes),
        'exploit_readiness': readiness,
        'top_gadgets': [
            {'addr': g.address, 'gqf': g.gqf, 'class': g.gadget_class.value,
             'insns': g.instructions[:60]}
            for g in scored[:5]
        ],
    }
