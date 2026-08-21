#
# 秘密依赖循环检测 - 检测循环的迭代次数是否受秘密数据影响
#
# 违规条件：
#   (a) 循环计数器（ECX/RCX for rep, 或显式循环变量）被秘密数据污染
#   (b) 循环出口条件（cmp/jcc 对）的比较操作数被污染
#   (c) rep 前缀指令（rep movs/stos/scas/cmps）的 CX/ECX/RCX 被污染
#
# 循环识别：
# 使用简化的循环检测：后向跳转（jcc 目标地址 < jcc 自身地址）即为循环尾
# 这不是结构化的循环分析（那需要 CFG + 支配树），但作为快速扫描足够
#
"ROBOV: Robust Binary Code Against Speculat Execu";
# 侧信道中的循环泄密（loop leakage）可在几秒内推断 RSA 密钥长度

import logging
from typing import Dict, List, Set, Tuple
from dataclasses import dataclass, field

from .secret_tracker import SecretTaint

logger = logging.getLogger(__name__)


@dataclass
class LoopViolation:
    """一个秘密依赖循环的违规记录"""
    func_name: str
    loop_header_addr: int    # 循环头（跳转目标）的地址
    loop_tail_addr: int      # 循环尾（条件跳转）的地址
    secret_source: str
    taint_depth: int
    severity: str
    detail: str


def check_secret_dependent_loops(
    func_name: str,
    insns: List[Tuple[str, List[str]]],
    taints: Dict[str, SecretTaint],
    func_addr: int = 0,
) -> List[LoopViolation]:
    """检测秘密依赖的循环结构

    两种模式：
    1. 显式循环：后向条件跳转 + cmp/test 操作数被污染
    2. rep 前缀：ECX/RCX 被秘密污染
    """
    violations = []

    # 模式 1: 显式循环-后向跳转 + 污染的比较操作数
    for offset, (mn, ops) in enumerate(insns):
        mn_lower = mn.lower()

        # 后向条件跳转
        if mn_lower in ('je', 'jne', 'jg', 'jge', 'jl', 'jle',
                        'ja', 'jae', 'jb', 'jbe', 'loop', 'loope', 'loopne'):
            if not ops:
                continue
            target = ops[-1].strip()
            try:
                target_addr = int(target, 16) if target.startswith('0x') else None
            except ValueError:
                target_addr = None

            if target_addr is None:
                continue

            insn_addr = func_addr + offset * 4
            if target_addr < insn_addr:
                # 后向跳转 = 循环尾
                # 检查紧邻前的 cmp/test 操作数
                if offset > 0:
                    prev_mn, prev_ops = insns[offset - 1]
                    if prev_mn.lower() in ('cmp', 'test', 'cmn', 'tst'):
                        for op in prev_ops:
                            if op in taints:
                                violations.append(LoopViolation(
                                    func_name=func_name,
                                    loop_header_addr=target_addr,
                                    loop_tail_addr=insn_addr,
                                    secret_source=str(taints[op].sources),
                                    taint_depth=taints[op].depth,
                                    severity='HIGH',
                                    detail=f'循环条件(prev cmp {op})被秘密数据污染',
                                ))
                                break

    # 模式 2: rep 前缀-ECX/RCX 被秘密污染
    rep_regs = {'ecx', 'rcx', 'cx'}
    for offset, (mn, ops) in enumerate(insns):
        if mn.lower().startswith('rep'):
            for reg in rep_regs:
                if reg in taints:
                    violations.append(LoopViolation(
                        func_name=func_name,
                        loop_header_addr=func_addr + offset * 4,
                        loop_tail_addr=func_addr + offset * 4,
                        secret_source=str(taints[reg].sources),
                        taint_depth=taints[reg].depth,
                        severity='HIGH',
                        detail=f'{mn}: {reg} 被秘密数据污染 → 迭代次数可变',
                    ))
                    break

    return violations
