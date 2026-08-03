#
# 秘密依赖分支检测 —— 检测秘密数据是否影响条件跳转的目标
#
# 违规条件: 秘密污点数据流到达以下指令的操作数时：
#   (a) jcc/jmp reg —— 条件/间接跳转
#   (b) call reg / call [mem] —— 间接调用（通过函数指针表的分发可能泄露）
#   (c) cmovcc —— 条件移动（不视为违规——无控制流分歧）
#   (d) setcc —— 字节级条件设置（不视为违规——原因同 cmovcc）
#
# 假阳性管理：
#   - 区分"秘密数据直接作为分支条件"（真违规）vs "秘密数据偶然在分支指令附近的
# 非条件寄存器中"（假阳性）。当前的启发式偏保守——宁可多报
# - 排除编译器插入的栈检查（__chkstk）和 CFI 指令
#
# ref: "Towards Verified Constant-Time Implementa" (Protzenko et al., 2020);
# Jasmin language semantics — 常量时间作为类型系统属性

import logging
from typing import Dict, List, Set, Tuple
from dataclasses import dataclass, field

from .secret_tracker import SecretTaint

logger = logging.getLogger(__name__)


@dataclass
class BranchViolation:
    """一个秘密依赖分支的违规记录"""
    func_name: str
    insn_address: int
    insn_text: str          # 如 'je 0x401000'
    secret_source: str      # 导致此分支的秘密源
    taint_depth: int        # 从秘密源到此分支的传播步数
    severity: str           # 'HIGH' | 'MEDIUM' | 'LOW'


# 不视为分支违规的条件移动/设置指令
_NON_BRANCHING_CONDITIONAL = {'cmov', 'cmove', 'cmovne', 'cmovg', 'cmovge',
                               'cmovl', 'cmovle', 'cmova', 'cmovae', 'cmovb',
                               'cmovbe', 'cmovo', 'cmovno', 'cmovs', 'cmovns',
                               'cmovp', 'cmovnp', 'cmovz', 'cmovnz',
                               'sete', 'setne', 'setg', 'setge', 'setl', 'setle',
                               'seta', 'setae', 'setb', 'setbe', 'seto', 'setno',
                               'sets', 'setns', 'setp', 'setnp'}

# 编译器栈检查忽略列表
_IGNORE_CALLEES = {'__chkstk', '__stack_chk_fail', '__chkstk_ms'}


def check_secret_dependent_branches(
    func_name: str,
    insns: List[Tuple[str, List[str]]],
    taints: Dict[str, SecretTaint],
    func_addr: int = 0,
) -> List[BranchViolation]:
    """检查函数中是否存在秘密依赖的分支指令
    
    对每条条件/间接跳转指令，检查其操作数是否被秘密数据污染
    """
    violations = []

    # 条件跳转助记符模式
    branch_mnemonics = {'je', 'jne', 'jg', 'jge', 'jl', 'jle', 'ja', 'jae',
                         'jb', 'jbe', 'jo', 'jno', 'js', 'jns', 'jp', 'jnp',
                         'jcxz', 'jecxz', 'jrcxz', 'jmp', 'loop', 'loope',
                         'loopne', 'call', 'ret'}

    for offset, (mn, ops) in enumerate(insns):
        mn_lower = mn.lower()

        # 跳过已知的非违规指令
        if mn_lower in _NON_BRANCHING_CONDITIONAL:
            continue

        # 间接跳转/调用: jmp reg, call reg, jmp [mem], call [mem]
        if (mn_lower in ('jmp', 'call') and len(ops) >= 1 and
            ops[0] in taints):
            violations.append(BranchViolation(
                func_name=func_name,
                insn_address=func_addr + offset * 4,
                insn_text=f'{mn} {", ".join(ops)}',
                secret_source=str(taints[ops[0]].sources),
                taint_depth=taints[ops[0]].depth,
                severity='HIGH',
            ))
            continue

        # 跳过已知的非关键调用
        if mn_lower == 'call' and ops:
            callee = ops[0].strip('<>"').split('.')[-1]
            if callee in _IGNORE_CALLEES:
                continue

        # 条件跳转——秘密在 flags 中
        # 检查紧邻前的 cmp/test 指令的源操作数是否被污染
        if mn_lower in branch_mnemonics and offset > 0:
            prev_mn, prev_ops = insns[offset - 1]
            if prev_mn.lower() in ('cmp', 'test', 'cmn', 'tst'):
                for op in prev_ops:
                    if op in taints:
                        violations.append(BranchViolation(
                            func_name=func_name,
                            insn_address=func_addr + offset * 4,
                            insn_text=f'{mn} {", ".join(ops)} (prev: {prev_mn} {", ".join(prev_ops)})',
                            secret_source=str(taints[op].sources),
                            taint_depth=taints[op].depth,
                            severity='MEDIUM',
                        ))
                        break

    return violations
