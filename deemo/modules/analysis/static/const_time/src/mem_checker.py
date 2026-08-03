#
# 秘密依赖访存检测 —— 检测秘密数据是否用作内存访问的地址或偏移
#
# 违规条件：秘密污点出现在以下位置时：
#   (a) [reg] 中 reg 被污染 —— 以秘密值为地址读取内存（查表攻击、cache 侧信道）
#   (b) [base + index*scale] 中 index 被污染 —— base 不变但 index 依赖于秘密
#   (c) [base + index*scale] 中 base 被污染 —— 指向不同表的基址选择
#   (d) xlatb 指令 —— x86 的 S-box 查表指令，AL = 索引
#
# 排除规则：
#   - 栈访问 [rsp+N] / [rbp-N] 不视为违规——栈偏移不携带秘密信息
#   - 立即数偏移量不视为秘密依赖（[array+0x10] 中的 0x10 不是秘密）
#
# ref: "Cache-timing attacks AES" (Bernstein, 2005) — T-t 访问模式泄露密钥；
# "Spectre Attacks: 漏洞利用ing Speculat Execu" (Kocher et al., 2019)

import logging
import re
from typing import Dict, List, Set, Tuple
from dataclasses import dataclass, field

from .secret_tracker import SecretTaint

logger = logging.getLogger(__name__)


@dataclass
class MemoryViolation:
    """一个秘密依赖访存的违规记录"""
    func_name: str
    insn_address: int
    insn_text: str
    mem_operand: str       # 被污染的内存操作数
    secret_source: str
    taint_depth: int
    access_type: str       # '读取' | '写入' | 'READ_WRITE'
    severity: str


# 栈指针寄存器——这些寄存器用于栈帧访问，不传递秘密（正常编译的代码中）
_STACK_REGS = {'rsp', 'rbp', 'esp', 'ebp', 'sp', 'bp'}


def _parse_memory_operand(op_str: str) -> List[str]:
    """从 [base + index*scale + disp] 中提取所有寄存器引用
    
    返回寄存器名列表（不含立即数）
    """
    if '[' not in op_str:
        return []
    inner = op_str.split('[')[1].split(']')[0]
    # 提取所有类似寄存器名的 token（2-5 个字母数字的标识符）
    regs = re.findall(r'\b([re][a-z0-9]{1,4})\b', inner)
    return regs


def check_secret_dependent_memory(
    func_name: str,
    insns: List[Tuple[str, List[str]]],
    taints: Dict[str, SecretTaint],
    func_addr: int = 0,
) -> List[MemoryViolation]:
    """检查秘密数据是否影响内存访问模式"""
    violations = []

    for offset, (mn, ops) in enumerate(insns):
        mn_lower = mn.lower()
        if not ops:
            continue

        # 确定访问类型
        if mn_lower in ('mov', 'movsx', 'movzx', 'lea'):
            # mov reg, [mem] → 读取; mov [mem], reg → 写入
            if ops[0].startswith('[') or ops[0] in _STACK_REGS:
                access_type = 'READ' if any('[' in o for o in ops[1:]) else 'WRITE'
            else:
                access_type = 'READ' if any('[' in o for o in ops) else 'WRITE'
        elif mn_lower in ('add', 'sub', 'and', 'or', 'xor', 'inc', 'dec'):
            access_type = 'READ_WRITE'
        elif mn_lower in ('push',):
            access_type = 'WRITE'
        elif mn_lower in ('pop',):
            access_type = 'READ'
        elif mn_lower == 'xlatb':
            # XLATB: AL = [RBX + AL] —— AL 作为索引
            if 'al' in taints:
                violations.append(MemoryViolation(
                    func_name=func_name,
                    insn_address=func_addr + offset * 4,
                    insn_text='xlatb',
                    mem_operand='[rbx+al]',
                    secret_source=str(taints['al'].sources),
                    taint_depth=taints['al'].depth,
                    access_type='READ',
                    severity='HIGH',
                ))
            continue
        else:
            continue

        # 检查所有含内存引用的操作数
        for op_str in ops:
            if '[' not in op_str:
                continue

            regs_in_mem = _parse_memory_operand(op_str)
            for reg in regs_in_mem:
                if reg in _STACK_REGS:
                    continue
                if reg in taints:
                    violations.append(MemoryViolation(
                        func_name=func_name,
                        insn_address=func_addr + offset * 4,
                        insn_text=f'{mn} {", ".join(ops)}',
                        mem_operand=op_str,
                        secret_source=str(taints[reg].sources),
                        taint_depth=taints[reg].depth,
                        access_type=access_type,
                        severity=('HIGH' if access_type == 'READ' else 'MEDIUM'),
                    ))
                    break  # 每个操作数只报告一次

    return violations
