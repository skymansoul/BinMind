# UAF利用难度分级 — 根据free后use的类型评估可利用性
# 不同use类型的利用难度差异巨大: dereference > arithmetic > comparison

from enum import Enum
from typing import Dict, List, Tuple

class UAFRiskLevel(Enum):
    CRITICAL = "critical"          # free后解引用 → 高度可exploit
    HIGH = "high"                  # free后写入 → 可能可控
    MEDIUM = "medium"              # free后读取 → 信息泄露
    LOW = "low"                    # free后比较/算术 → 不确定
    INFO = "info"                  # 无法分类

def classify_use_risk(insn_text: str) -> Tuple[UAFRiskLevel, float]:
    """根据use指令的类型评估UAF利用难度

    设计依据:
      mov [rax], val → free后写入 → 堆元数据可控 → CRITICAL
      mov reg, [rax] → free后读取 → 信息泄露 → MEDIUM
      cmp/test with [rax] → 比较 → 探测 → LOW
      lea/call [rax] → 控制流 → CRITICAL
    """
    t = insn_text.lower().strip()
    parts = t.split(None, 1)
    mnemonic = parts[0] if parts else ''

    # 控制流劫持: call/jmp [reg]
    if mnemonic in ('call', 'jmp') and '[' in t:
        return UAFRiskLevel.CRITICAL, 0.95

    # 写入内存: mov [reg], val → 可能控制堆元数据
    if mnemonic == 'mov' and '[' in (parts[1].split(',')[0] if len(parts)>1 else ''):
        return UAFRiskLevel.CRITICAL, 0.90

    # 读取内存: mov reg, [ptr]
    if mnemonic in ('mov', 'movzx', 'movsx') and '[' in t:
        return UAFRiskLevel.MEDIUM, 0.55

    # 比较/测试: cmp/test with [ptr]
    if mnemonic in ('cmp', 'test') and '[' in t:
        return UAFRiskLevel.LOW, 0.30

    # 算术运算: add/sub with [ptr] → 较少见
    if mnemonic in ('add', 'sub', 'and', 'or', 'xor') and '[' in t:
        return UAFRiskLevel.LOW, 0.25

    # 寄存器引用: mov reg, ptr_reg (不通过内存)
    if mnemonic == 'mov' and '[' not in t:
        return UAFRiskLevel.INFO, 0.15

    return UAFRiskLevel.INFO, 0.10
