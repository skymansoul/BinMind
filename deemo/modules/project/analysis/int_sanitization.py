# 整数回绕净化检测
# 技术问题: 回绕类检测 (UADD_WRAP/UMUL_OVF 等) 对回绕算术一律报告,
#   但回绕结果被确定性净化 (掩码/截断/右移) 后回绕不构成实际溢出,
#   逐算术点判定产生误报.
# 解决手段: 在回绕指令后的小窗口内检查净化指令作用于同一目标寄存器,
#   命中任一 → 回绕值被限制到合法域 → 标记可抑制.
# 与堆溢出 L5 路径守卫的思路同构: 后置证据层, 独立于逐点判定.
from typing import List

from .instruction_parser import InstructionParser

# 参与净化判定的回绕模式
_WRAP_MODES = ('UADD_WRAP', 'UMUL_OVF', 'USHL_OVF',
               'USUB_WRAP', 'SADD_OVF')

# 确定性净化指令: 结果值域被限制
_SANITIZE_OPS = ('and', 'movzx', 'shr')


def apply_sanitization(findings: List, instructions: List[str],
                       enabled: bool = True):
    """对回绕 finding 做净化检测.

    findings: IntOverflowFinding 列表 (原地标记 is_false_positive)
    enabled: 关闭时恢复逐算术点判定 (消融基线)
    """
    if not enabled:
        return
    for f in findings:
        if f.mode.name not in _WRAP_MODES or not f.dst_reg:
            continue
        dst64 = InstructionParser.normalize_reg64(f.dst_reg)
        dst_slot = None
        if '[' in f.dst_reg and ']' in f.dst_reg:
            dst_slot = InstructionParser.parse_mem_slot(f.dst_reg)
        for j in range(f.instruction_idx + 1,
                       min(f.instruction_idx + 9, len(instructions))):
            parsed = InstructionParser.parse_line(instructions[j])
            if parsed is None:
                continue
            op, ops = parsed
            if not ops:
                continue
            if op == 'call':
                break
            if op in _SANITIZE_OPS and len(ops) >= 1:
                d = InstructionParser.normalize_reg64(
                    InstructionParser.clean_reg(ops[0]))
                hit = False
                if dst_slot is not None:
                    hit = (InstructionParser.parse_mem_slot(ops[0])
                           == dst_slot)
                if not hit and d == dst64:
                    hit = True
                if hit:
                    f.is_false_positive = True
                    f.false_positive_reason = (
                        f"回绕净化: 结果被 {op} 限制到合法域, "
                        f"溢出不可达")
                    f.severity = f.severity.__class__.INFO
                    f.confidence = min(f.confidence, 0.2)
                    break
