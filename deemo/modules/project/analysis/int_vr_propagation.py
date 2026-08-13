# 整数回绕值域传播器: 寄存器 + 栈槽的值域转移
# 职责: mov/movzx/movsx/movabs 的立即数/寄存器/栈槽值域传播,
#   与 add/sub 等的寄存器-栈槽同步
import re
from typing import Dict, Optional

from .instruction_parser import InstructionParser
from .value_range import ValueRange


class IntVrPropagator:
    """值域传播器: 维护 ValueRangeDomain 与栈槽映射的转移函数."""

    def __init__(self, vd, stack_slots: Dict[str, ValueRange]):
        self._vd = vd
        self._stack_slots = stack_slots

    @staticmethod
    def get_stack_offset(text: str) -> Optional[int]:
        m = re.search(r'\[rbp\s*([-+])\s*(0x[0-9a-fA-F]+|\d+)\]',
                      text, re.IGNORECASE)
        if m:
            off = int(m.group(2), 16) if m.group(2).startswith(
                '0x') else int(m.group(2))
            return -off if m.group(1) == '-' else off
        return None

    def propagate(self, op: str, operands, idx: int, line: str):
        """值域转移: 寄存器 + 栈槽."""
        if op in ('mov', 'movzx', 'movsx', 'movabs') and len(operands) >= 2:
            self._propagate_mov(op, operands)
            return
        # 注意: add/sub 不更新槽值域 — 回绕判定需要操作前值
        # lea reg, [base+offset] → 传播调整后的值域
        if op == 'lea' and len(operands) >= 2:
            dst64 = InstructionParser.normalize_reg64(
                InstructionParser.clean_reg(operands[0]))
            base, off, idx_reg, scale = InstructionParser.parse_lea_src(
                operands[1])
            if base:
                base64 = InstructionParser.normalize_reg64(base)
                base_vr = self._vd.get(base64)
                if not base_vr.is_top:
                    if off != 0:
                        self._vd.set(dst64, base_vr.add(
                            ValueRange.constant(off)))
                    else:
                        self._vd.set(dst64, base_vr)
        if op == 'cdqe':
            eax_vr = self._vd.get('eax')
            if not eax_vr.is_top:
                self._vd.set('rax', eax_vr)

    def _propagate_mov(self, op: str, operands):
        raw_dst = operands[0]
        raw_src = operands[1] if len(operands) > 1 else ''
        dst = InstructionParser.clean_reg(raw_dst)
        src = InstructionParser.clean_reg(raw_src)
        dst64 = InstructionParser.normalize_reg64(dst)
        imm = InstructionParser.parse_immediate(src)
        # mov reg, imm
        if imm is not None and InstructionParser.is_reg(dst):
            self._vd.set(dst64, ValueRange.constant(imm))
            return
        # mov [rbp-X], imm → 栈槽
        if imm is not None:
            off = self.get_stack_offset(raw_dst)
            if off is not None:
                self._stack_slots[f'rbp{off:+d}'] = ValueRange.constant(imm)
            return
        # mov reg, reg → 传播
        if InstructionParser.is_reg(dst) and InstructionParser.is_reg(src):
            src64 = InstructionParser.normalize_reg64(src)
            src_vr = self._vd.get(src64)
            if not src_vr.is_top:
                self._vd.set(dst64, src_vr)
            return
        # mov reg, [rbp-X] → 从栈槽加载
        if InstructionParser.is_reg(dst):
            off = self.get_stack_offset(raw_src)
            if off is not None:
                slot_vr = self._stack_slots.get(f'rbp{off:+d}')
                if slot_vr is not None:
                    self._vd.set(dst64, slot_vr)
                else:
                    self._vd.set(dst64, ValueRange.top())
            return
        # mov [rbp-X], reg → 寄存器值存入栈槽
        if '[' in raw_dst and InstructionParser.is_reg(src):
            off = self.get_stack_offset(raw_dst)
            if off is not None:
                src_vr = self._vd.get(
                    InstructionParser.normalize_reg64(src))
                self._stack_slots[f'rbp{off:+d}'] = src_vr


def propagate_vr(det, op: str, operands, idx: int, line: str):
        """值域传播 (模块函数): 动态访问 detector 状态, 无引用失效."""
        if op in ('mov', 'movzx', 'movsx', 'movabs') and len(operands) >= 2:
            raw_dst = operands[0]
            raw_src = operands[1] if len(operands) > 1 else ''
            dst = InstructionParser.clean_reg(raw_dst)
            src = InstructionParser.clean_reg(raw_src)
            dst64 = InstructionParser.normalize_reg64(dst)
            imm = InstructionParser.parse_immediate(src)
            # mov reg, imm
            if imm is not None and InstructionParser.is_reg(dst):
                det._vd.set(dst64, ValueRange.constant(imm))
                return
            # mov [rbp-X], imm → 栈槽
            if imm is not None:
                off = det._get_stack_offset(raw_dst)
                if off is not None:
                    det._stack_slots[f'rbp{off:+d}'] = ValueRange.constant(imm)
                    return
            # mov reg, reg → 传播
            if InstructionParser.is_reg(dst) and InstructionParser.is_reg(src):
                src64 = InstructionParser.normalize_reg64(src)
                src_vr = det._vd.get(src64)
                if not src_vr.is_top:
                    det._vd.set(dst64, src_vr)
                return
            # mov reg, [rbp-X] → 从栈槽加载
            if InstructionParser.is_reg(dst):
                off = det._get_stack_offset(raw_src)
                if off is not None:
                    slot_key = f'rbp{off:+d}'
                    if slot_key in det._stack_slots:
                        det._vd.set(dst64, det._stack_slots[slot_key])
                    else:
                        det._vd.set(dst64, ValueRange.top())
                return
            # mov [rbp-X], reg → 寄存器值存入栈槽
            if '[' in raw_dst and InstructionParser.is_reg(src):
                off = det._get_stack_offset(raw_dst)
                if off is not None:
                    src_vr = det._vd.get(
                        InstructionParser.normalize_reg64(src))
                    det._stack_slots[f'rbp{off:+d}'] = src_vr
        # lea reg, [base+offset] → 传播调整后的值域
        if op == 'lea' and len(operands) >= 2:
            dst64 = InstructionParser.normalize_reg64(
                InstructionParser.clean_reg(operands[0]))
            src = operands[1]
            base, off, idx_reg, scale = InstructionParser.parse_lea_src(src)
            if base:
                base64 = InstructionParser.normalize_reg64(base)
                base_vr = det._vd.get(base64)
                if not base_vr.is_top:
                    if off != 0:
                        det._vd.set(dst64, base_vr.add(
                            ValueRange.constant(off)))
                    else:
                        det._vd.set(dst64, base_vr)
        # cdqe: eax → rax 符号扩展
        if op == 'cdqe':
            eax_vr = det._vd.get('eax')
            if not eax_vr.is_top:
                det._vd.set('rax', eax_vr)
