# 循环迭代次数推导器 (Loop Trip Counter)
#
# 核心决策:
#   从循环体内cmp指令和header前init推导精确迭代次数.
#   支持两种编译器模式:
#   A) 计数器循环 (O0): cmp reg, imm → trip = (cmp_val - init)
#   B) 指针比较循环 (O2/Os): cmp reg1, reg2 →
#      从 lea reg2,[base+offset] 提取总偏移,
#      从 add reg1, step 提取步长, trip = offset/step
#
# 创建: 2026-05-05

from typing import List, Optional, Tuple
from .disasm_util import norm_reg


class LoopTripCounter:
    """循环迭代次数推导器."""

    @staticmethod
    def estimate(instructions: List[dict],
                 header_idx: int, back_edge_idx: int,
                 jcc_mnem: str) -> Tuple[int, str, bool]:
        """返回 (trip_count, counter_reg, is_known).

        在循环体内搜索cmp, 在header前搜索init, 精确计算迭代次数.
        """
        cmp_val = None
        counter_reg = ""
        cmp_reg2 = ""
        for j in range(header_idx, min(back_edge_idx + 1, len(instructions))):
            ins = instructions[j]
            if ins.get("mnemonic", "").lower() == "cmp":
                ops = ins.get("operands", [])
                if len(ops) >= 2:
                    counter_reg = norm_reg(ops[0])
                    cmp_val = LoopTripCounter._parse_imm(ops[1])
                    if cmp_val is None:
                        cmp_reg2 = norm_reg(ops[1])
                    break
        # 模式A: 计数器与立即数比较
        if cmp_val is not None:
            for j in range(max(0, header_idx - 20), header_idx):
                ins = instructions[j]
                if ins.get("mnemonic", "").lower() == "mov":
                    ops = ins.get("operands", [])
                    if len(ops) >= 2 and norm_reg(ops[0]) == counter_reg:
                        init_val = LoopTripCounter._parse_imm(ops[1])
                        if init_val is not None and init_val >= 0:
                            trip = LoopTripCounter._calc_trip(
                                jcc_mnem, cmp_val, init_val)
                            return trip, counter_reg, True
            return 2, counter_reg, False
        # 模式B: 指针比较循环 (O2/Os优化)
        if cmp_reg2:
            trip = LoopTripCounter._ptr_cmp_trip_count(
                instructions, header_idx, back_edge_idx,
                counter_reg, cmp_reg2)
            if trip is not None:
                return trip, counter_reg, True
        return 2, counter_reg, False

    @staticmethod
    def _ptr_cmp_trip_count(instructions: List[dict],
                            header_idx: int, back_edge_idx: int,
                            reg1: str, reg2: str) -> Optional[int]:
        """指针比较型循环: 从lea提取end偏移, 从add提取步长, 计算trip.

        两种操作数顺序都支持:
          O2: cmp loop_reg, end_reg → loop_reg递增
          Os: cmp end_reg, loop_reg → loop_reg递增
        尝试两种排列, 返回第一个成功的结果.
        """
        for loop_reg, end_reg in ((reg1, reg2), (reg2, reg1)):
            trip = LoopTripCounter._try_ptr_cmp(
                instructions, header_idx, back_edge_idx,
                loop_reg, end_reg)
            if trip is not None:
                return trip
        return None

    @staticmethod
    def _try_ptr_cmp(instructions: List[dict],
                     header_idx: int, back_edge_idx: int,
                     loop_reg: str, end_reg: str) -> Optional[int]:
        """单次尝试: 假设loop_reg递增, end_reg为终止标记."""
        total_offset = None
        base_reg = None
        for j in range(max(0, header_idx - 20), header_idx):
            ins = instructions[j]
            mnem = ins.get("mnemonic", "").lower()
            ops = ins.get("operands", [])
            if mnem == "lea" and len(ops) >= 2:
                if norm_reg(ops[0]) == end_reg:
                    offset, breg = LoopTripCounter._parse_lea_offset(ops[1])
                    if offset is not None and offset > 0:
                        total_offset = offset
                        base_reg = breg
                        break
        if total_offset is None or total_offset <= 0:
            return None
        # 在header前找 mov loop_reg, base_reg
        has_init = False
        for j in range(max(0, header_idx - 20), header_idx):
            ins = instructions[j]
            mnem = ins.get("mnemonic", "").lower()
            ops = ins.get("operands", [])
            if mnem == "mov" and len(ops) >= 2:
                if norm_reg(ops[0]) == loop_reg and norm_reg(ops[1]) == base_reg:
                    has_init = True
                    break
        if not has_init:
            return None
        # 在循环体内找 add loop_reg, step
        step = None
        for j in range(header_idx, min(back_edge_idx + 1, len(instructions))):
            ins = instructions[j]
            mnem = ins.get("mnemonic", "").lower()
            ops = ins.get("operands", [])
            if mnem == "add" and len(ops) >= 2 and norm_reg(ops[0]) == loop_reg:
                step = LoopTripCounter._parse_imm(ops[1])
                if step is not None and step > 0:
                    break
        if step is None or step <= 0:
            return None
        if total_offset % step != 0:
            return None
        return total_offset // step

    @staticmethod
    def _parse_lea_offset(operand: str) -> Tuple[Optional[int], str]:
        """从lea操作数提取偏移量和基址寄存器."""
        s = operand.strip().lower().replace(" ", "")
        s = s.lstrip("[").rstrip("]")
        if "+" in s:
            parts = s.split("+")
            base = parts[0].strip()
            try:
                offset = int(parts[1], 16) if parts[1].startswith("0x") \
                    else int(parts[1])
            except (ValueError, IndexError):
                return None, base
            return offset, base
        if "-" in s and not s.startswith("-"):
            parts = s.split("-")
            base = parts[0].strip()
            try:
                offset = int(parts[1], 16) if parts[1].startswith("0x") \
                    else int(parts[1])
            except (ValueError, IndexError):
                return None, base
            return -offset, base
        return 0, s.strip()

    @staticmethod
    def _calc_trip(jcc: str, cmp_val: int, init_val: int) -> int:
        """根据jcc类型和cmp/init值计算迭代次数."""
        if jcc in ("jle", "jbe"):
            return max(1, cmp_val - init_val + 1)
        if jcc in ("jl", "jb", "jne"):
            return max(1, cmp_val - init_val)
        if jcc in ("jge", "jae"):
            return max(1, init_val - cmp_val + 1)
        if jcc in ("jg", "ja"):
            return max(1, init_val - cmp_val)
        return max(1, abs(cmp_val - init_val))

    @staticmethod
    def _parse_imm(op: str) -> Optional[int]:
        s = op.strip().lower().lstrip("%").replace("$", "")
        s = s.split("#")[0].strip()
        try:
            if s.startswith("0x"):
                return int(s, 16)
            if s.isdigit() or (s.startswith("-") and s[1:].isdigit()):
                return int(s)
        except ValueError:
            pass
        return None


__all__ = ["LoopTripCounter"]
