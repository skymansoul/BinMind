# 路径条件约束应用器: 在写入点对 size 值域施加分支守卫约束
# 技术问题: 编译器常将边界守卫编译为 "cmp X, imm; jcc 出口/提前返回",
#   落路径上 X ≤ imm 必然成立. 原实现的 _find_early_return_guard
#   仅检查写入点前 40 条指令内最近的 cmp, 且不验证跳转方向,
#   对 "cmp [rbp-0xc], 0x80" 内存槽守卫与多级守卫链覆盖不足,
#   导致本可证明安全的写入被误报.
# 解决手段: 回溯扫描 + 槽位溯源匹配 + 双向守卫判定:
#   A 型 (跳转=出口): jg/ja/jge/jae 且跳转目标越过写入点
#     → 落路径 (X≤imm) 到达写入点, 约束生效
#   B 型 (跳转=续行): jle/jbe/jl/jb 且跳转目标在写入点前汇合,
#     落路径为提前退出 (jmp/ret)
#     → 跳转路径 (X≤imm) 到达写入点, 约束生效
#   对多个守卫取最紧上界. 无指令地址表时保守不夹紧.
# TODO: 解析 printf 系格式串以区分 %p 值传递与 %s 解引用
# 与 PathConditionTracker 的关系: 该模块是其落地形态,
#   以函数内后向扫描实现相同的路径条件约束, 避免在主线管道中
#   维护分支栈的生命周期复杂度.
from __future__ import annotations
from typing import Dict, List, Optional, Tuple

from .instruction_parser import InstructionParser
from .value_range import ValueRange

# 前向守卫条件跳转: 跳转条件成立 → 离开 (不执行写入)
# 落路径 (跳转不取) 上 size 的上界:
#   jg/ja:   跳走当 X > imm → 落路径 X ≤ imm → 上界 = imm
#   jge/jae: 跳走当 X ≥ imm → 落路径 X < imm → 上界 = imm - 1
#   jle/jbe/jl/jb: 落路径是下界约束, 不用于收敛上界
_GUARD_UPPER_BOUND = {
    'jg': lambda imm: imm,
    'ja': lambda imm: imm,
    'jge': lambda imm: imm - 1,
    'jae': lambda imm: imm - 1,
}

# B 型守卫: 跳转=续行, 跳转路径上 X ≤ imm
_GUARD_CONTINUE_BOUND = {
    'jle': lambda imm: imm,
    'jbe': lambda imm: imm,
    'jl': lambda imm: imm - 1,
    'jb': lambda imm: imm - 1,
}

_SCAN_WINDOW = 80


class PathConstraintApplier:
    """路径条件约束应用器 (无状态, 纯函数式接口)."""

    @staticmethod
    def clamp_size_range(instructions: List[str],
                         func_map: Dict[str, Tuple[int, int]],
                         sink_idx: int,
                         size_reg: str,
                         size_range: ValueRange,
                         instr_addrs: Optional[List[int]] = None
                         ) -> Tuple[ValueRange, bool]:
        """在写入点对 size 值域应用守卫约束.

        返回 (修正后的值域, 是否发生夹紧).
        无指令地址表时保守不夹紧 (无法验证跳转方向).
        """
        if size_range.is_top:
            return size_range, False
        if not instructions or not (0 <= sink_idx < len(instructions)):
            return size_range, False
        if not instr_addrs or len(instr_addrs) != len(instructions):
            return size_range, False

        size_base = InstructionParser.normalize_reg64(
            InstructionParser.clean_reg(size_reg))
        traced_slot = InstructionParser.trace_reg_to_source_slot(
            sink_idx, instructions, size_base)
        bounds: List[int] = []

        scan_start = max(0, sink_idx - _SCAN_WINDOW)
        for i in range(sink_idx - 1, scan_start - 1, -1):
            parsed = InstructionParser.parse_line(instructions[i])
            if parsed is None:
                continue
            op, ops = parsed
            if op != 'cmp' or len(ops) < 2:
                continue
            imm_val = InstructionParser.parse_immediate(ops[1])
            if imm_val is None:
                continue
            left = ops[0].strip()
            left_clean = InstructionParser.clean_reg(left)
            reg_hit = (InstructionParser.normalize_reg64(left_clean)
                       == size_base)
            slot_hit = (traced_slot is not None
                        and InstructionParser.parse_mem_slot(left)
                        == traced_slot)
            if not (reg_hit or slot_hit):
                continue
            if i + 1 >= len(instructions):
                continue
            nxt = InstructionParser.parse_line(instructions[i + 1])
            if nxt is None:
                continue
            j_op, j_ops = nxt
            if not j_ops:
                continue
            target = PathConstraintApplier._parse_target(j_ops[0])
            hi = None
            if j_op in _GUARD_UPPER_BOUND:
                # A 型: 跳转=出口. 跳转目标越过写入点, 或目标区域
                # 在到达写入点前以 ret 终止 (支配性早退块)
                if target is not None and (
                        target > instr_addrs[sink_idx]
                        or (target > instr_addrs[i]
                            and PathConstraintApplier._target_exits(
                                instructions, i + 1, instr_addrs,
                                target, instr_addrs[sink_idx]))):
                    hi = _GUARD_UPPER_BOUND[j_op](imm_val)
            elif j_op in _GUARD_CONTINUE_BOUND:
                # B 型: 跳转=续行, 要求跳转目标在写入点前汇合,
                #       且落路径为提前退出 (jmp/ret)
                if (target is not None
                        and target <= instr_addrs[sink_idx]
                        and target > instr_addrs[i]
                        and PathConstraintApplier._fallthrough_exits(
                            instructions, i + 1)):
                    hi = _GUARD_CONTINUE_BOUND[j_op](imm_val)
                # C 型: 跳转=续行 + 落路径钳位到同一常数.
                # 跳转路径 X ≤ imm, 落路径 X = imm → 两路均 ≤ imm.
                # (safe04 钳位模式; cve18 的 jg 钳位不在此集合,
                #  其跳跃路径保留原始无界值, 由 L4 分裂检测兜底)
                elif (target is not None
                        and target <= instr_addrs[sink_idx]
                        and target > instr_addrs[i]
                        and PathConstraintApplier._fallthrough_clamps(
                            instructions, i + 1, imm_val, size_base,
                            traced_slot)):
                    hi = imm_val
            if hi is None:
                continue
            if 0 <= hi <= 0x100000:
                bounds.append(hi)

        if not bounds:
            return size_range, False
        best = min(bounds)
        if best >= size_range.umax:
            return size_range, True
        if size_range.umin <= best:
            new_range = ValueRange.unsigned_range(size_range.umin, best)
        else:
            new_range = ValueRange.unsigned_range(0, best)
        return new_range, True

    @staticmethod
    def _parse_target(target_text: str) -> Optional[int]:
        """解析跳转目标地址 (失败返回 None)."""
        target_str = target_text.split('<')[0].strip()
        try:
            return int(target_str, 16)
        except ValueError:
            return None

    @staticmethod
    def _target_exits(instructions: List[str], jcc_idx: int,
                      instr_addrs: List[int], target: int,
                      sink_addr: int) -> bool:
        """跳转目标区域在到达写入点前是否以 ret 终止.

        目标块位于写入点之前且以 ret 结束 → 跳转路径不达写入点,
        守卫对落路径 (X ≤ imm) 支配有效.
        """
        target_idx = None
        for i in range(jcc_idx + 1, min(jcc_idx + 80, len(instructions))):
            if instr_addrs[i] == target:
                target_idx = i
                break
        if target_idx is None:
            return False
        for i in range(target_idx + 1, len(instructions)):
            if instr_addrs[i] >= sink_addr:
                return False  # 目标块流入写入点, 非出口
            parsed = InstructionParser.parse_line(instructions[i])
            if parsed is None:
                continue
            op, _ = parsed
            if op == 'ret':
                return True
        return False

    @staticmethod
    def _fallthrough_exits(instructions: List[str], jcc_idx: int) -> bool:
        """jcc 的落路径是否为提前退出 (jmp/ret).

        3 条指令窗口内出现无条件跳转或返回即视为出口.
        """
        for i in range(jcc_idx + 1, min(jcc_idx + 4, len(instructions))):
            parsed = InstructionParser.parse_line(instructions[i])
            if parsed is None:
                continue
            op, _ = parsed
            if op in ('jmp', 'ret'):
                return True
            if op in ('call',):
                return False
        return False

    @staticmethod
    def _fallthrough_clamps(instructions: List[str], jcc_idx: int,
                            clamp_val: int, size_reg: str,
                            traced_slot: Optional[int]) -> bool:
        """jcc 的落路径是否将 size 源钳位到 clamp_val.

        匹配: mov <size 寄存器或溯源槽>, clamp_val 出现在
        跳转后的 3 条指令内.
        """
        size_base = InstructionParser.normalize_reg64(
            InstructionParser.clean_reg(size_reg))
        for i in range(jcc_idx + 1, min(jcc_idx + 4, len(instructions))):
            parsed = InstructionParser.parse_line(instructions[i])
            if parsed is None:
                continue
            op, ops = parsed
            if op != 'mov' or len(ops) < 2:
                continue
            imm = InstructionParser.parse_immediate(ops[1])
            if imm != clamp_val:
                continue
            dst = ops[0].strip()
            dst64 = InstructionParser.normalize_reg64(
                InstructionParser.clean_reg(dst))
            if dst64 == size_base:
                return True
            if (traced_slot is not None
                    and InstructionParser.parse_mem_slot(dst)
                    == traced_slot):
                return True
        return False
