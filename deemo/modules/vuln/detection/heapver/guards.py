# coding: utf-8
# 创建: 2026-07-23  |  守卫窗口约束——路径有界写入检测
#
"""
守卫窗口 (guard window) 约束提取。

二进制堆溢出误报的核心来源之一是"有界写入":
  cmp r8, rdx        ; write_size vs alloc_size
  ja  .skip          ; 若 write > alloc 跳过写入
  call memcpy        ; 仅 write <= alloc 时执行
此类写入实际不可能溢出, 但纯 size 比较会报 FP。

方法:
  从 write call 点反向扫描小窗口 (默认 10 条), 寻找
  `cmp <size_reg>, <bound>` 后紧跟条件跳转的模式, 按跳转语义判定:
    ja/jae/jg/jge 跳过   → 落入时 size <= bound   (有界 SAFE)
    jbe/jle/jb/jl 跳过   → 落入时 size >  bound   (下界, 反证溢出)
    je/jne 跳过          → 不提供可靠边界

返回 GuardInfo: bound 可为立即数或另一寄存器 (该寄存器解析后的
值域上界即分配可用大小)。
"""

import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from .insn import Instruction, normalize_reg
from .defuse import DefUseResolver
from .memop import _imm_val

_GUARD_WINDOW = 10
_AFTER_CMP = 4  # cmp 之后多少条内必须有条件跳转
_SLOT_RE = re.compile(r"\[(rbp|rsp)([+-])(0x[0-9a-fA-F]+|\d+)\]")

# 跳转语义: mnemonic → (符号, 方向)  direction: "upper" 表示落入时受上界约束
_JCC_UPPER_SKIP = {"ja", "jae", "jg", "jge"}   # 大于则跳过 → 落入 = 上界
_JCC_LOWER_SKIP = {"jb", "jbe", "jl", "jle"}   # 小于等于则跳过 → 落入 = 下界


@dataclass
class GuardInfo:
    """一条守卫约束."""
    cmp_idx: int
    size_reg: str
    bound_kind: str          # "imm" / "reg"
    bound_value: Optional[int]   # imm 时直接值; reg 时解析后的上界
    bound_reg: str = ""
    direction: str = "upper"     # "upper" → 落入时 size <= bound
    raw: str = ""

    def __repr__(self) -> str:
        return (f"guard(cmp#{self.cmp_idx} {self.size_reg}"
                f"{'<=' if self.direction == 'upper' else '>='}"
                f"{self.bound_value or self.bound_reg})")


class GuardExtractor:
    """守卫约束提取器."""

    def __init__(self, resolver: Optional[DefUseResolver] = None):
        self._resolver = resolver or DefUseResolver()
        self._stats = {"guards_found": 0, "upper_bounds": 0}

    def find_guard(self, insns: List[Instruction], call_idx: int,
                   size_cand_regs: List[str]) -> Optional[GuardInfo]:
        """在 write call 前寻找支配写入的有界守卫.

        支持两种比较形式:
          A. cmp <size_reg>, <bound>       (寄存器比较)
          B. cmp [slot], <bound>           (内存槽比较, slot 为
             write size 寄存器的定义来源槽, 如 [rbp-0x8])
        """
        lo = max(0, call_idx - _GUARD_WINDOW)
        size_names = {normalize_reg(r) for r in size_cand_regs}
        # 写大小寄存器的定义来源槽 (栈槽比较用)
        slot = self._size_slot(insns, call_idx, size_cand_regs)

        def _matches(a: str) -> Optional[str]:
            """a 是否为 size 寄存器或 size 来源槽."""
            if normalize_reg(a) in size_names:
                return "reg"
            m = _SLOT_RE.search(a)
            if m and slot and self._slot_key(m) == slot:
                return "slot"
            return None

        for j in range(call_idx - 1, lo - 1, -1):
            insn = insns[j]
            if insn.mnem != "cmp" or len(insn.ops) < 2:
                continue
            a, b = insn.ops[0], insn.ops[1]
            if _matches(a) is None:
                if _matches(b) is not None:
                    a, b = b, a
                else:
                    continue
            # 检查 cmp 之后的条件跳转
            for k in range(j + 1, min(j + _AFTER_CMP + 1, len(insns))):
                mnem = insns[k].mnem
                if not mnem.startswith("j") or mnem == "jmp":
                    continue
                if mnem in _JCC_UPPER_SKIP:
                    direction = "upper"
                elif mnem in _JCC_LOWER_SKIP:
                    direction = "lower"
                else:
                    continue
                # 解析 bound
                imm = _imm_val(b)
                if imm is not None:
                    bound_kind, bound_value, bound_reg = "imm", imm, ""
                else:
                    bound_reg = normalize_reg(b)
                    bound_value = None
                self._stats["guards_found"] += 1
                if direction == "upper":
                    self._stats["upper_bounds"] += 1
                return GuardInfo(
                    cmp_idx=j, size_reg=a, bound_kind=bound_kind,
                    bound_value=bound_value, bound_reg=bound_reg,
                    direction=direction, raw=insn.raw)
        return None

    def _size_slot(self, insns: List[Instruction], call_idx: int,
                   size_cand_regs: List[str]) -> Optional[str]:
        """解析写大小寄存器的定义来源栈槽 (如 'rbp-0x8')."""
        region = self._resolver.resolve(insns, call_idx, size_cand_regs)
        sid = region.source_id
        if sid and sid.startswith("stk:"):
            return sid[4:]
        return None

    @staticmethod
    def _slot_key(m) -> str:
        """归一化槽键: 与 defuse source_id 一致 (十进制带符号)."""
        base = m.group(1)
        val_str = m.group(3)
        try:
            val = int(val_str, 16) if val_str.lower().startswith("0x") \
                else int(val_str)
        except ValueError:
            return f"{base}{m.group(2)}{val_str}"
        val = val if m.group(2) == "+" else -val
        return f"{base}{val:+d}"

    def resolve_bound(self, insns: List[Instruction], call_idx: int,
                      guard: GuardInfo) -> Optional[Tuple[int, str]]:
        """解析守卫边界: imm 直接返回; reg 解析其值域上界.

        返回 (bound, kind); 无法确定返回 None.
        """
        if guard.bound_kind == "imm":
            return guard.bound_value, "imm"
        if guard.bound_reg:
            region = self._resolver.resolve(
                insns, call_idx, [guard.bound_reg])
            if region.has_upper_bound:
                return region.hi, region.kind
        return None

    def stats(self) -> dict:
        return dict(self._stats)


__all__ = ["GuardInfo", "GuardExtractor", "_JCC_UPPER_SKIP",
           "_JCC_LOWER_SKIP"]
