# FAPV - Format-Argument Provenance Verifier (格式串来源验证器).
#
# 决策逻辑:
#   格式化字符串误报源于"非 .rdata 来源一律视为用户可控"的粗判:
#     栈槽常量初始化 (char fmt[]="val=%d") 与只读字面量指针被误报.
#   本模块沿格式串寄存器的后向定义链分类来源, 输出三级判定:
#     BENIGN     - 定义链到达 lea [rip+off] / mov r, imm(字面量地址)
#                  或常量初始化的栈槽 -> 字面量.
#     CONFIRMED  - 定义链到达参数槽/参数派生内存/输入与复制函数
#                  填充缓冲 -> 用户可控.
#     SUSPECTED  - call 返回值或不可解析内存加载 -> 无法确认, 降级.
#   仅 CONFIRMED 计入检出, 与 PcWBI/ULPR 三级判定同机制.
#   定义链追踪位于 fmt_chain.FmtChainMixin.
#

from typing import Dict, List, Tuple

from fmt_env import FmtVerdict, FMT_ARG_IDX, ARG_REGS_SYSV, ARG_REGS_WIN64
from fmt_chain import FmtChainMixin

_MAX_HOPS = 8


class FmtArgVerifier(FmtChainMixin):
    """格式串参数来源验证器."""

    def __init__(self, instructions: List[dict], use_win64: bool = False):
        self._insns = instructions
        self._args = ARG_REGS_WIN64 if use_win64 else ARG_REGS_SYSV
        self._idx_map = {ins.get("address", i): i
                         for i, ins in enumerate(instructions)}
        # 参数槽偏移: argv 位于 O0 prologue 保存的 rbp+0x10/0x18 区域.
        self._arg_slots = ("rbp+0x10", "rbp+0x18", "rsp+0x10", "rsp+0x18")

    def verify(self, addr: int, func: str) -> Tuple[str, str]:
        """对 printf 调用点验证格式串参数来源."""
        base = func.replace("__mingw_", "")
        base = base[1:] if base.startswith("v") and base != "vfprintf" \
            else base
        fmt_idx = FMT_ARG_IDX.get(base, 0)
        if fmt_idx >= len(self._args):
            return FmtVerdict.SUSPECTED, "fmt arg beyond tracked regs"
        fmt_reg = self._args[fmt_idx]
        idx = self._idx_map.get(addr)
        if idx is None:
            return FmtVerdict.SUSPECTED, "call address not in stream"
        return self._chase(idx, fmt_reg, _MAX_HOPS, set())


__all__ = ["FmtArgVerifier"]
