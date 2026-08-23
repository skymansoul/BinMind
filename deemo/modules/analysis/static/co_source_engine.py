# AWSC 分配-写入同源关联引擎 (Allocation-Write Size Co-Sourcing Engine)
#
# 核心问题:
#   堆溢出静态检测最大的误报类: malloc(N) 与 memcpy(ptr, src, M)
#   中 N 和 M 实际来自同一数据流 (同一栈槽/参数/寄存器链), 即
#   "分配=写入" 不可能溢出. 区间分析只看到 N∈[0,2^31), M∈[0,2^31)
#   重叠即告警, 无法判定同源. 符号执行可以但代价高且对不可达路径脆弱.
#
# 本引擎决策:
#   从分配/写入调用点的 size 参数寄存器出发, 沿指令流反向做
#   def-use 根来源追踪 (backward root-source tracing), 将每个
#   size 参数归约到"根来源": 立即数 / 栈槽 / 函数参数 / 函数返回值.
#   若分配根与写入根等价 (同栈槽/同参数/同返回值且线性变换相同),
#   则判定 SAFE (分配=写入); 若写入根 = 分配根 + k (k>0) → 溢出 k 字节.
#
#

from typing import Dict, List, Optional, Tuple

from .co_source_core import (
    Root, ROOT_IMM, ROOT_STACK, ROOT_PARAM, ROOT_CALLRET, ROOT_UNKNOWN,
    _SYSV_ARGS, _WIN64_ARGS)
from .co_source_operands import CoSourceOperandMixin


class AWSCEngine(CoSourceOperandMixin):
    """分配-写入同源关联引擎.

    对单个指令序列执行后向 def-use 根来源追踪,
    判定分配大小与写入大小是否来自同一根来源.
    """

    MAX_WINDOW = 300   # 后向扫描最大指令数 (跨函数风险控制)

    def __init__(self, use_win64_abi: bool = False):
        self._args = _WIN64_ARGS if use_win64_abi else _SYSV_ARGS
        self._param_set = set(self._args)

# 公开 API

    def trace_size_root(self, instructions: List[dict],
                        call_addr: int, size_reg: str,
                        func_ranges: Optional[List[Tuple[int, int]]] = None
                        ) -> Root:
        """从 call_addr 处 size_reg 反向追踪根来源.

        状态机: state ∈ {"reg", "slot"}, 从 size 寄存器出发,
        沿 def-use 反推, 直至归约到 立即数/参数/返回值/未知.
        """
        if not instructions:
            return Root(ROOT_UNKNOWN, 0)
        idx = self._find_insn(instructions, call_addr)
        if idx < 0:
            return Root(ROOT_UNKNOWN, 0)

        func_lo = self._func_lower_bound(instructions, call_addr, func_ranges)

        state = "reg"
        current = self._norm(size_reg)
        coeff, const = 1, 0

        for i in range(idx - 1, max(0, idx - self.MAX_WINDOW) - 1, -1):
            ins = instructions[i]
            addr = ins.get("address", 0)
            if addr < func_lo:
                break

            if state == "reg":
                root = self._step_reg(ins, current, coeff, const)
            else:  # slot
                root = self._step_slot(ins, current, coeff, const)

            if isinstance(root, Root):
                return root
            if root is None:
                continue

            kind, payload = root[0], root[1]
            if kind == "imm":
                return Root(ROOT_IMM, payload, 1, 0)
            coeff, const = root[2], root[3]
            if kind == "slot":
                state = "slot"
                current = payload
            else:
                state = "reg"
                current = payload

        if state == "reg" and current in self._param_set:
            return Root(ROOT_PARAM, self._args.index(current),
                        coeff, const)
        return Root(ROOT_UNKNOWN, 0, coeff, const)

    def correlate(self, alloc_root: Optional[Root],
                  write_root: Optional[Root],
                  usable_size: int = 0,
                  alloc_value: Optional[int] = None,
                  dst_offset: int = 0
                  ) -> Tuple[str, Optional[int], str]:
        if alloc_root is None or write_root is None:
            return ("unknown", None, "missing_root")
        if alloc_root.is_unknown() or write_root.is_unknown():
            return ("unknown", None, "unknown_root")

        # Case 1: 两常量 → 数值比较 (含写入偏移)
        if (alloc_root.kind == ROOT_IMM and write_root.kind == ROOT_IMM):
            a = alloc_root.value + alloc_root.const
            w = write_root.value + write_root.const + dst_offset
            if w <= a:
                return ("safe", 0, f"imm: write_end={w}<=alloc={a}")
            return ("overflow", w - a, f"imm: write_end={w}>alloc={a}")

        # Case 2: 同根来源 (同栈槽/同参数/同返回值)
        if self._same_base(alloc_root, write_root):
            a_c, a_k = alloc_root.coeff, alloc_root.const
            w_c, w_k = write_root.coeff, write_root.const
            if a_c == w_c:
                # 写入末端 = 写入根 + 目标偏移, 与分配根比较.
                # 偏移计入后 diff>0 即溢出风险, 不因同源即判安全.
                diff = (w_k + dst_offset) - a_k
                if diff <= 0:
                    return ("safe", 0,
                            f"co_source: {alloc_root}=={write_root}")
                # padding-safe 仅当分配根为精确立即数且值可靠时适用.
                # 符号根 (param/stack) 的值无法静态确定 → 偏移视为溢出风险.
                if alloc_root.kind == ROOT_IMM and usable_size > 0:
                    a_val = alloc_root.value + alloc_root.const
                    if a_val + diff <= usable_size:
                        return ("safe", 0,
                                f"co_source: write_end("
                                f"{a_val + diff})<=usable({usable_size})")
                return ("overflow", diff,
                        f"co_source: write>alloc by {diff}")
            return ("unknown", None, "coeff_mismatch")

        # Case 3: 分配为立即数, 写入为变量 → 保守保留
        if alloc_root.kind == ROOT_IMM:
            return ("unknown", None, "imm_vs_var")

        return ("unknown", None, "different_base")

    def trace_dst_offset(self, instructions: List[dict],
                         call_addr: int, ptr_reg: str,
                         func_ranges=None) -> int:
        """追踪写入目标指针相对堆基址的常量偏移.

        memcpy(buf+0x10, src, n) 中 dst 寄存器由 lea dst,[base+0x10]
        或 add dst,0x10 产生. 从 call 点反向追踪 ptr_reg 的偏移量,
        无法归约为纯常量 → 返回 0 (安全侧, 不引入误报).
        """
        if not instructions or not ptr_reg:
            return 0
        idx = self._find_insn(instructions, call_addr)
        if idx < 0:
            return 0
        func_lo = self._func_lower_bound(instructions, call_addr, func_ranges)
        current = self._norm(ptr_reg)
        offset = 0
        for i in range(idx - 1, max(0, idx - 30) - 1, -1):
            ins = instructions[i]
            if ins.get("address", 0) < func_lo:
                break
            mnem = ins.get("mnemonic", "").lower()
            ops = ins.get("operands", [])
            if not ops:
                continue
            dst = self._norm(ops[0]) if len(ops) >= 1 else ""
            if dst != current:
                continue
            if mnem == "mov" and len(ops) >= 2:
                src = ops[1].strip()
                if "[" in src.lower():
                    base, off, _ = self._parse_mem_full(src)
                    if base in ("rbp", "rsp"):
                        # 栈槽装载: 分配基址通常存于 [rbp-X], 该装载即
                        # 分配指针. 已累计的偏移即为目标相对分配基址的
                        # 偏移, 返回累计值而非清零 (漏检方向从安全侧走).
                        return offset
                current = self._norm(src)
                continue
            if mnem == "lea" and len(ops) >= 2:
                base, off, scale = self._parse_mem_full(ops[1])
                if base is None or scale != 1:
                    return 0  # 复杂表达式或缩放, 放弃
                offset += off
                current = self._norm(base)
                continue
            if mnem in ("add", "sub") and len(ops) >= 2:
                if self._is_imm(ops[1]):
                    v = self._parse_imm_signed(ops[1], ops[0])
                    if v is None:
                        return 0
                    offset += v if mnem == "add" else -v
                    continue
                return 0  # 寄存器偏移无法静态确定
            return 0  # 其他定义指令, 无法继续追踪
        return offset

# 辅助

    @staticmethod
    def _same_base(a: Root, b: Root) -> bool:
        if a.kind != b.kind:
            return False
        if a.kind in (ROOT_IMM, ROOT_CALLRET, ROOT_PARAM, ROOT_STACK):
            return a.value == b.value
        return False

    def _find_insn(self, instructions: List[dict], addr: int) -> int:
        for i, ins in enumerate(instructions):
            if ins.get("address", 0) == addr:
                return i
        return -1

    @staticmethod
    def _func_lower_bound(instructions: List[dict], addr: int,
                          func_ranges: Optional[List[Tuple[int, int]]]
                          ) -> int:
        if func_ranges:
            for lo, hi in func_ranges:
                if lo <= addr < hi:
                    return lo
        return 0


__all__ = ["AWSCEngine", "Root", "ROOT_IMM", "ROOT_STACK", "ROOT_PARAM",
           "ROOT_CALLRET", "ROOT_UNKNOWN"]
