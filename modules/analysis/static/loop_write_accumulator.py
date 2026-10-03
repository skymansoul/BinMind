# 循环累加写入追踪器 (Loop Accumulative Write Tracker)
#
# 核心决策:
#   检测循环内多次memcpy的累加溢出: malloc(256); for(i=0;i<5;i++) memcpy(p+off, src, 64);
#   每次memcpy安全(64<=256), 但5次累加=320>256 → 溢出.
#   在循环所属函数范围内重建指针→分配映射 (避免CRT栈帧污染).
#   迭代次数委托 LoopTripCounter 推导.
#
import re
from typing import List, Optional, Tuple
from .disasm_util import norm_reg, extract_func_name
from .heap_constraint import HeapConstraintTracker
from .loop_ptr_resolver import LoopPtrResolver
from .loop_trip_counter import LoopTripCounter


class LoopInfo:
    """循环结构信息."""
    __slots__ = ("header_addr", "back_edge_addr", "body_start",
                 "body_end", "trip_count", "counter_reg", "is_known_count")

    def __init__(self, header: int, back_edge: int,
                 body_start: int, body_end: int,
                 trip_count: int = 2,
                 counter_reg: str = "",
                 is_known: bool = False):
        self.header_addr = header
        self.back_edge_addr = back_edge
        self.body_start = body_start
        self.body_end = body_end
        self.trip_count = trip_count
        self.counter_reg = counter_reg
        self.is_known_count = is_known


class WriteAccumulation:
    """单个分配对象的累加写入记录."""
    __slots__ = ("alloc_addr", "ptr_reg", "single_write_size",
                 "write_count", "total_write", "loop", "write_addrs")

    def __init__(self, alloc_addr: int, ptr_reg: str,
                 single_write: int, loop: LoopInfo):
        self.alloc_addr = alloc_addr
        self.ptr_reg = ptr_reg
        self.single_write_size = single_write
        self.write_count = 0
        self.total_write = 0
        self.loop = loop
        self.write_addrs: List[int] = []


class LoopWriteAccumulator:
    """循环累加写入追踪器."""
    _WRITE_FUNCS = {"memcpy", "memmove", "strncpy", "read",
                    "fread", "recv", "memset"}
    _ALLOC_FUNCS = {"malloc", "calloc", "realloc", "_Znwm", "_Znam"}

    def __init__(self, use_win64_abi: bool = False):
        self._loops: List[LoopInfo] = []
        self._accumulations: List[WriteAccumulation] = []
        self._findings: List[dict] = []
        self._win64 = use_win64_abi
        self._arg_regs = self._init_arg_regs(use_win64_abi)
        self._resolver = LoopPtrResolver()
        self._instructions: List[dict] = []

    @staticmethod
    def _init_arg_regs(win64: bool) -> tuple:
        return ("rcx", "rdx", "r8", "r9") if win64 \
            else ("rdi", "rsi", "rdx", "rcx", "r8", "r9")

    def analyze(self, instructions: List[dict],
                alloc_tracker: HeapConstraintTracker,
                use_win64_abi: bool = False) -> List[dict]:
        """分析指令序列, 检测循环累加溢出."""
        self._win64 = use_win64_abi
        self._arg_regs = self._init_arg_regs(use_win64_abi)
        self._instructions = instructions
        self._loops = self._detect_loops(instructions)
        if not self._loops:
            return []
        for loop in self._loops:
            accum = self._trace_loop_writes(instructions, loop, alloc_tracker)
            if accum:
                self._accumulations.extend(accum)
        self._findings = self._check_overflow(alloc_tracker)
        return list(self._findings)

    def _detect_loops(self, instructions: List[dict]) -> List[LoopInfo]:
        """检测所有循环结构 (后向条件跳转)."""
        loops = []
        addr_to_idx = {ins.get("address", 0): i
                       for i, ins in enumerate(instructions)}
        for i, ins in enumerate(instructions):
            mnem = ins.get("mnemonic", "").lower()
            if not mnem.startswith("j") or mnem == "jmp":
                continue
            ops = ins.get("operands", [])
            if not ops:
                continue
            target = self._parse_target(ops[0])
            if target is None:
                continue
            cur_addr = ins.get("address", 0)
            if target >= cur_addr or target not in addr_to_idx:
                continue
            header_idx = addr_to_idx[target]
            trip, counter, is_known = LoopTripCounter.estimate(
                instructions, header_idx, i, mnem)
            loops.append(LoopInfo(
                header=target, back_edge=cur_addr,
                body_start=target, body_end=cur_addr,
                trip_count=trip, counter_reg=counter,
                is_known=is_known))
        return loops

    def _trace_loop_writes(self, instructions: List[dict],
                           loop: LoopInfo,
                           alloc_tracker: HeapConstraintTracker
                           ) -> List[WriteAccumulation]:
        """在循环所属函数范围内追踪写入, 避免CRT污染.

        两类写入:
        A) call memcpy/memset - 尺寸从参数寄存器提取
        B) 直接内存写入 mov [reg], imm - 尺寸从操作数前缀推断
        """
        accumulations = []
        s_idx = self._resolver.find_func_start(instructions, loop.header_addr)
        e_idx = self._resolver.find_func_end(instructions, loop.back_edge_addr)
        ptr_map = self._resolver.build_ptr_map(
            instructions, s_idx, e_idx, alloc_tracker)
        dst_reg = self._arg_regs[0] if self._arg_regs else "rdi"
        for i in range(s_idx, min(e_idx + 1, len(instructions))):
            ins = instructions[i]
            addr = ins.get("address", 0)
            if not (loop.body_start <= addr <= loop.body_end):
                continue
            mnem = ins.get("mnemonic", "").lower()
            ops = ins.get("operands", [])
            # A) call形式的函数写入
            if mnem == "call" and ops:
                func = extract_func_name(ops[0])
                if func not in self._WRITE_FUNCS:
                    continue
                alloc_addr = self._resolver.resolve_ptr_for_call(
                    instructions, i, dst_reg, ptr_map)
                if alloc_addr is None:
                    continue
                size_idx = 2 if func in self._WRITE_FUNCS - {"fread"} else 1
                size_val = self._extract_write_size(instructions, i, size_idx)
                if size_val is None or size_val <= 0:
                    continue
                accum = self._find_or_create_accum(
                    accumulations, alloc_addr, dst_reg, size_val, loop)
                accum.write_count += 1
                accum.write_addrs.append(addr)
                continue
            # B) 直接内存写入 mov [reg], imm/reg
            if mnem == "mov" and len(ops) >= 2:
                dst_op = ops[0].strip()
                dst_lower = dst_op.lower()
                if "[" not in dst_lower:
                    continue
                # 解析基址寄存器
                base = self._extract_base_reg(dst_lower)
                if base is None:
                    continue
                alloc_addr = ptr_map.get(base)
                if alloc_addr is None:
                    continue
                write_size = self._infer_write_size_from_prefix(dst_lower)
                accum = self._find_or_create_accum(
                    accumulations, alloc_addr, base, write_size, loop)
                accum.write_count += 1
                accum.write_addrs.append(addr)
        return accumulations

    @staticmethod
    def _extract_base_reg(op: str) -> Optional[str]:
        from .loop_bound_correlate import extract_base_reg
        return extract_base_reg(op)

    @staticmethod
    def _infer_write_size_from_prefix(op: str) -> int:
        from .loop_bound_correlate import infer_write_size_from_prefix
        return infer_write_size_from_prefix(op)

    def _find_or_create_accum(self, lst: List[WriteAccumulation],
                              alloc_addr: int, ptr_reg: str,
                              single_write: int,
                              loop: LoopInfo) -> WriteAccumulation:
        for a in lst:
            if a.alloc_addr == alloc_addr:
                return a
        accum = WriteAccumulation(alloc_addr, ptr_reg, single_write, loop)
        lst.append(accum)
        return accum

    def _check_overflow(self, alloc_tracker: HeapConstraintTracker
                        ) -> List[dict]:
        """检查每个累加写入是否超过分配大小."""
        from .loop_overflow_builder import (
            build_offbyone as _build_offbyone,
            build_accum as _build_accum)
        findings = []
        for accum in self._accumulations:
            if accum.write_count == 0:
                continue
            alloc = alloc_tracker._allocations.get(accum.alloc_addr)
            if alloc is None:
                continue
            raw_size = getattr(alloc, 'raw_alloc_size', alloc.alloc_size)
            # alloc_size 用请求上界 (raw_alloc_size.hi); 与对齐上界
            # 相比更贴近实际请求, 供后续 allocator 层精确判定.
            alloc_size = raw_size.hi
            if alloc_size <= 0:
                continue
            total_write = accum.single_write_size * accum.loop.trip_count
            # 未知迭代次数: 若循环上界与分配大小同源, 且循环含
            # 等号 (jae/jbe/jge/jle), 则写入次数 = 分配大小+1 →
            # 必然 off-by-one 溢出. 这是经典的循环越界模式.
            if not accum.loop.is_known_count and \
                    self._loop_bound_equals_alloc(accum):
                total_write = alloc_size + 1
                accum.total_write = total_write
                findings.append(_build_offbyone(
                    accum, alloc, alloc_size, total_write))
                continue
            # 单次迭代可含多条写指令 (如两个 qword store = 16B),
            # 总量 = 单条写尺寸 × 单迭代写条数 × 迭代次数.
            if accum.write_count > 1:
                total_write = accum.single_write_size * \
                    accum.write_count * accum.loop.trip_count
                accum.total_write = total_write
            if total_write > alloc_size:
                overflow = total_write - alloc_size
                findings.append(_build_accum(
                    accum, alloc, alloc_size, total_write, overflow))
        return findings

    def _extract_write_size(self, instructions: List[dict],
                            call_idx: int, size_arg_idx: int) -> Optional[int]:
        """从call前的mov中提取写入大小的常量."""
        if size_arg_idx < len(self._arg_regs):
            size_reg = self._arg_regs[size_arg_idx]
            size_regs = (size_reg, size_reg.replace("r", "e")
                         if size_reg.startswith("r") else size_reg)
        else:
            size_regs = ("rdx", "edx")
        for j in range(max(0, call_idx - 15), call_idx):
            ins = instructions[j]
            mnem = ins.get("mnemonic", "").lower()
            ops = ins.get("operands", [])
            if mnem.startswith("mov") and len(ops) >= 2:
                if norm_reg(ops[0]) in size_regs:
                    val = self._parse_imm(ops[1])
                    if val is not None:
                        return val
        return None

    def _loop_bound_equals_alloc(self, accum: WriteAccumulation) -> bool:
        """判断循环上界是否与分配大小同源 (含等号边界循环).

        实现委托 loop_bound_correlate.
        """
        from .loop_bound_correlate import loop_bound_equals_alloc as _f
        return _f(self._instructions, accum.loop.body_start,
                  accum.alloc_addr, self._arg_regs)

    def _parse_target(self, op: str) -> Optional[int]:
        from .loop_bound_correlate import parse_target
        return parse_target(op)

    @staticmethod
    def _parse_imm(op: str) -> Optional[int]:
        from .loop_bound_correlate import parse_imm
        return parse_imm(op)

    @property
    def findings(self) -> List[dict]:
        return list(self._findings)

    @property
    def stats(self) -> dict:
        return {
            "loops_detected": len(self._loops),
            "accumulations_tracked": len(self._accumulations),
            "overflow_findings": len(self._findings),
        }

    def reset(self):
        self._loops.clear()
        self._accumulations.clear()
        self._findings.clear()


__all__ = ["LoopWriteAccumulator", "LoopInfo", "WriteAccumulation"]
