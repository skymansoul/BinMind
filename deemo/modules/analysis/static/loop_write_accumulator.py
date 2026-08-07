# 循环累加写入追踪器 (Loop Accumulative Write Tracker)
#
# 核心决策:
#   检测循环内多次memcpy的累加溢出: malloc(256); for(i=0;i<5;i++) memcpy(p+off, src, 64);
#   每次memcpy安全(64<=256), 但5次累加=320>256 → 溢出.
#   在循环所属函数范围内重建指针→分配映射 (避免CRT栈帧污染).
#   迭代次数委托 LoopTripCounter 推导.
#
# 理论依据: 循环感知的符号执行; 循环摘要驱动的漏洞检测.
#
# 创建: 2026-07-04

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
        A) call memcpy/memset — 尺寸从参数寄存器提取
        B) 直接内存写入 mov [reg], imm — 尺寸从操作数前缀推断
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
        """从 [reg+off] 形式操作数提取基址寄存器."""
        m = re.search(r'\[([a-z][a-z0-9]*)', op)
        if m:
            return m.group(1)
        return None

    @staticmethod
    def _infer_write_size_from_prefix(op: str) -> int:
        """从操作数前缀推断写入字节数."""
        if "byte" in op:
            return 1
        if "qword" in op:
            return 8
        if "dword" in op:
            return 4
        if "word" in op:
            return 2
        return 1

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
        findings = []
        for accum in self._accumulations:
            if accum.write_count == 0:
                continue
            alloc = alloc_tracker._allocations.get(accum.alloc_addr)
            if alloc is None:
                continue
            raw_size = getattr(alloc, 'raw_alloc_size', alloc.alloc_size)
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
                findings.append({
                    "type": "heap_overflow",
                    "alloc_addr": alloc.alloc_site,
                    "alloc_size": alloc_size,
                    "write_addr": accum.write_addrs[0] if accum.write_addrs else 0,
                    "write_size": total_write,
                    "overflow_bytes": 1,
                    "severity": "high",
                    "detection_method": "loop_accumulation",
                    "loop_trip_count": "alloc+1",
                    "single_write_size": accum.single_write_size,
                    "ptr_operand": accum.ptr_reg,
                    "_snapshot_alloc_addr": accum.alloc_addr,
                    "note": f"loop bound == alloc size: writes "
                            f"alloc+1 bytes (off-by-one) > alloc {alloc_size}B",
                })
                continue
            # 单次迭代可含多条写指令 (如两个 qword store = 16B),
            # 总量 = 单条写尺寸 × 单迭代写条数 × 迭代次数.
            if accum.write_count > 1:
                total_write = accum.single_write_size * \
                    accum.write_count * accum.loop.trip_count
                accum.total_write = total_write
            if total_write > alloc_size:
                overflow = total_write - alloc_size
                findings.append({
                    "type": "heap_overflow",
                    "alloc_addr": alloc.alloc_site,
                    "alloc_size": alloc_size,
                    "write_addr": accum.write_addrs[0] if accum.write_addrs else 0,
                    "write_size": total_write,
                    "overflow_bytes": overflow,
                    "severity": "critical" if overflow > 64 else "high",
                    "detection_method": "loop_accumulation",
                    "loop_trip_count": accum.loop.trip_count,
                    "single_write_size": accum.single_write_size,
                    "ptr_operand": accum.ptr_reg,
                    "_snapshot_alloc_addr": accum.alloc_addr,
                    "note": f"loop body writes {accum.single_write_size}B"
                            f" × {accum.loop.trip_count} iterations"
                            f" = {total_write}B > alloc {alloc_size}B",
                })
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

        典型模式 (CVE-2020-25692):
            n = 参数;  buf = malloc(n);
            for (i = 0; i <= n; i++) buf[i] = 'A';
        反汇编: cmp [rbp+X], rax; jae loop — 上界 [rbp+X] 与
        malloc(n) 的 size 参数同源 → 写入 alloc+1 字节 → off-by-one.
        保守实现: 上界栈槽与分配 size 参数栈槽相同才判 True.
        """
        if not self._instructions:
            return False
        start_idx = None
        for i, ins in enumerate(self._instructions):
            if ins.get("address", 0) == accum.loop.body_start:
                start_idx = i
                break
        if start_idx is None:
            return False
        for j in range(start_idx, min(start_idx + 40, len(self._instructions))):
            ins_j = self._instructions[j]
            if ins_j.get("mnemonic", "").lower() != "cmp":
                continue
            ops = ins_j.get("operands", [])
            if len(ops) < 2:
                return False
            bound_op = self._bound_operand(ops)
            if bound_op is None:
                return False
            alloc_src = self._alloc_size_source(accum.alloc_addr)
            if alloc_src is None:
                return False
            return self._same_source(bound_op, alloc_src)
        return False

    def _bound_operand(self, cmp_ops: List[str]) -> Optional[str]:
        """提取 cmp 中的上界操作数 (非计数器操作数).

        计数器是循环体内被 add/inc 修改的寄存器; 上界是另一个操作数.
        """
        if len(cmp_ops) < 2:
            return None
        ops = [o.strip().lower() for o in cmp_ops]
        counter = self._norm_cmp_counter(ops)
        for op in ops:
            if op != counter:
                return op
        return None

    @staticmethod
    def _norm_cmp_counter(ops: List[str]) -> Optional[str]:
        """识别 cmp 操作数中的纯寄存器作为计数器."""
        for op in ops:
            m = re.search(r'^([a-z][a-z0-9]*)$', op.strip())
            if m:
                return m.group(1)
        return None

    def _alloc_size_source(self, alloc_addr: int) -> Optional[str]:
        """提取分配点 size 参数的来源 (栈槽或寄存器).

        支持多跳寄存器链: mov rcx, rax; mov rax, [rbp+0x10] →
        归约到 [rbp+0x10]. 仅当链能归约为栈槽/参数时返回.
        """
        if not self._instructions:
            return None
        cur_reg = self._arg_regs[0] if self._arg_regs else "rcx"
        # 定位分配调用指令的下标
        alloc_idx = None
        for i, ins in enumerate(self._instructions):
            if ins.get("address", 0) == alloc_addr:
                alloc_idx = i
                break
        if alloc_idx is None:
            return None
        for _hop in range(8):
            src = None
            for j in range(alloc_idx - 1, max(0, alloc_idx - 20) - 1, -1):
                ins_j = self._instructions[j]
                mnem = ins_j.get("mnemonic", "").lower()
                ops = ins_j.get("operands", [])
                if mnem == "call":
                    return None
                if mnem in ("mov", "movsxd", "movzx", "movsx") \
                        and len(ops) >= 2 and norm_reg(ops[0]) == cur_reg:
                    src = ops[1].strip()
                    break
            if src is None:
                return None
            src_l = src.lower()
            if "[" in src_l:
                slot = re.search(r'(r[bs]p[+-]0x[0-9a-f]+)', src_l)
                if slot:
                    return f"[{slot.group(1)}]"
                return src_l
            if self._parse_imm(src_l) is not None:
                return src_l
            cur_reg = norm_reg(src)
            # 继续从该定义点向前回溯 (扫描窗口基于当前指令)
            alloc_idx = alloc_idx - 1
        return None

    @staticmethod
    def _same_source(a: str, b: str) -> bool:
        """比较两个来源 (栈槽/寄存器) 是否同源."""
        def norm(s: str) -> str:
            s = s.lower().replace(" ", "")
            if "ptr" in s:
                s = s.split("ptr")[-1]
            s = s.replace("[", "").replace("]", "")
            m = re.search(r'(r[bs]p[+-]0x[0-9a-f]+)', s)
            if m:
                return m.group(1)
            m = re.search(r'^[a-z][a-z0-9]*$', s)
            if m:
                return m.group(0)
            return s
        return norm(a) == norm(b)

    @staticmethod
    def _parse_target(op: str) -> Optional[int]:
        s = op.strip().lower().lstrip("%").replace("$", "")
        if "<" in s:
            s = s.split("<")[0].strip()
        s = s.split("#")[0].strip()
        try:
            if s.startswith("0x"):
                return int(s, 16)
            if len(s) >= 6 and all(c in "0123456789abcdef" for c in s):
                return int(s, 16)
            return int(s)
        except ValueError:
            return None

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
