"""抽象解释判定器 — 消费引擎收集的分配/写入/危险调用数据, 输出最终判定.

创建: 2026-07-25
用途: 独立执行安全判定逻辑.
      含 ptmalloc2 可用大小计算、后向约束窄化判定、堆写入偏移判定.
"""

from typing import Dict, List, Optional, Set, Tuple

from .instruction_parser import InstructionParser, ParsedInstruction
from .strided_value import StridedValue, AbsState
from .stack_frame_tracker import StackFrameTracker
from .backward_constraint import BackwardConstraintNarrower


# ptmalloc2 可用大小

def compute_usable(requested: int) -> int:
    """ptmalloc2: 将用户请求大小转换为 chunk 中实际可用字节数."""
    MIN_CHUNK, ALIGN, SIZE_SZ = 32, 16, 8
    s = max(requested, MIN_CHUNK - 2 * SIZE_SZ)
    chunk = (s + 2 * SIZE_SZ + ALIGN - 1) & ~(ALIGN - 1)
    return max(MIN_CHUNK, chunk) - 2 * SIZE_SZ


# 前向扫描辅助

def find_prev_imm(insns: List[ParsedInstruction], call_idx: int,
                  regs: Set[str]) -> Optional[int]:
    """在 call 前找 mov reg, imm 的值 (最多回溯10条)."""
    start = call_idx - 1
    for offset in range(10):
        j = start - offset
        if j < 0:
            break
        p = insns[j]
        if p.mnemonic not in ("mov", "movabs") or len(p.operands) < 2:
            continue
        norm = InstructionParser.normalize_reg(p.operands[0])
        if norm and norm in regs:
            try:
                return int(p.operands[1].strip(), 0)
            except ValueError:
                return None
    return None


# 内存写入处理

def handle_memory_write(state: AbsState, stack: StackFrameTracker,
                        heap_writes: List, ins: ParsedInstruction):
    """处理目标为内存操作数的 mov 指令.
    若目标是 rbp/rsp 相对偏移 → 记录到栈追踪器.
    若目标是堆指针 → 记录堆写入.
    """
    ops = ins.operands
    base, idx, scale, offset = \
        InstructionParser.parse_memory_operand_full(ops[0])
    src_val = ops[1].strip()

    # 存储到 rbp/rsp 相对偏移 → 记录到栈追踪器
    if base in ("rbp", "rsp") and idx is None:
        src_reg = InstructionParser.normalize_reg(src_val)
        if src_reg:
            sv = state.get(src_reg)
            if not (sv.is_top and not sv.is_heap_ptr):
                stack.record_store(
                    offset=offset, lo=sv.lo, hi=sv.hi,
                    stride=sv.stride, is_heap_ptr=sv.is_heap_ptr,
                    alloc_addr=sv.alloc_addr,
                    alloc_size=sv.alloc_size)
        else:
            imm = InstructionParser._try_parse_int(src_val)
            if imm is not None:
                stack.record_store(
                    offset=offset, lo=imm, hi=imm,
                    stride=0, is_heap_ptr=False)
        return

    # 存储到堆指针 → 记录堆写入
    br = base or idx
    if br:
        br_state = state.get(br)
        if br_state.is_heap_ptr:
            access_size = InstructionParser.infer_access_size(ins)
            if br_state.is_partial():
                effective_offset = -1  # sentinel: 未知偏移
            else:
                effective_offset = (br_state.lo
                    - br_state.alloc_addr + offset)
            heap_writes.append(
                (ins.address, br_state.alloc_addr,
                 effective_offset, access_size))


# add/sub 步进

def step_add_sub(state: AbsState, ins: ParsedInstruction):
    """add/sub 指令的抽象语义: 处理寄存器+寄存器或寄存器+立即数."""
    ops = ins.operands
    dst = InstructionParser.normalize_reg(ops[0])
    if not dst:
        return
    src = ops[1].strip()
    src_reg = InstructionParser.normalize_reg(src)
    delta_sign = -1 if ins.mnemonic == "sub" else 1
    if src_reg:
        dst_val = state.get(dst)
        src_val = state.get(src_reg)
        if src_val.is_unknown() and dst_val.is_unknown():
            state.set(dst, StridedValue.unknown())
        elif src_val.is_unknown():
            if dst_val.is_heap_ptr:
                result = dst_val.copy()
                result.is_top = True
                state.set(dst, result)
            else:
                state.set(dst, StridedValue.unknown())
        elif dst_val.is_unknown():
            if src_val.is_heap_ptr:
                result = src_val.copy()
                result.is_top = True
                state.set(dst, result)
            else:
                state.set(dst, StridedValue.unknown())
        elif dst_val.is_heap_ptr or src_val.is_heap_ptr:
            hp = (dst_val if dst_val.is_heap_ptr
                  else src_val)
            sc = (src_val if dst_val.is_heap_ptr
                  else dst_val)
            offset = sc.lo * delta_sign
            result = StridedValue(
                lo=hp.lo + offset, hi=hp.hi + offset,
                stride=hp.stride + sc.stride,
                is_heap_ptr=True,
                alloc_addr=hp.alloc_addr,
                alloc_size=hp.alloc_size)
            state.set(dst, result)
        else:
            result = StridedValue(
                lo=dst_val.lo + src_val.lo * delta_sign,
                hi=dst_val.hi + src_val.hi * delta_sign,
                stride=dst_val.stride + src_val.stride)
            state.set(dst, result)
    else:
        try:
            imm = int(src, 0) * delta_sign
            state.set(dst, state.get(dst).add_imm(imm))
        except ValueError:
            state.set(dst, StridedValue.unknown())


# 判定器

class AbsintAdjudicator:
    """抽象解释判定器 — 消费引擎中间数据, 输出最终安全判定."""

    def __init__(self):
        self._narrower = BackwardConstraintNarrower()

    def adjudicate(self, insns: List[ParsedInstruction],
                   addr_to_idx: Dict[int, int],
                   allocs: Dict[int, Tuple[int, int]],
                   danger_calls: List[Tuple[int, str, int, Optional[int]]],
                   heap_writes: List[Tuple[int, int, int, int]],
                   int_overflow_risks: List[Tuple[int, int, int, str]] = None
                   ) -> Tuple[List[dict], List[dict]]:
        """根据堆写入记录 + 分配信息做最终判定."""
        real, filtered = [], []

        # 整数溢出判定
        if int_overflow_risks:
            for addr, alloc_size, multiplier, reason in int_overflow_risks:
                real.append({
                    "type": "heap_overflow",
                    "subtype": "integer_overflow_alloc",
                    "insn_addr": addr,
                    "function": "malloc",
                    "write_size": 0,
                    "alloc_size": alloc_size,
                    "usable_size": compute_usable(alloc_size),
                    "overflow_by": 0,
                    "reason": reason,
                    "confidence": 0.65,
                    "filtered": False,
                })

        for addr, func, size_val, prov_alloc in danger_calls:
            # 指针溯源: 优先使用寄存器级溯源, 回退到空间邻近
            if prov_alloc is not None and prov_alloc in allocs:
                alloc_size, usable = allocs[prov_alloc]
            else:
                alloc = self._find_nearest_alloc(addr, allocs)
                if alloc is None:
                    real.append(self._mk(addr, func, 0, size_val, 0, 0,
                                         "no nearby alloc", 0.4))
                    continue
                alloc_size, usable = alloc

            # 若 size_val=0 (静态未知), 尝试逆向约束窄化
            narrowed_size = size_val
            if size_val == 0 and insns:
                call_idx = addr_to_idx.get(addr)
                if call_idx is not None:
                    for sz_reg in ('r8', 'rdx'):
                        lo, hi = self._narrower.narrow(
                            insns, call_idx, sz_reg)
                        if hi < 2**31 - 1 or lo > 0:
                            narrowed_size = hi
                            break

            if narrowed_size > 0 and narrowed_size <= usable:
                filtered.append(self._mk(addr, func, alloc_size, narrowed_size,
                    usable, narrowed_size,
                    f"{func} write({narrowed_size}) <= alloc({alloc_size}) "
                    f"usable({usable})", 0.0, True))
            elif size_val > 0:
                real.append(self._mk(addr, func, alloc_size, size_val,
                    usable, size_val,
                    f"{func} write({size_val}) vs alloc({alloc_size}) "
                    f"usable({usable})", 0.85))
            else:
                conf = 0.35 if narrowed_size > 0 else 0.50
                real.append(self._mk(addr, func, alloc_size,
                    max(size_val, narrowed_size), usable, size_val,
                    f"{func} write({size_val}) vs alloc({alloc_size}) "
                    f"usable({usable})", conf))

        # 直接写入判定
        for iaddr, alloc_addr, woffset, asize in heap_writes:
            if alloc_addr not in allocs:
                continue
            alloc_size, usable = allocs[alloc_addr]
            if woffset == -1:
                real.append(self._mk(iaddr, "direct_write",
                    alloc_size, 0, usable, 0,
                    f"direct_write unknown offset; alloc({alloc_size}) "
                    f"usable({usable})", 0.4))
            elif woffset + asize <= usable:
                filtered.append(self._mk(iaddr, "direct_write",
                    alloc_size, woffset + asize, usable, woffset + asize,
                    f"direct_write offset({woffset})+size({asize}) "
                    f"<= usable({usable})", 0.0, True))
            else:
                real.append(self._mk(iaddr, "direct_write",
                    alloc_size, woffset + asize, usable, woffset,
                    f"direct_write offset({woffset})+size({asize}) "
                    f"> alloc({alloc_size}) / usable({usable})",
                    0.85 if woffset >= usable else 0.6,
                    woffset + asize > alloc_size))
        return real, filtered

    @staticmethod
    def _find_nearest_alloc(addr: int,
                            allocs: Dict[int, Tuple[int, int]]
                            ) -> Optional[Tuple[int, int]]:
        best = None
        for a, sz in sorted(allocs.items()):
            if a < addr:
                best = (a, sz)
        return (best[1] if best else None) if best else None

    @staticmethod
    def _mk(addr: int, func: str, alloc_sz: int, write_sz: int,
            usable: int, overflow_by: int, reason: str,
            conf: float, filtered: bool = False) -> dict:
        return {
            "type": "heap_overflow",
            "subtype": "absint",
            "insn_addr": addr,
            "function": func,
            "write_size": write_sz,
            "alloc_size": alloc_sz,
            "usable_size": usable,
            "overflow_by": max(0, overflow_by - usable),
            "reason": reason,
            "confidence": conf,
            "filtered": filtered,
        }
