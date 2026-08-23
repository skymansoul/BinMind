# 二进制级抽象解释引擎 - objdump 上的跨步区间 VSA + 跨函数堆数据流.
# 零外部依赖; 跨函数堆追踪; 保守汇合→TOP; 后向约束窄化.

from typing import Dict, List, Optional, Set, Tuple

from .instruction_parser import InstructionParser, ParsedInstruction
from .strided_value import StridedValue, AbsState
from .stack_frame_tracker import StackFrameTracker, StackSlot
from .absint_adjudicator import (
    compute_usable, find_prev_imm,
    handle_memory_write, step_add_sub,
    AbsintAdjudicator,
)
from .cross_func_heap_tracker import CrossFuncHeapTracker


class AbstractInterpreter:
    """前向抽象解释器 - 逐指令追踪寄存器值集, 跨函数感知."""

    def __init__(self):
        self._state = AbsState()
        self._insns: List[ParsedInstruction] = []
        self._addr_to_idx: Dict[int, int] = {}
        self._allocs: Dict[int, Tuple[int, int]] = {}
        self._heap_writes: List[Tuple[int, int, int, int]] = []
        self._danger_calls: List[Tuple[int, str, int, Optional[int]]] = []
        # (insn_addr, func_name, write_size, provenance_alloc_addr|None)
        self._int_overflow_risks: List[Tuple[int, int, int, str]] = []
        self._alloc_funcs = {'malloc', 'calloc', 'realloc'}
        self._danger_funcs = {'memcpy', 'memmove', 'strcpy', 'strncpy',
                              'sprintf', 'snprintf', 'gets', '__memcpy_chk',
                              'memset'}
        self._stack = StackFrameTracker()
        self._adjudicator = AbsintAdjudicator()
        self._mul_result_regs: Set[str] = set()
        self._cross_tracker = CrossFuncHeapTracker()
        self._funcs: Dict[int, str] = {}

    def set_functions(self, funcs: Dict[int, str]):
        self._funcs = funcs

    def feed_instructions(self, insns: List[ParsedInstruction]):
        self._insns = insns

    def analyze_all(self) -> Tuple[List[dict], List[dict]]:
        self._prescan_allocs()
        self._addr_to_idx = {ins.address: i for i, ins in enumerate(self._insns)}
        for ins in self._insns:
            self._step_one(ins)
        return self._adjudicator.adjudicate(
            self._insns, self._addr_to_idx, self._allocs,
            self._danger_calls, self._heap_writes,
            self._int_overflow_risks)

    def _prescan_allocs(self):
        """预扫描 malloc + 跨函数堆数据流."""
        for i, ins in enumerate(self._insns):
            if ins.mnemonic != "call": continue
            callee = InstructionParser.extract_callee(ins)
            if callee not in self._alloc_funcs: continue
            size = find_prev_imm(self._insns, i, {'rdi','edi','rcx','ecx'})
            if size is None or size <= 0: size = 128
            self._allocs[ins.address] = (size, compute_usable(size))
        if self._funcs:
            self._cross_tracker.analyze(
                self._insns, self._funcs, self._alloc_funcs)

    def _step_one(self, ins: ParsedInstruction):
        mn, ops = ins.mnemonic, ins.operands
        if not ops: return
        recovered = self._stack.process(ins)
        if mn == "call": self._step_call(ins)
        elif mn in ("mov","movabs") and len(ops) >= 2: self._step_mov(ins, recovered)
        elif mn == "lea" and len(ops) >= 2: self._step_lea(ins)
        elif mn in ("add","sub") and len(ops) >= 2: step_add_sub(self._state, ins)
        elif mn == "xor" and len(ops) >= 2 and ops[0].strip() == ops[1].strip():
            dst = InstructionParser.normalize_reg(ops[0])
            if dst: self._state.set(dst, StridedValue.exact(0))
        elif mn == "imul" and len(ops) >= 2: self._step_imul(ins)
        elif mn == "shl" and len(ops) >= 2: self._step_shl(ins)

    def _step_call(self, ins: ParsedInstruction):
        callee = InstructionParser.extract_callee(ins)
        if callee in self._alloc_funcs:
            if ins.address in self._allocs:
                alloc_size, _ = self._allocs[ins.address]
            else:
                idx = self._addr_to_idx.get(ins.address, -1)
                alloc_size = (find_prev_imm(self._insns, idx,
                    {'rdi','edi','rcx','ecx'}) or 128 if idx >= 0 else 128)
            self._state.set('rax', StridedValue.heap_ptr(ins.address, alloc_size))
            self._check_int_overflow(ins)
        elif callee and self._cross_tracker.is_heap_returning(callee):
            # 跨函数: callee通过rax返回堆指针 → 注入调用者rax状态
            info = self._cross_tracker.get_heap_return_info(callee)
            if info:
                self._allocs[ins.address] = (info[1], info[2])
                self._state.set('rax', StridedValue.heap_ptr(ins.address, info[1]))
        elif callee in self._danger_funcs:
            dest_val = self._state.get('rdi')
            if dest_val.is_unknown(): dest_val = self._state.get('rcx')
            # 指针溯源: 从目标寄存器提取堆分配地址
            prov_alloc = (dest_val.alloc_addr if dest_val.is_heap_ptr
                         and dest_val.alloc_addr else None)
            is_three = callee in {'memcpy','memmove','memset','strncpy',
                                  'snprintf','__memcpy_chk'}
            r8_val = self._state.get('r8')
            rdx_val = self._state.get('rdx')
            size_src = rdx_val if r8_val.is_unknown() else r8_val \
                       if is_three else StridedValue.unknown()
            if size_src.is_unknown():
                size_src = StridedValue.unknown()
            size_val = (size_src.lo if not size_src.is_unknown()
                       and size_src.stride == 0 else 0)
            self._danger_calls.append(
                (ins.address, callee, size_val, prov_alloc))

    def _step_mov(self, ins: ParsedInstruction,
                  recovered: Optional[Tuple[str, 'StackSlot']] = None):
        ops = ins.operands
        dst = InstructionParser.normalize_reg(ops[0])
        if not dst:
            handle_memory_write(self._state, self._stack,
                               self._heap_writes, ins); return
        src_op = ops[1].strip()
        src_reg = InstructionParser.normalize_reg(src_op)
        if recovered and recovered[1]:
            slot = recovered[1]
            if slot.is_heap_ptr:
                self._state.set(dst, StridedValue.heap_ptr(
                    slot.alloc_addr, slot.alloc_size))
            elif slot.is_top: self._state.set(dst, StridedValue.unknown())
            else: self._state.set(dst, StridedValue(
                lo=slot.lo, hi=slot.hi, stride=slot.stride))
            return
        if src_reg: self._state.set(dst, self._state.get(src_reg))
        else:
            try: self._state.set(dst, StridedValue.exact(int(src_op, 0)))
            except ValueError: self._state.set(dst, StridedValue.unknown())

    def _step_lea(self, ins: ParsedInstruction):
        ops = ins.operands
        dst = InstructionParser.normalize_reg(ops[0])
        if not dst: return
        base, idx, scale, offset = \
            InstructionParser.parse_memory_operand_full(ops[1])
        total = StridedValue.exact(0)
        if base: total = self._state.get(base)
        if idx:
            ival = self._state.get(idx)
            if ival.is_unknown():
                self._state.set(dst, StridedValue.unknown()); return
            total = StridedValue(
                lo=total.lo+ival.lo*scale, hi=total.hi+ival.hi*scale,
                stride=total.stride+ival.stride*scale,
                is_heap_ptr=total.is_heap_ptr or ival.is_heap_ptr,
                alloc_addr=(total.alloc_addr if total.is_heap_ptr
                           else ival.alloc_addr),
                alloc_size=(total.alloc_size if total.is_heap_ptr
                           else ival.alloc_size))
        if offset != 0: total = total.add_imm(offset)
        self._state.set(dst, total)

    def _step_imul(self, ins: ParsedInstruction):
        dst = InstructionParser.normalize_reg(ins.operands[0])
        if dst:
            self._state.set(dst, StridedValue.unknown())
            self._mul_result_regs.add(dst)
            if dst.startswith('r'): self._mul_result_regs.add(dst.replace('r','e'))
            elif dst.startswith('e'): self._mul_result_regs.add(dst.replace('e','r'))

    def _step_shl(self, ins: ParsedInstruction):
        dst = InstructionParser.normalize_reg(ins.operands[0])
        if not dst: return
        shift_val = None
        if len(ins.operands) >= 2:
            shift_val = InstructionParser._try_parse_int(ins.operands[1])
        if shift_val is not None and shift_val >= 2:
            self._state.set(dst, StridedValue.unknown())
            self._mul_result_regs.add(dst)
            if dst.startswith('r'): self._mul_result_regs.add(dst.replace('r','e'))
        else: self._state.set(dst, StridedValue.unknown())

    def _check_int_overflow(self, ins: ParsedInstruction):
        idx = self._addr_to_idx.get(ins.address, -1)
        if idx < 0: return
        size_reg = None
        for offset in range(1, 6):
            prev_idx = idx - offset
            if prev_idx < 0: break
            prev = self._insns[prev_idx]
            if prev.mnemonic in ("mov","movabs") and len(prev.operands) >= 2:
                src = InstructionParser.normalize_reg(prev.operands[1])
                dst = InstructionParser.normalize_reg(prev.operands[0])
                if dst in ('rcx','rdi','ecx','edi') and src: size_reg = src
            elif prev.mnemonic == "imul":
                dst = InstructionParser.normalize_reg(prev.operands[0])
                if dst: size_reg = dst; break
            elif prev.mnemonic == "shl":
                dst = InstructionParser.normalize_reg(prev.operands[0])
                if dst: size_reg = dst; break
        if size_reg and size_reg in self._mul_result_regs:
            alloc_size = self._allocs.get(ins.address, (128, 128))[0]
            self._int_overflow_risks.append(
                (ins.address, alloc_size, 0,
                 f"malloc size from imul/shl ({size_reg}) - "
                 f"potential integer overflow in alloc size computation"))


def _check():
    asm = """
    1000:       48 c7 c7 40 00 00 00    mov    rdi,0x40
    1007:       e8 f4 fe ff ff          call   1000 <malloc@plt>
    100c:       48 89 c3                mov    rbx,rax
    100f:       48 8d 53 50             lea    rdx,[rbx+0x50]
    1013:       c7 02 ef be ad de       mov    DWORD PTR [rdx],0xdeadbeef
    """
    insns = InstructionParser.parse(asm)
    engine = AbstractInterpreter()
    engine.feed_instructions(insns)
    real, filtered = engine.analyze_all()
    assert len(real) >= 1, f"expected real vuln, got {len(real)}"
    assert any("direct_write" in r.get("function","") for r in real)
    print(f"[OK] absint_engine: real={len(real)} filtered={len(filtered)}")


if __name__ == "__main__":
    _check()
