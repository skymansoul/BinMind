"""二进制级 UAF 扫描器 - objdump → free/realloc → 释放后使用 + 栈槽 + 跨函数.
检测: deref_after_free | double_free | pass_as_arg | realloc_dangling
      realloc_zero_free | cross_func_return | stack_slot_propagate
架构: scanner (指令解释) + freed_tracker (寄存器+栈槽追踪) + cross_func (ret 逃逸)
理论: 过程间摘要 + 别名追踪."""

from typing import Dict, List, Optional, Set
import sys, os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from ..heap_analysis.instruction_parser import InstructionParser, ParsedInstruction
from .uaf_freed_tracker import FreedPtr, UafFinding, FreedPtrTracker
from .cross_func_uaf_tracker import CrossFuncUafTracker


class BinaryUafScanner:

    def __init__(self):
        self._tracker = FreedPtrTracker()
        self._findings: List[UafFinding] = []
        self._insns: List[ParsedInstruction] = []
        self._reported_addrs: set = set()
        self._cross_tracker = CrossFuncUafTracker()
        self._escaping_funcs: Set[str] = set()

    def scan(self, objdump_output: str, sample_name: str = "",
             user_code_only: bool = True,
             functions: Optional[Dict[int, str]] = None) -> List[dict]:
        self._tracker = FreedPtrTracker()
        self._findings.clear(); self._reported_addrs.clear()
        insns = InstructionParser.parse(objdump_output)
        if not insns: return []

        all_funcs = functions
        if user_code_only:
            if all_funcs is None:
                all_funcs = InstructionParser.parse_functions(objdump_output)
            insns = InstructionParser.filter_user_instructions(insns, all_funcs)
        self._insns = insns
        self._tracker.set_instructions(insns)

        # 跨函数分析: 检测通过 ret 逃逸 freed 指针的函数
        if all_funcs is None:
            all_funcs = InstructionParser.parse_functions(objdump_output)
        self._cross_tracker.analyze_functions(
            insns, all_funcs,
            self._tracker.FREE_FUNCS, self._tracker.REALLOC_FUNCS)
        self._escaping_funcs = self._cross_tracker._escaping_funcs

        for ins in insns: self._step(ins)
        return [f.__dict__ for f in self._findings]

    # 指令分发
    def _step(self, ins: ParsedInstruction):
        mn = ins.mnemonic
        if mn == "call": self._step_call(ins)
        elif mn in ("mov", "movabs") and len(ins.operands) >= 2: self._step_mov(ins)
        elif mn == "lea" and len(ins.operands) >= 2: self._step_lea(ins)
        elif mn in ("add", "sub") and len(ins.operands) >= 2: self._step_modify(ins)
        elif mn == "xor" and len(ins.operands) >= 2:
            if ins.operands[0].strip() == ins.operands[1].strip():
                dst = InstructionParser.normalize_reg(ins.operands[0])
                if dst: self._tracker.clear_reg(dst)
        elif mn == "ret": self._tracker.clear_all()

    # call 指令处理
    def _step_call(self, ins: ParsedInstruction):
        callee = InstructionParser.extract_callee(ins)
        if callee in self._tracker.FREE_FUNCS:
            self._handle_free(ins)
            self._tracker.clear_caller_clobbered(keep_freed=True)
            return
        if callee in self._tracker.REALLOC_FUNCS:
            self._handle_realloc(ins)
            self._tracker.clear_caller_clobbered(keep_freed=True)
            return
        self._check_pass_freed_arg(ins, callee)
        self._tracker.clear_caller_clobbered()
        # 跨函数: callee 通过 ret 逃逸 freed 指针 → rax 标记 freed
        if callee and callee in self._escaping_funcs:
            self._tracker.mark_freed('rax', ins.address, "free")
            self._add_finding(UafFinding(
                insn_addr=ins.address, subtype="cross_func_return",
                freed_at=ins.address,
                    reason=f"{callee}() returns freed ptr via rax - "
                       f"caller's rax now dangling",
                confidence=0.60))

    def _handle_free(self, ins: ParsedInstruction):
        for r in ('rcx', 'rdi'):
            if r in self._tracker:
                prev = self._tracker.get_freed(r)
                self._add_finding(UafFinding(
                    insn_addr=ins.address, subtype="double_free",
                    freed_at=prev.free_addr,
                    reason=f"double free of {r} "
                           f"(first free@0x{prev.free_addr:x})",
                    confidence=0.90))
                return
        for r in ('rcx', 'rdi'):
            if self._tracker.is_ptr_reg(r):
                dup = self._tracker.mark_freed(r, ins.address, "free")
                if dup:
                    self._add_finding(UafFinding(
                        insn_addr=ins.address, subtype="double_free",
                        freed_at=dup.free_addr,
                        reason=f"double free of {r} via mov chain",
                        confidence=0.85))
                    return
                aliases = self._tracker.find_aliases(r, ins.address)
                for alias in aliases:
                    if alias not in self._tracker:
                        self._tracker.mark_freed(alias, ins.address, "free")
                break

    def _handle_realloc(self, ins: ParsedInstruction):
        """realloc(ptr,size): 旧内存释放+别名悬空; realloc(ptr,0)≡free(ptr)."""
        size_is_zero = self._is_realloc_size_zero(ins.address)
        for r in ('rcx', 'rdi'):
            if not self._tracker.is_ptr_reg(r): continue
            if size_is_zero:
                self._tracker.mark_freed(r, ins.address, "realloc_zero")
                for alias in self._tracker.find_aliases(r, ins.address):
                    self._tracker.mark_freed(alias, ins.address, "realloc_zero")
                self._add_finding(UafFinding(
                    insn_addr=ins.address, subtype="realloc_zero_free",
                    freed_at=ins.address,
                    reason=f"realloc({r}, 0) ≡ free({r}) per C23 §7.24.3.7",
                    confidence=0.95))
            else:
                self._tracker.mark_freed(r, ins.address, "realloc")
                newly_freed = self._tracker.mark_realloc_freed(r, ins.address)
                if newly_freed:
                    self._add_finding(UafFinding(
                        insn_addr=ins.address, subtype="realloc_dangling",
                        freed_at=ins.address,
                        reason=f"realloc({r}): old aliases "
                               f"{','.join(sorted(newly_freed))} now dangling",
                        confidence=0.75))
            break

    def _check_pass_freed_arg(self, ins: ParsedInstruction, callee: str):
        for r in ('rcx', 'rdx', 'r8', 'r9'):
            if r in self._tracker:
                fp = self._tracker.get_freed(r)
                self._add_finding(UafFinding(
                    insn_addr=ins.address, subtype="pass_as_arg",
                    freed_at=fp.free_addr,
                    reason=f"freed ptr in {r} passed to {callee}() "
                           f"(freed@0x{fp.free_addr:x})",
                    confidence=0.65))

    def _step_mov(self, ins: ParsedInstruction):
        ops = ins.operands
        dst = InstructionParser.normalize_reg(ops[0])
        src = InstructionParser.normalize_reg(ops[1].strip())
        if dst and src and src in self._tracker:
            self._tracker.propagate(src, dst, ins.address)
        # 栈槽→栈槽: mov [rbp-0xN], freed_reg | mov reg, [freed_slot]
        self._step_mov_stack(ins, ops, dst, src)
        # 内存写入: mov [freed_reg], ... → UAF 写
        if not dst:
            base, _ = InstructionParser.parse_memory_operand(ops[0])
            if base and base in self._tracker:
                fp = self._tracker.get_freed(base)
                self._add_finding(UafFinding(
                    insn_addr=ins.address, subtype="deref_after_free",
                    freed_at=fp.free_addr,
                    reason=f"write to freed ptr {base} "
                           f"(freed@0x{fp.free_addr:x})",
                    confidence=0.85))
        # 内存读取: mov dst, [freed_reg] → UAF 读
        if dst:
            base, _ = InstructionParser.parse_memory_operand(ops[1].strip())
            if base and base in self._tracker:
                fp = self._tracker.get_freed(base)
                self._add_finding(UafFinding(
                    insn_addr=ins.address, subtype="deref_after_free",
                    freed_at=fp.free_addr,
                    reason=f"read from freed ptr {base} "
                           f"(freed@0x{fp.free_addr:x})",
                    confidence=0.80))
        # 从非 freed 内存加载 → 清除 dst
        if dst and dst in self._tracker and not src:
            base, _ = InstructionParser.parse_memory_operand(ops[1].strip())
            if base and base not in self._tracker:
                self._tracker.clear_reg(dst)
        # mov dst, imm → 清除 freed (立即数覆盖)
        if dst and dst in self._tracker and src is None:
            if '[' not in ops[1].strip().lower():
                self._tracker.clear_reg(dst)

    def _step_mov_stack(self, ins: ParsedInstruction, ops, dst, src):
        """栈槽 freed 标记: mov [slot], freed_reg | mov reg, [freed_slot]."""
        t = self._tracker
        d_slot = t.extract_stack_slot(ops[0])
        if d_slot and src and src in t:
            t.propagate_to_stack(d_slot, src, ins.address)
        if d_slot and src is None:
            try: int(ops[1].strip(), 0); t.clear_stack_slot(d_slot)
            except ValueError: pass
        if dst:
            s_slot = t.extract_stack_slot(ops[1])
            if s_slot and t.is_stack_freed(s_slot):
                t.propagate_from_stack(s_slot, dst, ins.address)
            elif s_slot:
                t.clear_reg(dst)

    def _step_lea(self, ins: ParsedInstruction):
        ops = ins.operands
        dst = InstructionParser.normalize_reg(ops[0])
        if not dst: return
        base, _ = InstructionParser.parse_memory_operand(ops[1])
        if base and base in self._tracker:
            self._tracker.propagate_derived(base, dst, ins.address)

    def _step_modify(self, ins: ParsedInstruction):
        """add/sub freed_reg, imm → 保持 freed 标记."""
        ops = ins.operands
        dst = InstructionParser.normalize_reg(ops[0])
        if dst and dst in self._tracker:
            src = ops[1].strip()
            if InstructionParser.normalize_reg(src) is None:
                try: int(src, 0); self._tracker.propagate(dst, dst, ins.address)
                except ValueError: pass

    def _is_realloc_size_zero(self, call_addr: int) -> bool:
        call_idx = -1
        for i, ins in enumerate(self._insns):
            if ins.address == call_addr: call_idx = i; break
        if call_idx < 0: return False
        for offset in range(1, 6):
            j = call_idx - offset
            if j < 0: break
            ins = self._insns[j]
            if ins.mnemonic not in ("mov", "movabs", "xor"): continue
            if len(ins.operands) < 2: continue
            dst = InstructionParser.normalize_reg(ins.operands[0])
            if dst in ('r8', 'rdx'):
                src = ins.operands[1].strip()
                if src in ('0', '0x0'): return True
                if InstructionParser.normalize_reg(src) == dst: return True
        return False

    def _add_finding(self, finding: UafFinding):
        if finding.insn_addr in self._reported_addrs:
            for i, existing in enumerate(self._findings):
                if existing.insn_addr == finding.insn_addr:
                    if finding.confidence > existing.confidence:
                        self._findings[i] = finding
                    return
        self._reported_addrs.add(finding.insn_addr)
        self._findings.append(finding)


def _check():
    s = BinaryUafScanner()
    # deref_after_free: free → write to freed
    r = s.scan("1000: 55 push rbp\n1001: 48 89 e5 mov rbp,rsp\n"
               "1004: 48 8b 4d 10 mov rcx,[rbp+0x10]\n"
               "1008: e8 f3 fe ff ff call free\n"
               "100d: 48 c7 01 00 mov QWORD PTR [rcx],0",
               user_code_only=False)
    assert len(r) >= 1 and any(
        f['subtype'] == 'deref_after_free' for f in r), f"deref:{len(r)}"
    # double_free: free → free same ptr
    r = s.scan("2000: 55 push rbp\n2001: 48 89 e5 mov rbp,rsp\n"
               "2004: 48 8b 4d 10 mov rcx,[rbp+0x10]\n"
               "2008: e8 f3 fe ff ff call free\n"
               "200d: e8 ee fe ff ff call free",
               user_code_only=False)
    assert any(f['subtype'] == 'double_free' for f in r), f"df:{r}"
    # safe: no free
    r = s.scan("3000: 48 8b 4d 10 mov rcx,[rbp+0x10]\n"
               "3004: 48 8b 01 mov rax,[rcx]\n3007: c3 ret",
               user_code_only=False)
    assert len(r) == 0, f"safe:{len(r)}"
    # cross_func_return: wrapper returns freed ptr → caller use
    r = s.scan("4000 <wrapper_free>:\n"
               "4000: 55 push rbp\n4001: 48 89 e5 mov rbp,rsp\n"
               "4004: 48 8b 4d 10 mov rcx,[rbp+0x10]\n"
               "4008: 48 89 c8 mov rax,rcx\n"
               "400b: e8 f0 fe ff ff call free\n"
               "4010: c3 ret\n"
               "4011 <caller>:\n"
               "4011: 55 push rbp\n4012: 48 89 e5 mov rbp,rsp\n"
               "4015: 48 8b 4d 10 mov rcx,[rbp+0x10]\n"
               "4019: e8 e2 fe ff ff call 4000 <wrapper_free>\n"
               "401e: 48 89 c1 mov rcx,rax\n"
               "4021: e8 da fe ff ff call free",
               user_code_only=False)
    cross = [f for f in r if f['subtype'] == 'cross_func_return']
    df = [f for f in r if f['subtype'] == 'double_free']
    assert len(cross) >= 1, f"expected cross_func_return, got {[f['subtype'] for f in r]}"
    print(f"  cross_func_return: {len(cross)}, double_free: {len(df)}")
    print("[OK] binary_uaf_scanner")


if __name__ == "__main__":
    _check()
