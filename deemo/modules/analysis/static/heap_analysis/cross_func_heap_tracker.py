"""跨函数堆数据流追踪 — callee malloc→rax→ret → caller memcpy溢出.
问题: absint_engine单函数, ret清空AbsState, callee中malloc结果caller不可见.
解法: 预扫描函数, 轻量级抽象解释判定rax在ret时是否持有堆指针, 引擎遇call注入.
设计: 二阶迭代(直接+间接传播, ≤5层); 保守仅追踪rax, 不追踪内存/全局变量.
"""

from typing import Dict, List, Optional, Set, Tuple

try:
    from .instruction_parser import InstructionParser, ParsedInstruction
except ImportError:
    from instruction_parser import InstructionParser, ParsedInstruction


def _compute_usable(requested: int) -> int:
    """ptmalloc2: 请求大小→chunk可用字节."""
    MIN_CHUNK, ALIGN, SIZE_SZ = 32, 16, 8
    s = max(requested, MIN_CHUNK - 2 * SIZE_SZ)
    chunk = (s + 2 * SIZE_SZ + ALIGN - 1) & ~(ALIGN - 1)
    return max(MIN_CHUNK, chunk) - 2 * SIZE_SZ


def _find_prev_imm(insns: list, call_idx: int, regs: set) -> int:
    start = call_idx - 1
    for offset in range(10):
        j = start - offset
        if j < 0: break
        p = insns[j]
        if p.mnemonic not in ("mov", "movabs") or len(p.operands) < 2: continue
        norm = InstructionParser.normalize_reg(p.operands[0])
        if norm and norm in regs:
            try: return int(p.operands[1].strip(), 0)
            except ValueError: return 0
    return 0


class FuncHeapState:
    """函数堆状态 — rax在ret时是否持有堆指针."""
    def __init__(self, name: str):
        self.func_name = name
        self.returns_heap_ptr = False
        self.alloc_addr = 0
        self.alloc_size = 0
        self.usable_size = 0
        self.indirect_from: Optional[str] = None


class CrossFuncHeapTracker:
    """跨函数堆数据流 — 预扫描→函数级堆状态图→引擎call时注入."""

    def __init__(self):
        self._func_states: Dict[str, FuncHeapState] = {}
        self._heap_returning: Dict[str, FuncHeapState] = {}

    def analyze(self, insns: List[ParsedInstruction],
                funcs: Dict[int, str], alloc_funcs: Set[str]):
        """两阶段: (1)直接malloc→ret检测 (2)间接传播(A调B,B返堆→A也返堆)."""
        self._func_states.clear(); self._heap_returning.clear()
        sorted_starts = sorted(funcs.keys())
        for i, start in enumerate(sorted_starts):
            end = (sorted_starts[i + 1] if i + 1 < len(sorted_starts)
                   else 0xFFFFFFFFFFFFFFFF)
            state = self._analyze_one(insns, start, end, alloc_funcs)
            self._func_states[funcs[start]] = state
            if state.returns_heap_ptr:
                self._heap_returning[funcs[start]] = state
        # 阶段2: 迭代传播至不动点 (≤5)
        for _ in range(5):
            changed = False
            for name, state in list(self._func_states.items()):
                if state.returns_heap_ptr: continue
                indirect = self._check_indirect(insns, funcs, name, alloc_funcs)
                if indirect:
                    cs = self._heap_returning.get(indirect)
                    if cs:
                        state.returns_heap_ptr = True
                        state.alloc_addr = cs.alloc_addr
                        state.alloc_size = cs.alloc_size
                        state.usable_size = cs.usable_size
                        state.indirect_from = indirect
                        self._heap_returning[name] = state
                        changed = True
            if not changed: break

    def _analyze_one(self, insns: List[ParsedInstruction],
                     start: int, end: int,
                     alloc_funcs: Set[str]) -> FuncHeapState:
        """单函数轻量级抽象解释 — 追踪rax堆状态."""
        state = FuncHeapState("")
        rs: Dict[str, Tuple[bool, int, int]] = {}
        for ins in insns:
            if ins.address < start: continue
            if ins.address >= end: break
            mn, ops = ins.mnemonic, ins.operands

            if mn == "call":
                callee = InstructionParser.extract_callee(ins)
                if callee in alloc_funcs:
                    idx = -1
                    for i, x in enumerate(insns):
                        if x.address == ins.address: idx = i; break
                    size = (_find_prev_imm(insns, idx,
                            {'rdi','edi','rcx','ecx'}) if idx >= 0 else 0) or 128
                    rs['rax'] = (True, ins.address, size)
                    for r in list(rs):
                        if r in ('rcx','rdx','r8','r9','r10','r11'): del rs[r]
                else:
                    for r in list(rs):
                        if r in ('rcx','rdx','r8','r9','r10','r11','rax'): del rs[r]

            elif mn in ('mov','movabs') and len(ops) >= 2:
                dst = InstructionParser.normalize_reg(ops[0])
                src_reg = InstructionParser.normalize_reg(ops[1].strip())
                if dst and src_reg and src_reg in rs:
                    rs[dst] = rs[src_reg]
                elif dst and dst in rs and src_reg is None:
                    if '[' not in ops[1].strip().lower(): del rs[dst]

            elif mn == 'xor' and len(ops) >= 2:
                if ops[0].strip() == ops[1].strip():
                    dst = InstructionParser.normalize_reg(ops[0])
                    if dst and dst in rs: del rs[dst]

            elif mn == 'lea' and len(ops) >= 2:
                dst = InstructionParser.normalize_reg(ops[0])
                if dst:
                    base, _, _, _ = InstructionParser.parse_memory_operand_full(ops[1])
                    if base and base in rs:
                        hp, aa, asz = rs[base]
                        rs[dst] = (hp, aa, asz) if hp else (False, 0, 0)
                    elif dst in rs: del rs[dst]

            elif mn in ('add','sub') and len(ops) >= 2:
                dst = InstructionParser.normalize_reg(ops[0])
                if dst and dst in rs:
                    hp, aa, asz = rs[dst]
                    rs[dst] = (hp, aa, asz)  # 偏移后仍为堆指针

            elif mn == 'ret':
                if 'rax' in rs:
                    hp, aa, asz = rs['rax']
                    if hp:
                        state.returns_heap_ptr = True
                        state.alloc_addr = aa; state.alloc_size = asz
                        state.usable_size = _compute_usable(asz)
                return state
        return state

    def _check_indirect(self, insns: List[ParsedInstruction],
                        funcs: Dict[int, str], name: str,
                        alloc_funcs: Set[str]) -> Optional[str]:
        """检测间接返回: call heap_func → ret (rax未污染)."""
        sorted_starts = sorted(funcs.keys())
        func_start = func_end = None
        for i, s in enumerate(sorted_starts):
            if funcs[s] == name:
                func_start = s
                func_end = (sorted_starts[i+1] if i+1 < len(sorted_starts)
                           else 0xFFFFFFFFFFFFFFFF); break
        if func_start is None: return None
        last_cc, rax_mod = None, False
        for ins in insns:
            if ins.address < func_start: continue
            if ins.address >= func_end: break
            if ins.mnemonic == 'call':
                cc = InstructionParser.extract_callee(ins)
                if cc and cc in self._heap_returning:
                    last_cc = cc; rax_mod = False
                elif cc and cc not in alloc_funcs: last_cc = None
            elif ins.mnemonic in ('mov','movabs') and last_cc:
                dst = InstructionParser.normalize_reg(ins.operands[0])
                if dst == 'rax':
                    if '[' not in ins.operands[1].strip().lower(): rax_mod = True
            elif ins.mnemonic == 'ret':
                return last_cc if (last_cc and not rax_mod) else None
        return None

    # 公共API
    def is_heap_returning(self, func_name: str) -> bool:
        return func_name in self._heap_returning

    def get_heap_return_info(self, func_name: str
                             ) -> Optional[Tuple[int, int, int]]:
        state = self._heap_returning.get(func_name)
        return ((state.alloc_addr, state.alloc_size, state.usable_size)
                if state else None)


# smoke test
def _check():
    asm = """
    1000 <do_alloc>:
    1000:       55                      push   rbp
    1001:       48 89 e5                mov    rbp,rsp
    1004:       48 8b 4d 10             mov    rcx,QWORD PTR [rbp+0x10]
    1008:       e8 f3 fe ff ff          call   malloc
    100d:       c3                      ret
    100e <caller>:
    100e:       55                      push   rbp
    100f:       48 89 e5                mov    rbp,rsp
    1012:       b9 80 00 00 00          mov    ecx,0x80
    1017:       e8 e4 fe ff ff          call   1000 <do_alloc>
    101c:       48 89 c7                mov    rdi,rax
    101f:       ba 00 01 00 00          mov    edx,0x100
    1024:       e8 d7 fe ff ff          call   memcpy
    """
    insns = InstructionParser.parse(asm)
    funcs = InstructionParser.parse_functions(asm)
    af = {'malloc', 'calloc', 'realloc'}
    t = CrossFuncHeapTracker()
    t.analyze(insns, funcs, af)
    assert t.is_heap_returning('do_alloc'), "do_alloc should return heap ptr"
    info = t.get_heap_return_info('do_alloc')
    assert info and info[1] == 128, f"expected alloc_size=128, got {info}"
    print(f"  heap-returning: {list(t._heap_returning.keys())}")
    print("[OK] cross_func_heap_tracker")


if __name__ == "__main__":
    _check()
