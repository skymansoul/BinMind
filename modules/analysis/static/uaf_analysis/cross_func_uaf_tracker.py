"""二进制级跨函数 UAF 追踪 - freed 指针通过 rax 返回值逃逸到调用者.

问题: 函数A中 free(ptr) 后 return ptr → 调用者B接收 rax 后继续使用.
当前 binary_uaf_scanner 在 call 时清除 caller-saved regs, 错过此场景.

解法: 追踪每个函数的返回寄存器 (rax/eax) 是否来自已释放指针.
在 call 指令处: 若 callee 返回值是 freed ptr → 标记调用者的 rax 为 freed.

决策: 需要函数边界信息 + 每条 ret 指令前的 rax 状态.
       合并到 FreedPtrTracker 的扩展 API 中, 不修改现有逻辑.
创建: 2024-11-29
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
import sys, os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ..heap_analysis.instruction_parser import InstructionParser, ParsedInstruction


@dataclass
class FuncReturnState:
    """函数的返回值状态 — freed 指针是否通过 rax 逃逸."""
    func_name: str
    func_start: int           # 函数起始地址
    func_end: int             # 函数结束地址 (最后一条指令地址)
    rax_is_freed: bool = False  # ret 时 rax 是否持有 freed 指针
    freed_at_call: int = 0    # 哪个 call free/realloc 导致的释放
    freed_reg_at_ret: str = "" # ret 前哪个寄存器持有 freed ptr


class CrossFuncUafTracker:
    """跨函数 freed 指针追踪 — 检测 ret 逃逸 + 调用者继续使用.

    集成到 BinaryUafScanner 的 scan() 流程中:
      1. 第一遍: 解析函数边界, 收集每个函数的 rax 返回状态
      2. 第二遍: 在 call 指令处, 检查 callee 是否返回 freed ptr
      3. 若 callee 返回 freed ptr → 标记调用者的 rax 为 freed
    """

    def __init__(self):
        # func_start → FuncReturnState
        self._func_states: Dict[int, FuncReturnState] = {}
        # addr → func_start (所有已知函数)
        self._all_funcs: Dict[int, str] = {}
        # callee_name → freed_ptr 逃离状态
        self._escaping_funcs: Set[str] = set()

    def analyze_functions(self, insns: List[ParsedInstruction],
                          funcs: Dict[int, str],
                          free_funcs: Set[str],
                          realloc_funcs: Set[str]):
        """第一遍: 分析每个函数, 检测 ret 时 rax 是否来自 freed ptr.

        算法: 在函数内追踪 rax/rcx 的 freed 状态, 到 ret 指令时记录.
        """
        self._func_states.clear()
        self._escaping_funcs.clear()
        self._all_funcs = dict(funcs)

        sorted_starts = sorted(funcs.keys())
        for i, start in enumerate(sorted_starts):
            end = (sorted_starts[i + 1]
                   if i + 1 < len(sorted_starts) else 0xFFFFFFFFFFFFFFFF)
            name = funcs[start]
            self._analyze_one_func(
                insns, start, end, name, free_funcs, realloc_funcs)

    def _analyze_one_func(self, insns: List[ParsedInstruction],
                          start: int, end: int, name: str,
                          free_funcs: Set[str], realloc_funcs: Set[str]):
        """单函数内追踪 rax freed 状态.

        核心: 维护别名等价类 (register aliasing via mov).
        mov rax,rcx → rax 和 rcx 属于同一等价类.
        后续 call free(rcx) → 等价类中所有寄存器均标记 freed.
        回溯 ret 时 rax 是否在 freed 等价类中.
        """
        # Union-Find: reg → canonical representative
        parent: Dict[str, str] = {}
        def find(r: str) -> str:
            if r not in parent:
                parent[r] = r
            if parent[r] != r:
                parent[r] = find(parent[r])
            return parent[r]
        def union(a: str, b: str):
            ra, rb = find(a), find(b)
            if ra != rb:
                parent[ra] = rb

        # freed_regs: 被 free() 调用标记的寄存器
        freed_regs: Set[str] = set()
        # rax 的释放来源
        rax_freed_at: int = 0
        last_ret_insn = None

        in_func = False
        for ins in insns:
            if ins.address < start:
                continue
            if ins.address >= end:
                break
            in_func = True

            mn = ins.mnemonic

            # call free/realloc: 标记 rcx/rdi + 其等价类
            if mn == "call":
                callee = InstructionParser.extract_callee(ins)
                if callee in free_funcs or callee in realloc_funcs:
                    for r in ('rcx', 'rdi'):
                        if r not in parent:
                            parent[r] = r
                        canon = find(r)
                        # 标记等价类中所有寄存器
                        for reg, p in list(parent.items()):
                            if find(reg) == canon:
                                freed_regs.add(reg)
                                if reg == 'rax':
                                    rax_freed_at = ins.address
                                # rcx 自身也被标记
                                freed_regs.add(r)

            # mov reg, reg → 建立别名 + 传播 freed 状态
            elif mn in ('mov', 'movabs') and len(ins.operands) >= 2:
                dst = InstructionParser.normalize_reg(ins.operands[0])
                src = InstructionParser.normalize_reg(ins.operands[1].strip())
                if dst and src:
                    # 建立等价类
                    union(dst, src)
                    # 若 src 已 freed → dst 也 freed
                    if src in freed_regs:
                        freed_regs.add(dst)
                        if dst == 'rax':
                            rax_freed_at = ins.address

            # xor reg,reg → 清除所有别名 + freed 标记
            elif mn == 'xor' and len(ins.operands) >= 2:
                if ins.operands[0].strip() == ins.operands[1].strip():
                    dst = InstructionParser.normalize_reg(ins.operands[0])
                    if dst:
                        canon = find(dst)
                        for reg in list(freed_regs):
                            if find(reg) == canon:
                                freed_regs.discard(reg)
                        # 从父映射中移除该寄存器的等价类
                        for reg in list(parent.keys()):
                            if find(reg) == canon:
                                del parent[reg]

            # ret: 检查 rax 是否 freed
            elif mn == 'ret':
                last_ret_insn = ins
                if 'rax' in freed_regs or 'eax' in freed_regs:
                    state = FuncReturnState(
                        func_name=name, func_start=start,
                        func_end=ins.address,
                        rax_is_freed=True,
                        freed_at_call=rax_freed_at,
                        freed_reg_at_ret=(
                            'rax' if 'rax' in freed_regs else 'eax'))
                    self._func_states[start] = state
                    self._escaping_funcs.add(name)
                    return

        # 函数未以 ret 结束或无 rax freed → 记录安全状态
        if start not in self._func_states:
            self._func_states[start] = FuncReturnState(
                func_name=name, func_start=start,
                func_end=(last_ret_insn.address
                          if last_ret_insn else end))

    def is_escaping(self, func_name: str) -> bool:
        """检查函数是否通过 rax 逃逸 freed 指针."""
        return func_name in self._escaping_funcs

    def get_return_state(self, func_name: str) -> Optional[FuncReturnState]:
        """获取函数的返回状态."""
        for state in self._func_states.values():
            if state.func_name == func_name:
                return state
        return None


# smoke test
def _check():
    free_funcs = {'free'}
    realloc_funcs = {'realloc'}

    # 场景: wrapper_free 中 free(ptr) 后 return ptr
    asm = """
    1000:       55                      push   rbp
    1001:       48 89 e5                mov    rbp,rsp
    1004:       48 8b 4d 10             mov    rcx,QWORD PTR [rbp+0x10]
    1008:       48 89 c8                mov    rax,rcx
    100b:       e8 f0 fe ff ff          call   free
    1010:       c3                      ret
    """
    insns = InstructionParser.parse(asm)
    funcs = {0x1000: "wrapper_free"}
    tracker = CrossFuncUafTracker()
    tracker.analyze_functions(insns, funcs, free_funcs, realloc_funcs)
    state = tracker.get_return_state("wrapper_free")
    # rax=rcx=ptr, free(rcx) marks rcx as freed,
    # mov rax,rcx propagates freed to rax → ret rax is freed
    assert state is not None, "expected state"
    print(f"  wrapper_free: rax_is_freed={state.rax_is_freed}")
    assert state.rax_is_freed, \
        f"expected rax_is_freed=True for wrapper_free, got {state.rax_is_freed}"
    assert "wrapper_free" in tracker._escaping_funcs

    # 场景: safe_wrapper 中 malloc 后 return ptr (安全)
    asm2 = """
    2000:       55                      push   rbp
    2001:       48 89 e5                mov    rbp,rsp
    2004:       b9 40 00 00 00          mov    rcx,0x40
    2009:       e8 f2 fe ff ff          call   malloc
    200e:       48 89 c1                mov    rcx,rax
    2011:       e8 ea fe ff ff          call   free
    2016:       31 c0                   xor    eax,eax
    2018:       c3                      ret
    """
    insns2 = InstructionParser.parse(asm2)
    funcs2 = {0x2000: "safe_wrapper"}
    tracker2 = CrossFuncUafTracker()
    tracker2.analyze_functions(insns2, funcs2, free_funcs, realloc_funcs)
    state2 = tracker2.get_return_state("safe_wrapper")
    assert state2 is not None, "expected state2"
    assert not state2.rax_is_freed, \
        f"expected rax_is_freed=False, got {state2.rax_is_freed}"
    assert "safe_wrapper" not in tracker2._escaping_funcs

    print("[OK] cross_func_uaf_tracker (return-value escape)")


if __name__ == "__main__":
    _check()
