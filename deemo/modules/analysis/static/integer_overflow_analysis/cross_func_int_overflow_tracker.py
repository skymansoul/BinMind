"""跨函数整数溢出追踪 — callee 返回 tainted rax → 调用者 malloc 欠分配.

问题: 函数A中 imul 结果未检查, 通过 rax 返回 → 调用者B直接传入 malloc.
当前 binary_int_overflow_scanner 在 ret 时清除 taint, 错过此跨函数场景.
解法: 预扫描所有函数, 记录 ret 时 rax 是否来自 imul/shl.
"""

from typing import Dict, List, Optional, Set
import sys, os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ..heap_analysis.instruction_parser import InstructionParser, ParsedInstruction


class CrossFuncIntOverflowTracker:
    """跨函数整数溢出追踪 — 检测哪些函数通过 rax 返回溢出结果."""

    def __init__(self):
        self._tainted_returns: Set[str] = set()

    def analyze_functions(self, insns: List[ParsedInstruction],
                          funcs: Dict[int, str],
                          overflow_ops: Set[str]):
        """预扫描: 对每个函数追踪 rax 在 ret 时是否持有 imul/shl 结果."""
        self._tainted_returns.clear()
        sorted_starts = sorted(funcs.keys())
        for i, start in enumerate(sorted_starts):
            end = (sorted_starts[i + 1]
                   if i + 1 < len(sorted_starts) else 0xFFFFFFFFFFFFFFFF)
            self._analyze_one(insns, start, end, funcs[start], overflow_ops)

    def _analyze_one(self, insns: List[ParsedInstruction],
                     start: int, end: int, name: str,
                     overflow_ops: Set[str]):
        """单函数内: 追踪 rax 的溢出状态直到 ret."""
        reg_taint: Set[str] = set()

        for ins in insns:
            if ins.address < start: continue
            if ins.address >= end: break
            mn = ins.mnemonic

            if mn in overflow_ops and len(ins.operands) >= 1:
                dst = InstructionParser.normalize_reg(ins.operands[0])
                if dst: reg_taint.add(dst)
            elif mn in ('mov', 'movabs') and len(ins.operands) >= 2:
                dst = InstructionParser.normalize_reg(ins.operands[0])
                src = InstructionParser.normalize_reg(ins.operands[1].strip())
                if dst and src:
                    if src in reg_taint:
                        reg_taint.add(dst)
                    elif dst in reg_taint:
                        reg_taint.discard(dst)
                elif dst and src is None:
                    # mov dst, imm → 清除; mov dst, [mem] → 保留 (可能持有 taint)
                    if '[' not in ins.operands[1].strip().lower():
                        reg_taint.discard(dst)
            elif mn == 'xor' and len(ins.operands) >= 2:
                if ins.operands[0].strip() == ins.operands[1].strip():
                    dst = InstructionParser.normalize_reg(ins.operands[0])
                    if dst: reg_taint.discard(dst)
            elif mn == 'lea' and len(ins.operands) >= 2:
                dst = InstructionParser.normalize_reg(ins.operands[0])
                if dst: reg_taint.discard(dst)
            elif mn == 'ret':
                if 'rax' in reg_taint:
                    self._tainted_returns.add(name)
                return

    def is_tainted_return(self, func_name: str) -> bool:
        return func_name in self._tainted_returns


# smoke test
def _check():
    asm = """
1000 <compute_size>:
1000:       55                      push   rbp
1001:       48 89 e5                mov    rbp,rsp
1004:       48 8b 45 10             mov    rax,QWORD PTR [rbp+0x10]
1008:       48 0f af 45 18          imul   rax,QWORD PTR [rbp+0x18]
100d:       c3                      ret
100e <caller>:
100e:       55                      push   rbp
100f:       48 89 e5                mov    rbp,rsp
1012:       48 8b 4d 10             mov    rcx,QWORD PTR [rbp+0x10]
1016:       e8 e5 fe ff ff          call   1000 <compute_size>
101b:       48 89 c1                mov    rcx,rax
101e:       e8 dd fe ff ff          call   malloc
"""
    insns = InstructionParser.parse(asm)
    funcs = InstructionParser.parse_functions(asm)
    tracker = CrossFuncIntOverflowTracker()
    tracker.analyze_functions(insns, funcs, {'imul', 'mul', 'shl', 'sal'})
    assert tracker.is_tainted_return('compute_size'), \
        "compute_size should return tainted rax"
    assert not tracker.is_tainted_return('caller'), \
        "caller should not return tainted rax"
    print("[OK] cross_func_int_overflow_tracker")


if __name__ == "__main__":
    _check()
