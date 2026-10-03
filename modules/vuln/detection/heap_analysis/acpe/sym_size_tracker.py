"""符号 size 追踪器 — 函数内前向单遍扫描, 提取符号容量表达式.

用途: 分配容量溯源的数据流侧。对单个函数维护寄存器/栈槽的符号值
      (容量表达式), 在调用点捕获分配 size 与写入 size。

与 reg_tracker.py 的关系:
  reg_tracker 用字符串标签 + 整数记录 size_val。
  本模块保留整数能力并新增符号表达式(参数/地址派生), 使分配容量溯源
  能判定 malloc(n) 与 memcpy(...,n) 的容量等价关系。

注: 指令处理逻辑与共享类型分别维护在独立模块, 与 heap_analysis
    既有 reg_tracker/_insn_handlers/_types 的组织一致。
"""

from typing import List

from modules.vuln.detection.heap_analysis.insn_parser import Instruction

from modules.vuln.detection.heap_analysis.acpe.sym_types import (
    FuncSymResult, _detect_abi, _COND_JCC, match_write_alloc)
from modules.vuln.detection.heap_analysis.acpe._insn_handlers_alloc_capacity import (
    TrackerState, reset,
    on_mov, on_lea, on_addsub, on_imul, on_xor, on_bitop,
    on_cmp, on_jcc, on_call)


class SymSizeTracker:
    """符号容量追踪器 — 单个函数内前向扫描.

    使用:
      tracker = SymSizeTracker()
      result = tracker.analyze_function(func_name, insns)
    """

    def __init__(self):
        self._st = TrackerState()

    def analyze_function(self, func_name: str,
                         insns: List[Instruction]) -> FuncSymResult:
        result = FuncSymResult(name=func_name, insns=list(insns))
        arg_regs = _detect_abi(insns)
        reset(self._st, arg_regs)

        for insn in insns:
            mn = insn.mnemonic
            if mn == 'cmp':
                on_cmp(self._st, insn, result)
            elif mn in _COND_JCC:
                on_jcc(self._st, insn, result)
            elif mn == 'call':
                on_call(self._st, insn, result, func_name, arg_regs)
            elif mn in ('mov', 'movsxd', 'movzx', 'movsx'):
                on_mov(self._st, insn)
            elif mn == 'lea':
                on_lea(self._st, insn)
            elif mn in ('add', 'sub'):
                on_addsub(self._st, insn, mn == 'add')
            elif mn == 'imul':
                on_imul(self._st, insn)
            elif mn in ('xor', 'pxor'):
                on_xor(self._st, insn)
            elif mn in ('and', 'or'):
                on_bitop(self._st, insn, mn)
        return result


# 自检
def _check():
    from modules.vuln.detection.heap_analysis.insn_parser import (
        Instruction as I)
    insns = [
        I(0x1000, 'mov', 'QWORD PTR [rbp+0x10],rcx', ''),
        I(0x1004, 'mov', 'rax,QWORD PTR [rbp+0x10]', ''),
        I(0x1008, 'mov', 'rcx,rax', ''),
        I(0x100c, 'call', '140003378 <malloc>', ''),
        I(0x1010, 'mov', 'QWORD PTR [rbp-0x8],rax', ''),
        I(0x1014, 'mov', 'rax,QWORD PTR [rbp+0x10]', ''),
        I(0x1018, 'mov', 'rcx,rax', ''),
        I(0x101a, 'mov', 'r8,rcx', ''),
        I(0x101c, 'call', '140003380 <memcpy>', ''),
    ]
    res = SymSizeTracker().analyze_function('f', insns)
    assert len(res.allocs) == 1, res.allocs
    assert res.allocs[0].size_expr.canonical() == 'A:1', res.allocs[0]
    assert len(res.writes) == 1, res.writes
    assert res.writes[0].size_expr.canonical() == 'A:1', res.writes[0]
    alloc = match_write_alloc(res.writes[0], res.allocs)
    assert alloc is not None
    print('[OK] sym_size_tracker passed')


if __name__ == '__main__':
    _check()
