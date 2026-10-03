"""ALPR 过程间摘要 — 提取/合并函数级 free/use 参数摘要.

用途: 跨函数 UAF 关联。函数内分析无法关联 free 在 A、use 在 B 的
       场景; 本模块从单函数结果提取"哪些参数被释放/被解引用",
       在 call 点展开为调用方的事件。

摘要格式:
  {func_name: {'frees': [arg_idx...], 'uses': [arg_idx...]}}
  arg_idx 为 1-based 参数序号 (Win64: rcx=1, rdx=2, ...)。
"""

from typing import Dict, List

from modules.vuln.detection.heap_analysis.insn_parser import Instruction
from modules.vuln.detection.heap_analysis.acpe.sym_types import _detect_abi

from modules.vuln.detection.heap_analysis.uaf_alpr.uaf_types import (
    FreeRecord, UafUse, FuncLifetimeResult)


def _arg_index(reg: str, arg_regs: List[str]) -> int:
    try:
        return arg_regs.index(reg) + 1
    except ValueError:
        return 0


def _arg_index_from_label(label: str) -> int:
    """arg1 → 1. 解引用常发生在 rax 等非参数寄存器上,
    但其溯源标签指向参数 — 按标签映射更稳健。"""
    if label.startswith('arg'):
        try:
            return int(label[3:])
        except ValueError:
            return 0
    return 0


def build_summary(result: FuncLifetimeResult, insns: List[Instruction]) -> dict:
    """从单函数结果提取参数摘要."""
    arg_regs = _detect_abi(insns)
    frees: List[int] = []
    uses: List[int] = []
    for f in result.frees:
        idx = _arg_index(f.ptr_reg, arg_regs) or _arg_index_from_label(f.freed_label)
        if idx and idx not in frees:
            frees.append(idx)
    for u in result.uses:
        idx = _arg_index(u.ptr_reg, arg_regs) or _arg_index_from_label(u.use_label)
        if idx and idx not in uses:
            uses.append(idx)
    return {'frees': sorted(frees), 'uses': sorted(uses)}


def build_summaries(functions, tracker) -> Dict[str, dict]:
    """第一遍: 对所有用户函数构建摘要."""
    summaries = {}
    for fn in functions:
        result = tracker.analyze_function(fn.name, fn.insns)
        summ = build_summary(result, fn.insns)
        if summ['frees'] or summ['uses']:
            summaries[fn.name] = summ
    return summaries


# 自检
def _check():
    from modules.vuln.detection.heap_analysis.insn_parser import (
        Instruction as I)
    # teardown(t): free(t) → t 为参数1
    insns = [
        I(0x100, 'call', '1400032c0 <free>', ''),
    ]
    # 手工构造 result: free 作用于 rcx (Win64 arg1)
    from modules.vuln.detection.heap_analysis.uaf_alpr.uaf_types import (
        FreeRecord, UseKind, UafUse)
    res = FuncLifetimeResult(name='teardown')
    res.frees.append(FreeRecord(0x100, 'teardown', 'rcx', 'alloc@50'))
    summ = build_summary(res, insns)
    assert summ['frees'] == [1], summ
    assert summ['uses'] == []
    print('[OK] interproc passed')


if __name__ == '__main__':
    _check()
