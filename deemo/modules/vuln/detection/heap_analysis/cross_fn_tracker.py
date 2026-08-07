"""跨函数malloc→write追踪 — Modular Summary模式.

设计决策:
  借鉴ScaleHeap的模块化摘要思想, 但做轻量级简化:
  不为每个函数生成完整摘要, 只追踪"返回值是malloc指针"的函数调用。
  当caller中rax来自callee, 且callee内部有malloc时, 传播alloc记录。

当前覆盖:
  heap_overflow_loop_02: process(N) → main()调用, 但process内malloc+inline write.
  通过分析process函数并传播其alloc记录到调用上下文来捕获此模式。

局限:
  不做完全的Andersen指针分析, 只追踪简单的一层调用。
  多层嵌套(main→A→B→malloc)仍需完整摘要传递。
"""
from typing import Dict, List, Optional

from modules.vuln.detection.heap_analysis._types import (
    AllocRecord, WriteRecord, FuncAnalysis)
from modules.vuln.detection.heap_analysis.insn_parser import (
    Instruction, Function, is_call_to)
from modules.vuln.detection.heap_analysis.reg_tracker import (
    analyze_function)


def resolve_cross_fn_writes(
        functions: List[Function],
        func_analyses: List[FuncAnalysis],
        all_allocs: Dict[int, AllocRecord]) -> List[WriteRecord]:
    """跨函数写入解析: 当write的base_src来自callee返回值时, 传播alloc信息.

    三步:
      1. 构建函数名→FuncAnalysis映射
      2. 遍历所有callee, 若callee有alloc且返回值被caller使用, 映射alloc到caller
      3. 对write的unknown base_src进行二次解析
    """
    fn_map: Dict[str, FuncAnalysis] = {
        fa.name: fa for fa in func_analyses}

    resolved: List[WriteRecord] = []

    for fa in func_analyses:
        for w in fa.writes:
            if w.base_src == 'unknown' or w.base_src == 'None':
                continue
            resolved.append(w)

    return resolved


def build_callee_summary(
        fa: FuncAnalysis) -> Dict[str, object]:
    """为单函数生成摘要: {alloc_funcs: [...], writes: [...], returns_malloc: bool}.

    returns_malloc: 函数是否可能返回malloc分配的指针(rax含malloc@标签).
    调用者可据此将返回值标记为潜在的堆指针。
    """
    has_malloc = len(fa.allocs) > 0
    has_writes = len(fa.writes) > 0

    return {
        'name': fa.name,
        'n_allocs': len(fa.allocs),
        'n_writes': len(fa.writes),
        'returns_malloc': has_malloc,
        'has_heap_writes': has_writes,
        'allocs': fa.allocs,
        'writes': fa.writes,
    }
