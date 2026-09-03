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
    Instruction, Function)


def resolve_cross_fn_writes(
        functions: List[Function],
        func_analyses: List[FuncAnalysis],
        all_allocs: Dict[int, AllocRecord]) -> List[WriteRecord]:
    """跨函数写入解析: 当write的base_src来自callee返回值时, 传播alloc信息.

    三步:
      1. 构建函数名→FuncAnalysis映射
      2. 遍历函数指令, 记录callee含alloc的call点: 其返回值携带malloc标签
      3. 对base_src为unknown的write, 按call处解析出的标签二次回填
    """
    fn_map: Dict[str, FuncAnalysis] = {
        fa.name: fa for fa in func_analyses}
    fn_insns: Dict[str, List[Instruction]] = {
        f.name: f.insns for f in functions if f.name in fn_map}

    # 写类调用: 目标缓冲区取第一个ABI参数(Windows: rcx, SysV: rdi)
    _WRITE_CALLS = {'memcpy', 'memmove', 'memset',
                    'strcpy', 'strcat', 'sprintf', 'snprintf'}

    def _callee_label(callee: str) -> Optional[str]:
        """callee内首个alloc的标签, 无alloc返回None. 校验其已登记到全局allocs."""
        cfa = fn_map.get(callee)
        if not cfa or not cfa.allocs:
            return None
        a = cfa.allocs[0]
        if a.addr not in all_allocs:
            return None
        return f'{a.alloc_func}@{a.addr:x}'

    resolved: List[WriteRecord] = []
    seen = set()

    for fa in func_analyses:
        insns = fn_insns.get(fa.name, [])
        # 单遍扫描: call(malloc函数) → rax=标签; mov/lea传播标签; 写调用记录标签
        reg_tags: Dict[str, str] = {}
        resolved_at: Dict[int, str] = {}
        for insn in insns:
            op = insn.operands
            mn = insn.mnemonic
            if mn == 'call':
                callee = op.strip().split()[0].lstrip('*').split('@')[0]
                if callee in _WRITE_CALLS:
                    arg0 = reg_tags.get('rcx') or reg_tags.get('rdi')
                    if arg0:
                        resolved_at[insn.addr] = arg0
                else:
                    label = _callee_label(callee)
                    if label:
                        reg_tags['rax'] = label
                    else:
                        reg_tags.pop('rax', None)
                continue
            if mn in ('mov', 'movsxd', 'movzx', 'movsx', 'lea'):
                parts = [p.strip() for p in op.split(',')]
                if len(parts) == 2 and reg_tags.get(parts[1]):
                    dst = parts[0]
                    if dst.startswith(('r', 'e')):
                        reg_tags[dst] = reg_tags[parts[1]]
                continue

        for w in fa.writes:
            label = None
            if w.base_src in ('unknown', 'None'):
                label = resolved_at.get(w.addr)
            if label:
                w = WriteRecord(
                    addr=w.addr, write_func=w.write_func, base_src=label,
                    offset=w.offset, size_reg=w.size_reg, size_val=w.size_val,
                    access_size=w.access_size, func_name=w.func_name)
            if w.base_src in ('unknown', 'None'):
                continue
            key = (w.addr, w.write_func, w.base_src)
            if key in seen:
                continue
            seen.add(key)
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
