"""UAF检测编排器 — 反汇编→free/malloc追踪→DT-HSA过滤→多因素分类.

创建: 2025-02-06
拆分: 2025-02-06 — 函数内UAF检测提取至_uaf_intra_detect
管线: objdump → parse_instructions → func_analyzer(free追踪) → FreelistSim
      → intra/cross UAF检测 → DT-HSA时间验证 → confirmed/possible/safe分类

方法依据: DT-HSA (原创, ptmalloc2 bin模拟用于二进制UAF验证)
         + UAF 生命周期验证 typestate + Lancet 所有权语义
"""

import os, sys, subprocess, time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

_cur_dir = os.path.dirname(os.path.abspath(__file__))
if _cur_dir not in sys.path:
    sys.path.insert(0, _cur_dir)

from insn_parser import (Instruction, parse_instructions,
                          extract_malloc_addr, extract_register)
from func_analyzer import FunctionAnalysis, analyze_function
from cross_fn_analyzer import CrossFnAnalyzer
from uaf_freelist_sim import (
    Ptmalloc2FreelistSim, TemporalVerdict, usable_size)
from _uaf_intra_detect import detect_intra_uaf


# 数据结构

@dataclass
class UAFCandidate:
    ptr_name: str; ptr_value: str
    free_insn_addr: int; use_insn_addr: int
    use_type: str          # 'read'|'write'|'call_via'
    function_name: str; instruction_gap: int
    is_cross_fn: bool = False
    temporal_verdict: Optional[TemporalVerdict] = None


@dataclass
class UAFReport:
    binary_path: str = ""
    n_functions: int = 0; n_mallocs: int = 0; n_frees: int = 0
    n_candidates: int = 0; confirmed_uaf: int = 0
    possible_uaf: int = 0; filtered_safe: int = 0
    elapsed_ms: float = 0.0
    findings: List[dict] = field(default_factory=list)


# 主入口

def analyze_uaf(binary_path: str, timeout_s: int = 60) -> UAFReport:
    t0 = time.time()
    report = UAFReport(binary_path=binary_path)
    asm_text = _disassemble(binary_path)
    if not asm_text:
        report.elapsed_ms = round((time.time() - t0) * 1000, 1)
        return report

    functions = parse_instructions(asm_text)
    report.n_functions = len(functions)
    sim = Ptmalloc2FreelistSim()
    candidates: List[UAFCandidate] = []
    all_fas: Dict[str, FunctionAnalysis] = {}

    for fn_name, insns in functions:
        if len(insns) < 3:
            continue
        fa = analyze_function(fn_name, insns)
        all_fas[fn_name] = fa
        _register_fn_events(fa, sim)
        report.n_mallocs += len(fa.mallocs)
        report.n_frees += len(fa.frees)
        candidates.extend(detect_intra_uaf(fa, insns, fn_name, UAFCandidate))

    cross_fn = CrossFnAnalyzer()
    for fn_name, insns in functions:
        if len(insns) >= 3 and fn_name in all_fas:
            cross_fn.register(fn_name, insns, all_fas[fn_name])
    cross_fn.analyze_all()
    candidates.extend(_detect_cross_fn_uaf(cross_fn, all_fas, sim))

    _, _, _, f_all = cross_fn.get_all_findings()
    n_new_frees = 0
    already_freed = {cs.addr for cs in sim._chunks.values() if cs.free_time > 0}
    for f in f_all:
        m_addr = extract_malloc_addr(str(f.get('ptr_val', '')))
        if m_addr and m_addr not in already_freed:
            sim.record_free(m_addr)
            already_freed.add(m_addr)
            n_new_frees += 1
    report.n_frees = max(report.n_frees, n_new_frees + report.n_frees)

    report.n_candidates = len(candidates)

    for cand in candidates:
        cand.temporal_verdict = _verify_temporal(cand, sim)
    _classify_candidates(candidates, report)
    report.elapsed_ms = round((time.time() - t0) * 1000, 1)
    return report


# 注册

def _register_fn_events(fa: FunctionAnalysis, sim: Ptmalloc2FreelistSim) -> None:
    """按指令地址交错注册 malloc+free — 保证函数内执行时序."""
    events = []
    for m in fa.mallocs:
        events.append(('alloc', m.get('addr', 0), m))
    for f in fa.frees:
        events.append(('free', f.get('addr', 0), f))
    for evt, _, data in sorted(events, key=lambda x: x[1]):
        if evt == 'alloc':
            _register_one_malloc(data, sim)
        else:
            _register_one_free(data, sim)


def _register_one_malloc(m: dict, sim: Ptmalloc2FreelistSim) -> None:
    addr = m.get('addr', 0); size = m.get('size_val')
    if isinstance(size, int) and 0 < size <= 0x1000000:
        sim.record_malloc(addr, size)
    elif size is None:
        sim.record_malloc(addr, 128)


def _register_one_free(f: dict, sim: Ptmalloc2FreelistSim) -> None:
    m_addr = extract_malloc_addr(str(f.get('ptr_val', '')))
    if m_addr:
        sim.record_free(m_addr)


# 跨函数 UAF 检测

def _detect_cross_fn_uaf(cross_fn: CrossFnAnalyzer,
                         all_fas: Dict[str, FunctionAnalysis],
                         sim: Ptmalloc2FreelistSim) -> List[UAFCandidate]:
    """指针通过参数/返回值逃逸→其他函数free→原函数仍使用."""
    candidates: List[UAFCandidate] = []
    m_all, w_all, _, f_all = cross_fn.get_all_findings()
    malloc_map = {m.get('addr', 0): m for m in m_all}

    all_frees = list(f_all) if f_all else []
    if not all_frees:
        for fn_name, fa in all_fas.items():
            for f in fa.frees:
                f2 = dict(f); f2['function'] = fn_name; all_frees.append(f2)

    for f_info in all_frees:
        m_addr = extract_malloc_addr(str(f_info.get('ptr_val', '')))
        if not m_addr or m_addr not in malloc_map:
            continue
        free_fn = f_info.get('function', '')
        for w in w_all:
            w_m = extract_malloc_addr(str(w.get('base_val', '')))
            if w_m != m_addr:
                continue
            w_fn = w.get('function', '')
            if w_fn == free_fn:
                continue
            candidates.append(UAFCandidate(
                ptr_name=w.get('base_reg', ''),
                ptr_value=str(f_info.get('ptr_val', '')),
                free_insn_addr=f_info.get('addr', 0),
                use_insn_addr=w.get('addr', 0),
                use_type='write', function_name=w_fn,
                instruction_gap=0, is_cross_fn=True))
    return candidates


# DT-HSA 时间验证

def _verify_temporal(cand: UAFCandidate,
                     sim: Ptmalloc2FreelistSim) -> TemporalVerdict:
    m_addr = extract_malloc_addr(cand.ptr_value)
    if not m_addr:
        return TemporalVerdict(
            chunk_addr=0, is_uaf=True, confidence='possible',
            reason='无法提取malloc地址', accessed_at_time=0)
    return sim.check_uaf(m_addr)


# 分类

def _classify_candidates(candidates: List[UAFCandidate],
                         report: UAFReport) -> None:
    for cand in candidates:
        tv = cand.temporal_verdict
        if tv is None:
            continue
        if tv.confidence == 'confirmed':
            report.confirmed_uaf += 1; decision = 'confirmed_uaf'
        elif tv.confidence == 'possible':
            report.possible_uaf += 1; decision = 'possible_uaf'
        else:
            report.filtered_safe += 1; continue
        report.findings.append({
            'decision': decision, 'function': cand.function_name,
            'ptr_name': cand.ptr_name,
            'free_addr': f'{cand.free_insn_addr:#x}',
            'use_addr': f'{cand.use_insn_addr:#x}',
            'use_type': cand.use_type,
            'instruction_gap': cand.instruction_gap,
            'is_cross_fn': cand.is_cross_fn,
            'temporal_reason': tv.reason,
            'intervening_allocs': tv.intervening_allocs,
            'intervening_same_size': tv.intervening_same_size,
        })


# 反汇编

def _disassemble(elf_path: str) -> str:
    for tool in ['objdump', 'llvm-objdump']:
        try:
            proc = subprocess.run(
                [tool, '-d', '-M', 'intel', elf_path],
                capture_output=True, text=True, timeout=30)
            if proc.returncode == 0 and len(proc.stdout) > 100:
                return proc.stdout
        except Exception:
            continue
    return ""
