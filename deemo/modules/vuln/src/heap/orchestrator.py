"""堆溢出分析编排器 — 顶层管线: 反汇编→指令解析→函数分析→DP-TVRA过滤.

创建: 2026-06-10  修改: 2026-08-06 (跨函数分析集成)
拆分: 2026-08-09 — 辅助函数提取至_heap_orch_helpers
依赖: insn_parser → func_analyzer → cross_fn_analyzer → orchestrator
"""
import os
import sys
import subprocess
import time
from dataclasses import dataclass, field
from typing import Dict, List, Tuple

_cur_dir = os.path.dirname(os.path.abspath(__file__))
if _cur_dir not in sys.path:
    sys.path.insert(0, _cur_dir)

from heap_bound_infer import HeapBoundInferrer, HeapAccess, IntervalDomain
from heap_fp_filter_v2 import HeapFPFilterV2
from insn_parser import Instruction, parse_instructions, extract_malloc_addr
from func_analyzer import FunctionAnalysis, analyze_function
from cross_fn_analyzer import CrossFnAnalyzer
from inline_copy_detector import InlineCopyDetector
from offset_proof_filter import OffsetProofFilter, ProofResult
from loop_accum_detector import detect_loop_accumulated
from _heap_orch_helpers import (register_mallocs, collect_findings,
                                 classify_findings)

_DEFAULT_ALLOC = 128


@dataclass
class HeapAnalysisReport:
    """一次完整的堆分析报告."""
    binary_path: str = ""
    raw_findings: int = 0
    confirmed: int = 0
    likely: int = 0
    uncertain: int = 0
    filtered_fp: int = 0
    fp_reduction_pct: float = 0.0
    elapsed_sec: float = 0.0
    n_functions: int = 0
    n_user_functions: int = 0
    findings: List[dict] = field(default_factory=list)


# 主入口

def analyze_heap(binary_path: str, timeout_s: int = 60,
                 use_cross_fn: bool = True) -> HeapAnalysisReport:
    """完整管线: 反汇编→指令解析→函数分析→DP-TVRA过滤.

    use_cross_fn=True 启用跨函数调用链参数传播.
    """
    t0 = time.time()
    report = HeapAnalysisReport(binary_path=binary_path)
    asm_text = _disassemble(binary_path)
    if not asm_text:
        report.elapsed_sec = round(time.time() - t0, 3)
        return report

    functions = parse_instructions(asm_text)
    report.n_functions = len(functions)
    inferrer = HeapBoundInferrer()
    fp_filter = HeapFPFilterV2()
    all_findings: List[dict] = []
    seen: Dict[int, Tuple[str, int]] = {}

    mc_all = []
    m_all = []
    if use_cross_fn:
        cross_fn = CrossFnAnalyzer()
        for fn_name, insns in functions:
            if len(insns) >= 3:
                cross_fn.register(fn_name, insns, analyze_function(fn_name, insns))
        cross_fn.analyze_all()
        m_all, w_all, mc_all, _ = cross_fn.get_all_findings()
        register_mallocs(m_all, inferrer, seen)
        all_findings = collect_findings(w_all, mc_all, seen, inferrer, mallocs=m_all)
    else:
        for fn_name, insns in functions:
            if len(insns) < 3:
                continue
            fa = analyze_function(fn_name, insns)
            register_mallocs(fa.mallocs, inferrer, seen, fn_name=fa.name)
            all_findings.extend(collect_findings(fa.writes, fa.memcpys, seen,
                            inferrer, fn_name=fa.name, mallocs=fa.mallocs))
            mc_all.extend(fa.memcpys)

    # 内联拷贝检测: 字节循环 + sprintf
    gm_list = [{'addr': a, 'size_val': s} for a, (_, s) in seen.items()]
    detector = InlineCopyDetector()
    for fn_name, insns in functions:
        if len(insns) < 3:
            continue
        inline = detector.scan(insns, gm_list, fn_name)
        if inline:
            all_findings.extend(collect_findings([], inline, seen, inferrer,
                                         fn_name=fn_name, mallocs=gm_list))

    # 循环累积写入检测
    for fn_name, insns in functions:
        if len(insns) < 6:
            continue
        loop_extra = detect_loop_accumulated(
            insns, mc_all, m_all if use_cross_fn else gm_list)
        for le in loop_extra:
            inferrer.register_access(HeapAccess(
                insn_addr=le['insn_addr'],
                base_ptr=f"ptr@{le.get('malloc_addr', 0):x}"
                if le.get('malloc_addr') else 'ptr@0',
                offset_expr=str(le.get('offset', 0)),
                access_size=le.get('per_iter_size', le.get('access_size', 4)),
                function_name=le.get('function', fn_name), is_write=True))
            all_findings.append(le)

    violations = inferrer.check_all()
    report.raw_findings = len(all_findings)
    classify_findings(all_findings, violations, fp_filter, report,
                        functions=functions)
    total = max(1, report.raw_findings)
    report.fp_reduction_pct = round(report.filtered_fp / total * 100, 1)
    report.elapsed_sec = round(time.time() - t0, 3)
    report.n_user_functions = len(functions)
    return report


# 反汇编

def _disassemble(elf_path: str) -> str:
    """反汇编二进制 (objdump 优先, 回退 llvm-objdump)."""
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
