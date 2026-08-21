# 堆溢出分析编排器辅助函数 — 从orchestrator.py拆分.
# 包含发现收集、分类判定、memcpy处理等内部辅助.

import re
from typing import Dict, List, Tuple

from .heap_bound_infer import HeapBoundInferrer, HeapAccess, IntervalDomain
from heap_fp_filter_v2 import HeapFPFilterV2
from filter_types import FilterDecision
from taint_propagation import TaintSourceType
from allocator_model import Ptmalloc2Model
from .insn_parser import extract_malloc_addr
from offset_proof_filter import OffsetProofFilter, ProofResult

_DEFAULT_ALLOC = 128


def register_mallocs(mallocs: List[dict], inferrer: HeapBoundInferrer,
                     seen: Dict[int, Tuple[str, int]],
                     fn_name: str = 'cross_fn') -> None:
    """注册malloc分配点到Inferrer — 单函数或跨函数路径共用."""
    for m in mallocs:
        size = m.get('size_val')
        addr = m.get('addr', 0)
        if isinstance(size, int) and 0 < size <= 0x1000000:
            inferrer.register_malloc(addr, f"ptr@{addr:x}", size)
            seen[addr] = (fn_name, size)
        elif isinstance(size, int):
            inferrer.register_malloc(addr, f"ptr@{addr:x}", _DEFAULT_ALLOC)
            seen[addr] = (fn_name, _DEFAULT_ALLOC)
        elif size is None:
            inferrer.register_malloc(addr, f"ptr@{addr:x}", _DEFAULT_ALLOC)
            seen[addr] = (fn_name, _DEFAULT_ALLOC)


def collect_findings(writes: List[dict], memcpys: List[dict],
             seen: Dict[int, Tuple[str, int]],
             inferrer: HeapBoundInferrer,
             fn_name: str = '',
             mallocs: List[dict] = None) -> List[dict]:
    """从write/memcpy列表收集发现 — 单函数或跨函数路径共用."""
    mallocs_by_fn: Dict[str, List[int]] = {}
    if mallocs:
        for m in mallocs:
            m_fn = m.get('function', '') or fn_name
            if m_fn not in mallocs_by_fn:
                mallocs_by_fn[m_fn] = []
            mallocs_by_fn[m_fn].append(m.get('addr', 0))

    findings: List[dict] = []
    for w in writes:
        m_addr = extract_malloc_addr(str(w.get('base_val', '')))
        if m_addr and m_addr in seen:
            _, alloc_sz = seen[m_addr]
            inferrer.register_access(HeapAccess(
                insn_addr=w['addr'], base_ptr=f"ptr@{m_addr:x}",
                offset_expr=str(w.get('offset', 0)),
                access_size=w.get('access_size', 4),
                function_name=w.get('function', fn_name), is_write=True))
            findings.append({
                'type': 'direct_write',
                'function': w.get('function', fn_name),
                'insn_addr': w['addr'], 'alloc_size': alloc_sz,
                'offset': w.get('offset', 0),
                'access_size': w.get('access_size', 4)})
    for mc in memcpys:
        _collect_one_memcpy(mc, seen, inferrer, findings, fn_name,
                            mallocs_by_fn)
    return findings


def _extract_malloc_offset(dst_val: str) -> int:
    """从 'malloc@0x140001772+96+256' 提取累积偏移量."""
    total = 0
    for m in re.finditer(r'\+(\d+)', str(dst_val)):
        try:
            total += int(m.group(1))
        except ValueError:
            pass
    return total


def _collect_one_memcpy(mc: dict, seen: Dict[int, Tuple[str, int]],
                         inferrer: HeapBoundInferrer,
                         findings: List[dict], fn_name: str = '',
                         mallocs_by_fn: Dict[str, List[int]] = None) -> None:
    """单个memcpy记录→发现. mallocs_by_fn作realloc回退."""
    dst_val = str(mc.get('dst_val', ''))
    m_addr = extract_malloc_addr(dst_val)
    if not m_addr or m_addr not in seen:
        if mallocs_by_fn and fn_name in mallocs_by_fn:
            for ra in mallocs_by_fn[fn_name]:
                if ra in seen:
                    m_addr = ra
                    break
    if not m_addr or m_addr not in seen:
        return
    _, alloc_sz = seen[m_addr]
    effective = alloc_sz if alloc_sz > 0 else _DEFAULT_ALLOC
    mc_offset = _extract_malloc_offset(dst_val)
    size_val = mc.get('size_val')
    size_bounded = isinstance(size_val, int) and size_val > 0
    access_size = size_val if size_bounded else effective + 1024
    inferrer.register_access(HeapAccess(
        insn_addr=mc['addr'], base_ptr=f"ptr@{m_addr:x}",
        offset_expr=str(mc_offset), access_size=access_size,
        function_name=mc.get('function', fn_name), is_write=True))
    findings.append({
        'type': 'memcpy', 'function': mc.get('function', fn_name),
        'insn_addr': mc['addr'], 'alloc_size': effective,
        'real_alloc_size': alloc_sz, 'offset': mc_offset,
        'access_size': access_size, 'size_bounded': size_bounded,
        'size_unknown': not size_bounded})


def classify_findings(findings: List[dict], violations: list,
                       fp_filter: HeapFPFilterV2,
                       report, functions: list = None) -> None:
    """对发现做分类判定 (安全/确认/可能/不确定).

    管线: CAORN proof → BOUND_CHECK → DP-TVRA scoring
    """
    proof_filter = OffsetProofFilter()
    alloc_model = Ptmalloc2Model()
    insns_by_fn = {}
    if functions:
        for fn_name, insns in functions:
            insns_by_fn[fn_name] = insns

    for f in findings:
        func_name = f.get('function', '')
        insns = insns_by_fn.get(func_name, [])
        if insns:
            m_addr = extract_malloc_addr(
                str(f.get('base_val', f'ptr@{f.get("insn_addr", 0):x}')))
            alloc_sz = f.get('alloc_size', 128)

            constraints = OffsetProofFilter.extract_branch_constraints(
                insns, malloc_addr=m_addr or 0,
                access_addr=f.get('insn_addr', 0))

            proof_result = proof_filter.prove(
                malloc_addr=m_addr or 0,
                alloc_size=alloc_sz,
                access_addr=f.get('insn_addr', 0),
                access_size=f.get('access_size', 4),
                insns=insns,
                branch_constraints=constraints,
                offset_value=f.get('offset', 0),
                func_name=func_name)

            if proof_result.proof == ProofResult.PROVED_SAFE:
                report.filtered_fp += 1
                report.findings.append({
                    **f, 'decision': 'safe', 'phase': 'CAORN_PROOF',
                    'reasoning': proof_result.reason,
                    'fp_probability': 0.98})
                continue
            elif proof_result.proof == ProofResult.PROVED_OVERFLOW:
                report.confirmed += 1
                report.findings.append({
                    **f, 'decision': 'vuln', 'phase': 'CAORN_PROOF',
                    'reasoning': proof_result.reason,
                    'fp_probability': 0.02})
                continue

        is_violation = any(
            v[0].insn_addr == f['insn_addr'] for v in violations)
        if not is_violation:
            report.filtered_fp += 1
            report.findings.append({
                **f, 'decision': 'safe', 'phase': 'BOUND_CHECK',
                'reasoning': 'offset+access_size within allocation bounds',
                'fp_probability': 0.95})
            continue

        alloc_sz = f.get('alloc_size', 128)
        real_alloc = f.get('real_alloc_size', alloc_sz)
        access_sz = f.get('access_size', 4)
        size_unknown = f.get('size_unknown', False)

        if not size_unknown:
            usable = alloc_model.model_alloc(alloc_sz).usable_size
            effective_limit = max(alloc_sz, usable)
            if f.get('offset', 0) + access_sz > effective_limit:
                report.confirmed += 1
                report.findings.append({
                    **f, 'decision': 'vuln', 'phase': 'BOUND_CHECK',
                    'reasoning': (f'Overflow: offset {f.get("offset", 0)} + '
                                f'size {access_sz} > usable {effective_limit} '
                                f'(alloc {alloc_sz})'),
                    'fp_probability': 0.05})
                continue

        if size_unknown:
            report.likely += 1
            report.findings.append({
                **f, 'decision': 'likely', 'phase': 'BOUND_CHECK',
                'reasoning': (f'Unbounded copy into buffer of '
                            f'{real_alloc if real_alloc > 0 else alloc_sz}B'),
                'fp_probability': 0.20})
            continue

        insn_addr = f.get('insn_addr', 0)
        result = fp_filter.evaluate(
            insn_addr=(insn_addr if isinstance(insn_addr, int) else 0),
            offset_reg=f"ptr@{f.get('function', '')}",
            offset_value=f.get('offset', 0), alloc_size=alloc_sz,
            access_size=access_sz, func_name=f.get('function', ''))
        _apply_filter_result(result, f, report)


def _apply_filter_result(result, finding: dict, report) -> None:
    """将 DP-TVRA 过滤结果写入报告."""
    if result.decision == FilterDecision.SAFE_FILTERED:
        report.filtered_fp += 1
    elif result.decision == FilterDecision.CONFIRMED_VULN:
        report.confirmed += 1
    elif result.decision == FilterDecision.LIKELY_VULN:
        report.likely += 1
    else:
        report.uncertain += 1
    report.findings.append({
        **finding, 'decision': result.decision.value,
        'phase': result.decisive_phase.name,
        'reasoning': result.reasoning,
        'fp_probability': result.fp_probability})
