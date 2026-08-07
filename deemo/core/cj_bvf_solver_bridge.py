"""
DD-BVF求解器桥接 — CJ INCONCLUSIVE时触发BVF反向值流证明.

从cj_solver.py拆分, 提供BVF证明入口和循环偏移证明.
"""
from __future__ import annotations
from typing import Optional

from core.cj_constraint_types import SolverVerdict, SolverResult


def try_bvf_proof(
    candidate,
    ir_lines: list[str],
    platform: str,
) -> Optional[SolverResult]:
    """DD-BVF反向值流证明 — CJ INCONCLUSIVE时的精确化判定.

    从告警点反向追踪alloc_size和write_size的符号表达式,
    通过相关性分析判定安全/溢出. 不影响召回率:
    BVF无法判定时返回None, 调用方保留原始INCONCLUSIVE结果.
    """
    from core.cj_bvf_tracer import BackwardValueFlow, SymbolicExpr

    bvf = BackwardValueFlow()
    alloc = candidate.alloc_site
    store = candidate.overflow_store

    alloc_expr = bvf.trace_alloc_size(
        ir_lines, alloc.alloc_func,
        alloc.size_expr if alloc.size_is_dynamic else str(alloc.size_arg),
        alloc.pc)
    if alloc.size_arg > 0 and not alloc.size_is_dynamic:
        alloc_expr = SymbolicExpr(
            const=float(alloc.size_arg),
            origin=f"const_alloc:{alloc.size_arg}")

    if store.mnemonic in ('strcpy', 'strcat'):
        return None

    if store.store_size > 0:
        write_expr = SymbolicExpr(
            const=float(store.store_size),
            origin=f"store_size:{store.store_size}")
    elif store.mnemonic in ('memcpy', 'memmove', 'strncpy', 'memset',
                             'strncat'):
        write_expr = bvf.trace_write_size(
            ir_lines, store.pc, store.mnemonic, store.store_size)
    else:
        write_expr = SymbolicExpr(
            const=float(store.store_size if store.store_size > 0 else 4))

    if not store.offset_is_dynamic and store.offset >= 0:
        offset_expr = SymbolicExpr(const=float(store.offset))
    elif store.offset_is_dynamic:
        offset_expr = bvf.trace_var(ir_lines, "offset", store.pc)
    else:
        offset_expr = SymbolicExpr(const=0.0)

    result = bvf.correlate(alloc_expr, write_expr, offset_expr)

    # BVF无法关联时, 尝试调用点常量注入: 从调用处提取参数常量值
    if not result.proven_safe and not result.proven_overflow:
        call_site_result = _try_call_site_constant_injection(
            ir_lines, alloc_expr, write_expr, offset_expr,
            candidate, bvf)
        if call_site_result is not None:
            return call_site_result

    if result.proven_safe:
        sr = SolverResult()
        sr.verdict = SolverVerdict.PROVEN_SAFE
        sr.reason = f"DD-BVF: {result.reason}"
        sr.confidence_delta = -0.40
        sr.proof_chain = [
            f"BVF Step 1: alloc_expr = {alloc_expr}",
            f"BVF Step 2: write_expr = {write_expr}",
            f"BVF Step 3: offset_expr = {offset_expr}",
            f"BVF Step 4: {result.reason}",
            f"BVF Certificate:\n{result.certificate}",
        ]
        return sr

    if result.proven_overflow:
        sr = SolverResult()
        sr.verdict = SolverVerdict.PROVEN_OVERFLOW
        sr.reason = f"DD-BVF: {result.reason}"
        sr.confidence_delta = +0.15
        sr.proof_chain = [
            f"BVF Step 1: alloc_expr = {alloc_expr}",
            f"BVF Step 2: write_expr = {write_expr}",
            f"BVF Step 3: offset_expr = {offset_expr}",
            f"BVF Step 4: {result.reason}",
        ]
        return sr

    if store.offset_is_dynamic and store.store_size > 0:
        loop_result = _try_loop_offset_proof(
            candidate, ir_lines, alloc_expr, store.store_size)
        if loop_result is not None:
            return loop_result

    lsp_result = _try_lsp_layered_proof(
        candidate, ir_lines, platform,
        alloc_expr, write_expr, offset_expr, result)
    if lsp_result is not None:
        return lsp_result

    return None


def _try_lsp_layered_proof(
    candidate,
    ir_lines: list[str],
    platform: str,
    alloc_expr: SymbolicExpr,
    write_expr: SymbolicExpr,
    offset_expr: Optional[SymbolicExpr],
    bvf_result: CorrelationResult,
) -> Optional[SolverResult]:
    """LSP分层安全证明 — BVF-INCONCLUSIVE时的精确化判定.

    Layer 2(不变式推导)→Layer 3(分配器对齐)级联,
    任一层判定成功即返回SolverResult.
    """
    from core.lsp_orchestrator import try_lsp_proof
    return try_lsp_proof(
        candidate, ir_lines, platform,
        alloc_expr, write_expr, offset_expr, bvf_result)


def _try_loop_offset_proof(
    candidate,
    ir_lines: list[str],
    alloc_expr,
    store_size: int,
) -> Optional[SolverResult]:
    """循环偏移场景的溢出证明.

    从循环结构提取上界, 计算max_write_end,
    与alloc_size比较判定安全/溢出.
    """
    from core.cj_bvf_loop import compute_loop_offset

    alloc_size = int(alloc_expr.const) if alloc_expr.is_constant() else 0
    if alloc_size <= 0:
        return None

    loop_result = compute_loop_offset(
        ir_lines, candidate.overflow_store.pc,
        store_size, alloc_size)
    if loop_result is None:
        return None

    max_write_end, reason = loop_result
    sr = SolverResult()
    if max_write_end > alloc_size:
        sr.verdict = SolverVerdict.PROVEN_OVERFLOW
        sr.reason = f"DD-BVF-loop: {reason}"
        sr.confidence_delta = +0.15
    else:
        sr.verdict = SolverVerdict.PROVEN_SAFE
        sr.reason = f"DD-BVF-loop: {reason}"
        sr.confidence_delta = -0.35
    sr.proof_chain = [f"BVF Loop: {reason}"]
    return sr


def _try_call_site_constant_injection(
        ir_lines: list[str],
        alloc_expr: 'SymbolicExpr',
        write_expr: 'SymbolicExpr',
        offset_expr: Optional['SymbolicExpr'],
        candidate,
        bvf,
) -> Optional[SolverResult]:
    """调用点常量注入 — 当BVF无法关联不同参数时, 从调用处提取常量实参.

    模式: 在IR中搜索被分析函数的调用点,
    将常量实参代入alloc/write表达式后重新correlate.
    仅当代入后能明确判定时返回结果, 否则返回None.
    """
    import re
    from core.cj_bvf_types import SymbolicExpr

    if not alloc_expr.has_vars() or not write_expr.has_vars():
        return None
    shared = alloc_expr.vars() & write_expr.vars()
    if shared:
        return None

    all_vars = alloc_expr.vars() | write_expr.vars()

    # 提取函数参数名和位置
    param_pat = re.compile(
        r'\b(?:int|char|size_t|unsigned|long|short|void|uint\d+_t|int\d+_t|u_int\d+_t)\s+\*?\s*(\w+)')
    params = []
    for line in ir_lines:
        m = param_pat.search(line)
        if m:
            params.append(m.group(1))

    if not params:
        return None

    # 搜索调用点: 含常量参数的函数调用
    call_pat = re.compile(r'(\w+)\s*\(([^)]+)\)')
    for line in ir_lines:
        cm = call_pat.search(line)
        if not cm:
            continue
        func_name = cm.group(1)
        if func_name in ('malloc', 'calloc', 'realloc', 'memcpy',
                         'memset', 'free', 'printf', 'strlen'):
            continue
        args_str = cm.group(2)
        arg_parts = [a.strip().rstrip(',') for a in args_str.split(',')]
        const_map = {}
        for idx, arg in enumerate(arg_parts):
            arg = arg.strip()
            if re.match(r'^(?:0x[0-9a-fA-F]+|\d+)$', arg):
                try:
                    val = int(arg, 0)
                    if idx < len(params):
                        const_map[params[idx]] = val
                except ValueError:
                    pass

        if all_vars <= set(const_map.keys()):
            new_alloc = _substitute_consts(alloc_expr, const_map)
            new_write = _substitute_consts(write_expr, const_map)
            if new_alloc.is_constant() and new_write.is_constant():
                result = bvf.correlate(new_alloc, new_write, offset_expr)
                if result.proven_safe or result.proven_overflow:
                    sr = SolverResult()
                    if result.proven_overflow:
                        sr.verdict = SolverVerdict.PROVEN_OVERFLOW
                        sr.reason = f"DD-BVF(call-site): {result.reason}"
                        sr.confidence_delta = +0.10
                    else:
                        sr.verdict = SolverVerdict.PROVEN_SAFE
                        sr.reason = f"DD-BVF(call-site): {result.reason}"
                        sr.confidence_delta = -0.30
                    sr.proof_chain = [
                        f"BVF call-site injection: {const_map}",
                        f"  alloc: {alloc_expr} -> {new_alloc}",
                        f"  write: {write_expr} -> {new_write}",
                        f"  result: {result.reason}",
                    ]
                    return sr
    return None


def _substitute_consts(
        expr: 'SymbolicExpr',
        const_map: dict,
) -> 'SymbolicExpr':
    """将SymbolicExpr中的变量替换为常量值."""
    from core.cj_bvf_types import SymbolicExpr
    new_const = expr.const
    new_coefs = dict(expr.coefs)
    for var, val in const_map.items():
        if var in new_coefs:
            new_const += new_coefs[var] * float(val)
            del new_coefs[var]
    return SymbolicExpr(
        const=new_const, coefs=new_coefs,
        tainted=expr.is_tainted(),
        origin=f"{expr.origin}(injected)")



