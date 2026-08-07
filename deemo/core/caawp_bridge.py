"""
CAAWP-CJ桥接器 — 将上下文敏感仿射证明集成到CJ求解管线.

集成策略:
  在solve_candidate管线中, 当BVF和PCBVF都返回INCONCLUSIVE时,
  调用CAAWP做上下文敏感仿射证明:
    1. 从候选提取alloc_var和write_var
    2. 从IR/源码提取alloc_size_expr和write_size_expr
    3. 调用caawp_prover.prove_candidate
    4. 证明成功返回SolverResult, 否则返回None

保守性: CAAWP证明失败不影响后续步骤, 不引入假阴性.

与现有仿射桥接器(cj_affine_bridge)的区别:
  cj_affine_bridge: 无上下文区分, 全函数一个仿射状态
  caawp_bridge: 按call-site区分上下文, 跨函数时区分调用来源

  SAIL USENIX'23 — 上下文敏感稀疏值流
  Inferbo PLDI'23 — 区间域+缓冲区推理
"""

from __future__ import annotations
import re
from typing import Optional

from core.cj_constraint_types import SolverVerdict, SolverResult
from core.heap_overflow_detector import HeapOverflowCandidate
from core.caawp_prover import prove_candidate

def try_caawp_proof(
    candidate: HeapOverflowCandidate,
    ir_lines: list[str],
    platform: str = "x86_64",
) -> Optional[SolverResult]:
    """对候选尝试CAAWP上下文敏感仿射证明.

    返回SolverResult(证明成功时)或None(无法判定).
    """
    from core.caawp_prover import prove_candidate

    alloc = candidate.alloc_site
    store = candidate.overflow_store

    alloc_var = alloc.result_var or ""
    write_var = store.base_var or ""

    # 从IR中推断alloc_var: 用alloc.pc定位精确的malloc行
    if not alloc_var:
        alloc_pc = alloc.pc
        if 0 <= alloc_pc < len(ir_lines):
            line = ir_lines[alloc_pc]
            m = re.search(r'(\w+)\s*=\s*(?:malloc|calloc|realloc)\s*\(', line)
            if m:
                alloc_var = m.group(1)

    if not alloc_var and not write_var:
        return None

    alloc_size_expr = ""
    if alloc.size_is_dynamic and alloc.size_expr:
        alloc_size_expr = alloc.size_expr
    elif alloc.size_arg > 0:
        alloc_size_expr = str(alloc.size_arg)

    write_size_expr = ""
    copy_ops = ('memcpy', 'memmove', 'strncpy', 'memset', 'read', 'recv')
    if store.mnemonic in copy_ops:
        if store.store_size > 0:
            write_size_expr = str(store.store_size)
        elif store.store_size == -1:
            return None
    elif store.mnemonic in ('strcpy', 'gets', 'sprintf'):
        return None

    # 从memcpy调用行提取write_size_expr
    if not write_size_expr:
        store_pc = store.pc
        if 0 <= store_pc < len(ir_lines):
            line = ir_lines[store_pc]
            m = re.search(
                r'(?:memcpy|memmove|strncpy|memset)\s*\('
                r'[^,]+,\s*[^,]+,\s*(\w+)\)', line)
            if m:
                write_size_expr = m.group(1)
        # 如果store_pc行没找到, 搜索全局
        if not write_size_expr:
            for line in ir_lines:
                m = re.search(
                    r'(?:memcpy|memmove|strncpy|memset)\s*\('
                    r'[^,]+,\s*[^,]+,\s*(\w+)\)', line)
                if m:
                    write_size_expr = m.group(1)
                    break

    if not alloc_size_expr:
        # 从IR中用alloc.pc精确提取alloc行
        alloc_pc = alloc.pc
        if 0 <= alloc_pc < len(ir_lines):
            line = ir_lines[alloc_pc]
            m = re.search(r'(\w+)\s*=\s*malloc\s*\(([^)]+)\)', line)
            if m:
                alloc_var = alloc_var or m.group(1)
                alloc_size_expr = m.group(2).strip()
            else:
                m = re.search(r'(\w+)\s*=\s*calloc\s*\(([^)]+)\)', line)
                if m:
                    alloc_var = alloc_var or m.group(1)
                    parts = [p.strip() for p in m.group(2).split(',')]
                    if len(parts) == 2:
                        try:
                            v1 = int(parts[0])
                            v2 = int(parts[1])
                            alloc_size_expr = str(v1 * v2)
                        except ValueError:
                            alloc_size_expr = '*'.join(parts)
                    else:
                        alloc_size_expr = m.group(2).strip()

    if not alloc_size_expr:
        return None

    # write_size_expr可为空, prove_candidate会从快照提取
    if alloc_var == write_var or not write_var:
        write_var = alloc_var if alloc_var else write_var

    from analysis.allocator_chunk_model import compute_effective_boundary
    chunk_slack = 0
    if alloc.size_arg > 0:
        usable = compute_effective_boundary(alloc.size_arg, "malloc")
        chunk_slack = max(0, usable - alloc.size_arg)

    code_text = '\n'.join(ir_lines)

    proof = prove_candidate(
        code=code_text,
        alloc_var=alloc_var,
        write_var=write_var,
        alloc_size_expr=alloc_size_expr,
        write_size_expr=write_size_expr,
        offset=store.offset,
        chunk_slack=chunk_slack,
    )

    if proof.proven_safe:
        result = SolverResult()
        result.verdict = SolverVerdict.PROVEN_SAFE
        result.reason = proof.reason
        result.confidence_delta = -0.45
        result.proof_chain = proof.proof_chain
        return result

    if proof.proven_overflow:
        result = SolverResult()
        result.verdict = SolverVerdict.PROVEN_OVERFLOW
        result.reason = proof.reason
        result.confidence_delta = +0.25
        result.proof_chain = proof.proof_chain
        return result

    return None

__all__ = ['try_caawp_proof']
