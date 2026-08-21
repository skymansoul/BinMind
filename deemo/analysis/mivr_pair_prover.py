"""
MIVR 分配-写入对证明器 — 组合约束传播 + 仿射关系 + 分配器语义的三层证明.

证明层次 (从强到弱):
  L1 (硬证明): 守卫约束直接证明偏移 < 分配大小 (confidence ≥ 0.85)
  L2 (仿射证明):alloc-write共享变量 + 仿射关系diff≤0 → SAFE (≥0.75)
  L3 (语义证明): glibc chunk slack吸收写入尾部 (≥0.60)

保守原则: 仅当L1/L2/L3任一层次给出确定答案时才判定.
UNCERTAIN永远fall through到下一层管线, 不冒进过滤.

L1/L2/L3 证明方法 → 已提取至 analysis.mivr_proof_layers.
"""


import re
from typing import Dict, List, Tuple

from analysis.mivr_constraint_graph import (
    VarConstraint, GuardSite, MIVRConstraintGraph,
)
from analysis.mivr_path_propagator import (
    WriteSafetyVerdict, MIVRPathPropagator,
)
from analysis.mivr_proof_layers import PairProof, prove_single


class MIVRPairProver:
    """分配-写入对证明器 — MIVR 的核心证明引擎.

    作为 GAPSBV 管线的新增维度 (维度6): 结合守卫约束的仿射关系,
    传递性约束传播和分配器语义做三层证明.
    """

    _MALLOC_RE = re.compile(
        r'(?:(\w+)\s*=\s*(?:\([^)]*\)\s*)?)?'
        r'(malloc|calloc|realloc|kmalloc|kzalloc|vmalloc|kcalloc)\s*'
        r'\(\s*([^)]+)\s*\)',
        re.IGNORECASE)
    _MEMCPY_RE = re.compile(
        r'(memcpy|memmove)\s*\(\s*'
        r'(\w[\w]*(?:\s*->\s*\w+)?)'     # target (allow ->field)
        r'\s*(?:\+\s*(\d+|\w[\w]*))?\s*,'  # optional +offset
        r'\s*[^,]+,\s*'                     # src (ignored)
        r'([^)]+)'                          # size expression
        r'\s*\)', re.IGNORECASE)
    _STRCPY_RE = re.compile(
        r'(strcpy|strcat|sprintf|gets)\s*\(\s*'
        r'(\w[\w]*(?:\s*->\s*\w+)?)', re.IGNORECASE)
    _STRNCPY_RE = re.compile(
        r'(strncpy|snprintf)\s*\(\s*(\w[\w]*)\s*,\s*[^,]+,\s*(\d+)\s*\)',
        re.IGNORECASE)
    _ARRAY_STORE_RE = re.compile(r'(\w+)\s*\[\s*(\w+|\d+)\s*\]\s*=')
    _CALLOC_ARGS_RE = re.compile(
        r'calloc\s*\(\s*(\d+)\s*,\s*(\d+|sizeof\s*\([^)]+\))\s*\)')

    _SIZEOF_MAP = {
        'int': 4, 'long': 8, 'long long': 8, 'short': 2, 'char': 1,
        'float': 4, 'double': 8, 'void*': 8, 'char*': 8, 'int*': 4,
        'size_t': 8, 'ssize_t': 8, 'uint32_t': 4, 'uint64_t': 8,
    }

    def __init__(self):
        self._propagator = MIVRPathPropagator()

    def prove_from_source(self, pseudocode: str) -> List[PairProof]:
        """从源码一次性发现并证明所有 alloc-write 对.

        按缓冲区聚合: 若同一缓冲区的任一写入无法证明安全 (UNCERTAIN
        或 OVERFLOW), 则该缓冲区的所有 SAFE 证明降级为 UNCERTAIN.
        防止无界写入 (strcpy/gets) 因同缓冲区另一写入被证明安全而漏报.
        """
        self._graph = self._propagator.build_and_propagate(pseudocode)
        allocs = self._find_allocs(pseudocode)
        writes = self._find_writes(pseudocode)
        lines = pseudocode.splitlines()

        raw_proofs = []
        for ai in allocs:
            for wi in writes:
                # ai: (line, var, func, expr, size, col)
                # wi: (line, func, target, offset, write_size, size_expr, col)
                if wi[0] < ai[0]:
                    continue
                if wi[0] == ai[0]:
                    a_col = ai[5] if len(ai) > 5 else 0
                    w_col = wi[6] if len(wi) > 6 else 0
                    if w_col <= a_col:
                        continue
                # 委托给 mivr_proof_layers.prove_single
                proof = prove_single(ai, wi, self._propagator, self._graph)
                raw_proofs.append(proof)

        # 缓冲区聚合: 按 write_var 分组
        buf_proofs: Dict[str, List[PairProof]] = {}
        for p in raw_proofs:
            buf_proofs.setdefault(p.write_var, []).append(p)

        # 若某缓冲区有未证明安全的写入, 则该缓冲区所有 SAFE 降级
        consolidated = []
        for buf, pfs in buf_proofs.items():
            has_unsafe = any(pf.verdict != "SAFE" for pf in pfs)
            if has_unsafe:
                for pf in pfs:
                    if pf.verdict == "SAFE":
                        pf.verdict = "UNCERTAIN"
                        pf.confidence = 0.0
                        pf.proof_level = ""
                        pf.proof_detail = (
                            f"demoted: other write to '{buf}' is "
                            f"{'UNCERTAIN' if any(p.verdict=='UNCERTAIN' for p in pfs) else 'OVERFLOW'}")
            consolidated.extend(pfs)

        return consolidated

    def _find_allocs(self, src: str) -> List[Tuple[int, str, str, str, int, int]]:
        """提取分配点: (line, var, func, expr, size_bytes, col)."""
        allocs = []
        for i, line in enumerate(src.splitlines()):
            m = self._MALLOC_RE.search(line)
            if not m:
                continue
            var = m.group(1) or "anon"
            func = m.group(2)
            expr = m.group(3).strip()
            size = self._resolve_size(expr, func, line)
            allocs.append((i, var, func, expr, size, m.start()))
        return allocs

    def _find_writes(self, src: str) -> List[Tuple[int, str, str, int, int, str, int]]:
        """提取写入点: (line, func, target, offset, write_size, size_expr, col)."""
        writes = []
        for i, line in enumerate(src.splitlines()):
            # memcpy/memmove
            mm = self._MEMCPY_RE.search(line)
            if mm:
                target = mm.group(2)
                off_str = mm.group(3)
                off = int(off_str) if off_str and off_str.isdigit() else (
                    -1 if not off_str else -2)  # -2 = variable offset
                sz_str = mm.group(4).strip()
                sz = int(sz_str) if sz_str.isdigit() else -1
                if sz < 0 and sz_str:
                    sz = -2  # -2 = 含变量的表达式
                writes.append((i, mm.group(1), target, off, sz, sz_str, mm.start()))
                continue
            # strcpy/gets (无界)
            sm = self._STRCPY_RE.search(line)
            if sm:
                writes.append((i, sm.group(1), sm.group(2), -1, -1, "", sm.start()))
                continue
            # strncpy/snprintf
            snm = self._STRNCPY_RE.search(line)
            if snm:
                sz = int(snm.group(3)) if snm.group(3).isdigit() else -1
                writes.append((i, snm.group(1), snm.group(2), -1, sz, snm.group(3), snm.start()))
                continue
            # buf[idx] = x
            am = self._ARRAY_STORE_RE.search(line)
            if am:
                off_str = am.group(2)
                off = int(off_str) if off_str.isdigit() else -2
                writes.append((i, 'store', am.group(1), off, 1, off_str, am.start()))
        return writes

    def _resolve_size(self, expr: str, func: str, line: str) -> int:
        """将分配表达式解析为字节数."""
        if func == 'calloc':
            cm = self._CALLOC_ARGS_RE.search(line)
            if cm:
                nmemb = int(cm.group(1))
                sz_str = cm.group(2)
                if sz_str.startswith('sizeof'):
                    tm = re.search(r'sizeof\s*\(\s*([\w\s*]+)\s*\)', sz_str)
                    if tm:
                        elem = self._SIZEOF_MAP.get(tm.group(1).strip(), 0)
                        if elem > 0:
                            return nmemb * elem
                elif sz_str.isdigit():
                    return nmemb * int(sz_str)
        try:
            return int(expr.strip())
        except ValueError:
            pass
        sm = re.match(r'sizeof\s*\(\s*([\w\s*]+)\s*\)', expr.strip())
        if sm:
            return self._SIZEOF_MAP.get(sm.group(1).strip(), -1)
        return -1


from analysis.mivr_proof_layers import (  # noqa: F401
    _shared_vars, _is_complex_expr,
    _extract_var_coef, _extract_const_term,
    _eval_expr_bound, _effective_boundary,
)


__all__ = ['PairProof', 'MIVRPairProver']
