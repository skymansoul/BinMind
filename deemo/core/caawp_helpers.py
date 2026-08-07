"""
CAAWP辅助函数模块 — 从caawp_prover.py拆分.

包含快照匹配、直接表达式证明、证书构建等功能.
"""

import re
from typing import Dict, List, Optional, Tuple

from core.caawp_types import AffineSnapshot, ProofResult
from core.caawp_parser import (
    parse_size_expr as _parse_size_expr,
    expand_vars as _expand_vars,
    multiply_affine as _multiply_affine,
    parse_write_args as _parse_write_args,
    split_args as _split_args,
)


_ALLOC_RE = re.compile(
    r'(\w+)\s*=\s*(malloc|calloc|realloc)\s*\(([^)]+)\)', re.I)
_WRITE_RE = re.compile(
    r'(memcpy|memmove|memset|strncpy|strcpy|read|recv)\s*\(([^)]+)\)', re.I)
_ASSIGN_RE = re.compile(
    r'(\w+)\s*=\s*([^;]+?)(?:;|$)', re.MULTILINE)


def find_best_snapshot(
    snapshots: Dict[str, List[AffineSnapshot]],
    alloc_var: str,
    write_var: str,
    alloc_size_var: str,
    write_size_var: str,
) -> Optional[AffineSnapshot]:
    """找到包含目标变量的最佳仿射快照."""
    best = None
    best_score = 0

    for func_name, snap_list in snapshots.items():
        for snap in snap_list:
            score = 0
            if alloc_var in snap.alloc_sites:
                score += 2
            if alloc_size_var in snap.var_relations:
                score += 2
            if write_size_var in snap.var_relations:
                score += 2
            for ws_info in snap.write_sites.values():
                if ws_info.get('dst_var') == write_var:
                    score += 2
                    break
            if score > best_score:
                best_score = score
                best = snap

    return best if best_score > 0 else None


def direct_proof(
    alloc_expr_str: str,
    write_expr_str: str,
    offset: int,
    chunk_slack: int,
    result: ProofResult,
) -> ProofResult:
    """无快照时的直接表达式证明."""
    alloc_coefs, alloc_const = _parse_size_expr(alloc_expr_str)
    write_coefs, write_const = _parse_size_expr(write_expr_str)

    write_end = write_const + offset
    alloc_bound = alloc_const + chunk_slack

    shared = set(alloc_coefs.keys()) & set(write_coefs.keys())

    if not shared:
        # copy_size=-1哨兵值不能作为常量-1参与比较
        if write_const < -0.5:
            result.reason = "direct: write_size sentinel -1, cannot prove"
            return result
        if write_end <= alloc_bound + 1e-9 and not alloc_coefs and not write_coefs:
            result.proven_safe = True
            result.reason = (
                f"direct: write_end({write_end}) <= "
                f"alloc({alloc_bound})")
            return result
        if write_end > alloc_const + 1e-9 and not alloc_coefs:
            result.proven_overflow = True
            result.reason = (
                f"direct: write_end({write_end}) > "
                f"alloc({alloc_const})")
            return result

    for v in shared:
        ac = alloc_coefs.get(v, 0)
        wc = write_coefs.get(v, 0)
        if wc > ac + 1e-9:
            result.proven_overflow = True
            result.reason = (
                f"direct: write_coef[{v}]={wc} > "
                f"alloc_coef[{v}]={ac}")
            return result

    all_equal = all(
        alloc_coefs.get(v, 0) == write_coefs.get(v, 0)
        for v in shared)
    if all_equal and shared:
        if write_end > alloc_const + 1e-9:
            result.proven_overflow = True
            result.reason = (
                f"direct: equal coefs, "
                f"write_end({write_end}) > "
                f"alloc_const({alloc_const})")
            return result
        result.proven_safe = True
        result.reason = (
            f"direct: equal coefs, "
            f"write_end({write_end}) <= "
            f"alloc_const({alloc_const})")
        return result

    result.reason = "direct proof inconclusive"
    return result


def build_certificate(
    alloc_var: str,
    write_var: str,
    alloc_expr: Tuple[Dict[str, float], float],
    write_expr: Tuple[Dict[str, float], float],
    offset: int,
    chunk_slack: int,
    verdict: str,
    ctx_key: str,
) -> str:
    """构建形式化安全证书."""
    alloc_coefs, alloc_const = alloc_expr
    write_coefs, write_const = write_expr

    alloc_str = expr_to_str(alloc_coefs, alloc_const)
    write_str = expr_to_str(write_coefs, write_const)

    return (
        f"CAAWP Certificate [{verdict}]\n"
        f"  Context     = {ctx_key}\n"
        f"  alloc({alloc_var})  = {alloc_str}\n"
        f"  write({write_var})  = {write_str}\n"
        f"  offset      = {offset}\n"
        f"  chunk_slack = {chunk_slack}\n"
        f"  write_end   = {write_str} + {offset}\n"
        f"  proof       = context-sensitive affine relation")


def expr_to_str(coefs: Dict[str, float], const: float) -> str:
    """仿射表达式转字符串."""
    terms = [f"{c:g}*{v}" for v, c in coefs.items() if c != 0]
    s = " + ".join(terms)
    if const != 0 or not terms:
        s += f" + {const:g}" if terms else f"{const:g}"
    return s.strip(" +")


def process_line(
    line: str,
    snapshot: AffineSnapshot,
    ctx_key: str,
) -> None:
    """处理单行代码, 更新仿射状态."""
    if line.startswith('#') or line.startswith('//') or line.startswith('/*'):
        return

    m = _ALLOC_RE.search(line)
    if m:
        var = m.group(1)
        func = m.group(2).lower()
        size_str = m.group(3)
        if func == 'calloc':
            parts = _split_args(size_str)
            if len(parts) == 2:
                expr1 = _parse_size_expr(parts[0].strip())
                expr2 = _parse_size_expr(parts[1].strip())
                coefs, const = _multiply_affine(expr1, expr2)
            else:
                coefs, const = _parse_size_expr(size_str)
        else:
            coefs, const = _parse_size_expr(size_str)
        snapshot.var_relations[var] = ({}, 0.0)
        size_var = f"{var}_size"
        snapshot.var_relations[size_var] = (coefs, const)
        snapshot.alloc_sites[var] = {
            'func': func,
            'size_coefs': coefs,
            'size_const': const,
            'ctx': ctx_key,
            'line': line,
        }
        return

    m = _WRITE_RE.search(line)
    if m:
        mnemonic = m.group(1).lower()
        args_str = m.group(2)
        dst_var, size_expr = _parse_write_args(args_str, mnemonic)
        if not dst_var:
            return
        if mnemonic in ('strcpy', 'gets', 'sprintf'):
            snapshot.tainted_vars.add(f"{dst_var}_writesize")
            snapshot.write_sites[f"{dst_var}_{id(line)}"] = {
                'func': mnemonic,
                'dst_var': dst_var,
                'size_coefs': {},
                'size_const': -1,
                'tainted': True,
                'ctx': ctx_key,
                'line': line,
            }
            return
        if size_expr:
            coefs, const = _parse_size_expr(size_expr)
            expanded_coefs, expanded_const = _expand_vars(
                coefs, const, snapshot.var_relations)
            wvar = f"{dst_var}_writesize"
            snapshot.var_relations[wvar] = (expanded_coefs, expanded_const)
            snapshot.write_sites[f"{dst_var}_{id(line)}"] = {
                'func': mnemonic,
                'dst_var': dst_var,
                'size_coefs': expanded_coefs,
                'size_const': expanded_const,
                'tainted': False,
                'ctx': ctx_key,
                'line': line,
            }
        return

    m = _ASSIGN_RE.match(line)
    if m:
        var = m.group(1)
        rhs = m.group(2).strip()
        if rhs.startswith(('malloc', 'calloc', 'realloc', 'atoi', ' getopt', 'read')):
            return
        coefs, const = _parse_size_expr(rhs)
        if coefs or const != 0:
            snapshot.var_relations[var] = (coefs, const)


__all__ = ['find_best_snapshot', 'direct_proof',
           'build_certificate', 'expr_to_str',
           'process_line']
