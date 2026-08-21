"""
MIVR 三层证明 — L1守卫/L2仿射/L3语义 + PairProof dataclass.


L1 (硬证明): 守卫约束证明偏移 < 分配大小 (≥0.85)
L2 (仿射证明):alloc-write共享变量+仿射diff≤0 → SAFE (≥0.75)
L3 (语义证明): glibc chunk slack吸收写入尾部 (≥0.60)

仅当L1/L2/L3给出确定答案时才判定, UNCERTAIN fall through到下一层管线.
"""


import re
from dataclasses import dataclass
from typing import Dict, Set, Tuple


@dataclass
class PairProof:
    """alloc-write 对证明结果 (移至此处消除 mivr_pair_prover ↔ mivr_proof_layers 循环导入)."""
    alloc_var: str
    alloc_line: int
    alloc_expr: str
    alloc_size: int           # 解析后的字节数, -1=未知
    write_var: str
    write_line: int
    write_expr: str
    write_offset: int         # 偏移常量, -1=未知
    write_size: int           # 写入字节数, -1=无界
    proof_level: str = ""     # L1/L2/L3/FAIL
    verdict: str = ""         # SAFE/OVERFLOW/UNCERTAIN
    confidence: float = 0.0
    proof_detail: str = ""


def prove_single(alloc: Tuple, write: Tuple,
                 propagator=None, graph=None) -> PairProof:
    """单点证明: 对单个 alloc-write 对执行三层级联验证。

    alloc 为 (line, var, func, expr, size, col), write 为
    (line, func, target, offset, write_size, size_expr, col)。
    """
    a_line, a_var, a_func, a_expr, a_size = alloc[:5]
    w_line = write[0]
    w_func = write[1]
    w_target = write[2]
    w_off = write[3]
    w_sz = write[4]
    w_sz_expr = write[5] if len(write) > 5 else ""

    proof = PairProof(
        alloc_var=a_var, alloc_line=a_line,
        alloc_expr=a_expr, alloc_size=a_size,
        write_var=w_target, write_line=w_line,
        write_expr=w_func, write_offset=w_off,
        write_size=w_sz,
    )

    # L1: 守卫直接证明 (需要数值alloc_size)
    if a_size > 0 and propagator is not None:
        v = propagator.check_write_safety(w_line, w_target, a_size)
        if v.verdict == "SAFE" and v.confidence >= 0.80:
            proof.proof_level = "L1"
            proof.verdict = "SAFE"
            proof.confidence = v.confidence
            proof.proof_detail = v.reason
            return proof

        # L1b: 数组store buf[idx] + 守卫 if(idx < N)
        if w_off == -2 and w_sz_expr and graph:
            idx_var = w_sz_expr
            gs = graph.has_guard_before_write(idx_var, w_line)
            if gs and gs.is_constant:
                g_hi = (gs.bound_const - 1 if gs.operator == '<'
                        else gs.bound_const)
                if g_hi >= 0 and g_hi < a_size:
                    proof.proof_level = "L1"
                    proof.verdict = "SAFE"
                    proof.confidence = 0.85
                    proof.proof_detail = f"guard {idx_var} {gs.operator} {gs.bound_const} → max index {g_hi} < alloc {a_size}"
                    return proof

    # L2: 仿射关系 + 约束
    write_size_expr = w_sz_expr if w_sz_expr else (
        str(w_off) if w_off > 0 else "")
    # 跳过复杂表达式 (三元、比较、逻辑、逗号多参) — 简单仿射分析无法处理
    if ',' in a_expr:
        if a_func == 'calloc' or a_func == 'kcalloc':
            a_expr_for_l2 = None
        else:
            a_expr_for_l2 = a_expr.split(',')[0].strip()
    else:
        a_expr_for_l2 = a_expr

    if a_expr_for_l2 is not None and \
       not _is_complex_expr(write_size_expr) and \
       not _is_complex_expr(a_expr_for_l2):
        shared = _shared_vars(a_expr_for_l2, write_size_expr)
        if shared:
            write_all_vars = set(re.findall(r'\b([a-zA-Z_]\w*)\b', write_size_expr))
            alloc_all_vars = set(re.findall(r'\b([a-zA-Z_]\w*)\b', a_expr_for_l2))
            extra_vars = write_all_vars - alloc_all_vars - shared
            has_extra_vars = len(extra_vars) > 0

            for sv in shared:
                # 方向1: 守卫约束检查
                if graph:
                    c = graph.get_direct_constraint(sv)
                    if c and c.hi >= 0:
                        max_write = _eval_expr_bound(
                            write_size_expr, {sv: c.hi})
                        if max_write >= 0 and max_write < a_size:
                            proof.proof_level = "L2"
                            proof.verdict = "SAFE"
                            proof.confidence = 0.75
                            proof.proof_detail = f"affine: shared var {sv} bounded to {c.hi} → max write {max_write} < alloc {a_size}"
                            return proof

                # 方向2: 模式匹配 — claimed+3 vs claimed → 明确溢出
                sv_coef_w = _extract_var_coef(write_size_expr, sv)
                sv_coef_a = _extract_var_coef(a_expr_for_l2, sv)
                const_w = _extract_const_term(write_size_expr)
                const_a = _extract_const_term(a_expr_for_l2)

                if sv_coef_w > 0 or sv_coef_a > 0:
                    if sv_coef_w > sv_coef_a:
                        proof.proof_level = "L2"
                        proof.verdict = "OVERFLOW"
                        proof.confidence = 0.80
                        proof.proof_detail = f"affine: write coef {sv_coef_w} > alloc coef {sv_coef_a}, overflow for any {sv}≥1"
                        return proof
                    elif sv_coef_w == sv_coef_a:
                        if const_w > const_a:
                            proof.proof_level = "L2"
                            proof.verdict = "OVERFLOW"
                            proof.confidence = 0.80
                            proof.proof_detail = f"affine: write({write_size_expr}) > alloc({a_expr_for_l2}) for any {sv}≥1"
                            return proof
                        elif has_extra_vars:
                            proof.proof_level = "L2"
                            proof.verdict = "OVERFLOW"
                            proof.confidence = 0.70
                            proof.proof_detail = f"affine: write({write_size_expr}) has extra vars {extra_vars} vs alloc({a_expr_for_l2})"
                            return proof
                        elif const_w <= const_a:
                            proof.proof_level = "L2"
                            proof.verdict = "SAFE"
                            proof.confidence = 0.75
                            proof.proof_detail = f"affine: write({write_size_expr}) ≤ alloc({a_expr_for_l2}) for any {sv}≥1"
                            return proof
                    else:
                        proof.proof_level = "L2"
                        proof.verdict = "SAFE"
                        proof.confidence = 0.65
                        proof.proof_detail = f"affine: alloc coef {sv_coef_a} > write coef {sv_coef_w}, safe for large {sv}"
                        return proof

    # L3: 常量偏移 + chunk slack (需要数值alloc_size)
    if a_size > 0 and w_off >= 0:
        if w_off >= a_size:
            proof.proof_level = "L3"
            proof.verdict = "OVERFLOW"
            proof.confidence = 0.90
            proof.proof_detail = f"constant offset {w_off} >= alloc {a_size}"
            return proof
        if w_sz > 0 and (w_off + w_sz) > a_size:
            proof.proof_level = "L3"
            proof.verdict = "OVERFLOW"
            proof.confidence = 0.90
            proof.proof_detail = f"offset {w_off} + write_size {w_sz} = {w_off+w_sz} > alloc {a_size}"
            return proof
        effective = _effective_boundary(a_size)
        if w_off < a_size:
            proof.proof_level = "L3"
            proof.verdict = "SAFE"
            proof.confidence = 0.90
            proof.proof_detail = f"constant offset {w_off} < alloc {a_size}"
            return proof
        elif w_off < effective:
            proof.proof_level = "L3"
            proof.verdict = "SAFE"
            proof.confidence = 0.65
            proof.proof_detail = f"offset {w_off} within chunk slack (alloc={a_size}, effective={effective})"
            return proof
    # 常量写入大小 + 无偏移 → 检查 total_write ≤ alloc
    if a_size > 0 and w_sz > 0 and w_off == -1:
        if w_sz <= a_size:
            proof.proof_level = "L3"
            proof.verdict = "SAFE"
            proof.confidence = 0.85
            proof.proof_detail = f"write size {w_sz} ≤ alloc {a_size}"
            return proof
        elif w_sz > a_size:
            proof.proof_level = "L3"
            proof.verdict = "OVERFLOW"
            proof.confidence = 0.90
            proof.proof_detail = f"write size {w_sz} > alloc {a_size}"
            return proof

    # 无法证明
    proof.verdict = "UNCERTAIN"
    proof.proof_detail = f"cannot prove: alloc={a_size}, write_off={w_off}, write_sz={w_sz}"
    return proof


# 辅助函数

def _shared_vars(expr1: str, expr2: str) -> Set[str]:
    """提取两个表达式中的共享变量."""
    v1 = set(re.findall(r'\b([a-zA-Z_]\w*)\b', expr1))
    v2 = set(re.findall(r'\b([a-zA-Z_]\w*)\b', expr2))
    return v1 & v2 - {'sizeof', 'malloc', 'calloc', 'free', 'NULL'}


def _is_complex_expr(expr: str) -> bool:
    """检查表达式是否包含简单仿射分析无法处理的结构."""
    if '?' in expr or ':' in expr:
        return True
    if re.search(r'[<>!=]=|\&\&|\|\|', expr):
        return True
    if '(' in expr and ')' in expr:
        return True
    return False


def _extract_var_coef(expr: str, var: str) -> int:
    """提取表达式中变量的系数. expr='n*4+8', var='n' → 4."""
    m = re.search(rf'(\d+)\s*\*\s*{re.escape(var)}', expr)
    if m:
        return int(m.group(1))
    m = re.search(rf'{re.escape(var)}\s*\*\s*(\d+)', expr)
    if m:
        return int(m.group(1))
    if re.search(rf'\b{re.escape(var)}\b', expr):
        return 1
    return 0


def _extract_const_term(expr: str) -> int:
    """提取表达式中的常量项. expr='n*4+8' → 8."""
    cleaned = re.sub(r'\b[a-zA-Z_]\w*\s*\*\s*\d+', '', expr)
    cleaned = re.sub(r'\d+\s*\*\s*\b[a-zA-Z_]\w*', '', cleaned)
    cleaned = re.sub(r'\b[a-zA-Z_]\w*', '', cleaned)
    consts = re.findall(r'(?<!\w)(\d+)(?!\s*\*)', cleaned)
    if consts:
        return sum(int(c) for c in consts)
    return 0


def _eval_expr_bound(expr: str, bindings: Dict[str, int]) -> int:
    """在变量替换下评估表达式的上界."""
    try:
        result = expr
        for v, val in bindings.items():
            result = re.sub(r'\b' + re.escape(v) + r'\b', str(val), result)
        cleaned = re.sub(r'[^0-9+\-*/()]', '', result)
        if cleaned:
            return int(eval(cleaned))
    except Exception:
        pass
    return -1


def _effective_boundary(raw: int) -> int:
    """含glibc chunk alignment slack的有效边界."""
    if raw <= 0:
        return 0
    return max(raw, ((raw + 15) // 16) * 16)


__all__ = [
    'PairProof', 'prove_single',
    '_shared_vars', '_is_complex_expr',
    '_extract_var_coef', '_extract_const_term',
    '_eval_expr_bound', '_effective_boundary',
]
