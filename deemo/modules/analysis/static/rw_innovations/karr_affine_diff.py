"""KarrAffineDiff - Karr 仿射差 (stage 106).

write-alloc 仿射差 + eval_bounds 极值, 单维纯 Karr 表示:
  记录形如 var = a*base + b 的仿射关系, 求差区间极值判定越界.
与 delta_interval_eval 不同: 本模块用 Karr 仿射关系链传播而非守卫窄化.

设计决策:
  - Karr 仿射: 只记录单维 x = a*y + b 关系
  - eval_bounds: 由 y 的区间求 x 极值
  - 差 = 写极值 - 分配大小, 上界<0 safe, 下界>0 overflow
  - C 分支 (新): 沿赋值链传播仿射关系, 再用传播后的关系评估写点
"""

import re
from typing import Dict, List, Optional, Tuple


def _collect_affine(pseudocode: str) -> Dict[str, Tuple[int, str, int]]:
    """收集 var = a*base + b 或 var = base + b 关系."""
    rel: Dict[str, Tuple[int, str, int]] = {}
    for line in pseudocode.splitlines():
        m = re.search(r"\b(\w+)\s*=\s*(\d+)\s*\*\s*(\w+)\s*\+\s*(\d+)", line)
        if m:
            rel[m.group(1)] = (int(m.group(2)), m.group(3), int(m.group(4)))
            continue
        m = re.search(r"\b(\w+)\s*=\s*(\w+)\s*\+\s*(\d+)", line)
        if m:
            rel[m.group(1)] = (1, m.group(2), int(m.group(3)))
    return rel


def _eval_bounds(
    rel: Dict[str, Tuple[int, str, int]],
    ranges: Dict[str, Tuple[int, int]],
    idx: str,
) -> Optional[Tuple[int, int]]:
    return _bounds(idx, rel, ranges)


def _bounds(
    idx: str, rel: Dict[str, Tuple[int, str, int]], ranges: Dict[str, Tuple[int, int]]
) -> Optional[Tuple[int, int]]:
    r = rel.get(idx)
    if r is None:
        return ranges.get(idx)
    a, base, b = r
    rb = ranges.get(base)
    if rb is None:
        return None
    lo, hi = rb
    vals = (a * lo + b, a * hi + b)
    return (min(vals), max(vals))


def _parse_c_alloc(pseudocode: str) -> Optional[Tuple[str, int, int]]:
    """解析 C 风格 malloc 表达式 -> (var, coeff, const)."""
    m = re.search(r"malloc\s*\(\s*([^)]+)\s*\)", pseudocode)
    if not m:
        return None
    expr = m.group(1).strip()
    if re.fullmatch(r"\d+", expr):
        return ('', 0, int(expr))
    if re.fullmatch(r"\w+", expr):
        return (expr, 1, 0)
    m2 = re.fullmatch(r"(\w+)\s*\*\s*(\d+)", expr)
    if m2:
        return (m2.group(1), int(m2.group(2)), 0)
    m3 = re.fullmatch(r"(\d+)\s*\*\s*(\w+)", expr)
    if m3:
        return (m3.group(2), int(m3.group(1)), 0)
    return None


def _parse_c_index_expr(expr: str) -> Optional[Tuple[str, int, int]]:
    """解析 C 风格索引表达式 -> (idx_var, scale, offset)."""
    expr = expr.strip()
    m = re.fullmatch(r"(\w+)\s*\+\s*(\d+)", expr)
    if m:
        return (m.group(1), 1, int(m.group(2)))
    m = re.fullmatch(r"(\w+)\s*-\s*(\d+)", expr)
    if m:
        return (m.group(1), 1, -int(m.group(2)))
    m = re.fullmatch(r"(\w+)\s*\*\s*(\d+)", expr)
    if m:
        return (m.group(1), int(m.group(2)), 0)
    m = re.fullmatch(r"(\d+)\s*\*\s*(\w+)", expr)
    if m:
        return (m.group(2), int(m.group(1)), 0)
    m = re.fullmatch(r"(\w+)", expr)
    if m:
        return (m.group(1), 1, 0)
    return None


def _c_loop_bound(pseudocode: str, idx: str) -> Optional[str]:
    """解析 for(idx=0; idx<bound; idx++) -> bound."""
    m = re.search(
        r"for\s*\(\s*(?:int\s+)?\w+\s*=\s*\d+\s*;\s*"
        + re.escape(idx) + r"\s*<\s*(\w+)\s*;",
        pseudocode,
    )
    return m.group(1) if m else None


# #[DEPRECATED] 旧的系数+常量直接比较逻辑, 由 _karr_propagate_chain 替代
def _karr_symbolic(
    idx_var: str, scale: int, offset: int,
    pseudocode: str, a_var: str, a_coeff: int, a_const: int,
) -> Optional[Tuple[int, int, int, int]]:
    """Karr 仿射差: 写偏移 = α*var+β, 分配 = a_coeff*var+a_const.
    差 = (α-a_coeff)*var + (β-a_const).
    返回 (d_lo_coeff, d_lo_const, d_hi_coeff, d_hi_const).
    """
    if idx_var == a_var:
        # 索引变量即分配变量: 写偏移 = scale*var+offset (单点)
        dc = scale - a_coeff
        return (dc, offset - a_const, dc, offset - a_const)
    bound = _c_loop_bound(pseudocode, idx_var)
    if bound is not None:
        if bound == a_var:
            # 循环上界为分配变量: i in [0,var-1]
            # write_lo = offset, write_hi = scale*(var-1)+offset
            # delta_lo = offset - (a_coeff*var+a_const) = -a_coeff*var + (offset-a_const)
            # delta_hi = scale*var+(offset-scale) - (a_coeff*var+a_const) = (scale-a_coeff)*var + (offset-scale-a_const)
            return (-a_coeff, offset - a_const,
                    scale - a_coeff, offset - scale - a_const)
        if re.fullmatch(r"\d+", bound):
            b = int(bound)
            w_lo = offset
            w_hi = scale * (b - 1) + offset
            if a_coeff == 0:
                return (w_lo - a_const, 0, w_hi - a_const, 0)
            return (-a_coeff, w_lo - a_const, -a_coeff, w_hi - a_const)
    m_const = re.search(
        r"\b" + re.escape(idx_var) + r"\s*=\s*(\d+)", pseudocode)
    if m_const:
        v = int(m_const.group(1))
        w = scale * v + offset
        if a_coeff == 0:
            return (w - a_const, 0, w - a_const, 0)
        return (-a_coeff, w - a_const, -a_coeff, w - a_const)
    return None


# #[DEPRECATED] 旧的评级逻辑, 由 _karr_propagate_grade 替代
def _karr_grade(d_lo_c: int, d_lo: int, d_hi_c: int, d_hi: int) -> str:
    """Karr 仿射差评级: 下界>0 -> overflow, 上界<0 -> safe, 否则 bounded."""
    if d_lo_c == 0 and d_hi_c == 0:
        if d_lo > 0:
            return "overflow"
        if d_hi < 0:
            return "safe"
        return "bounded"
    if d_hi_c > 0:
        return "overflow"
    if d_hi_c < 0:
        return "safe"
    if d_lo_c > 0:
        return "overflow"
    if d_lo_c < 0:
        return "safe"
    return "bounded"


def _karr_collect_chain(pseudocode: str) -> Dict[str, Tuple[int, str, int]]:
    """收集所有 x = a*y + b 仿射关系, 用于赋值链传播."""
    chain: Dict[str, Tuple[int, str, int]] = {}
    for line in pseudocode.splitlines():
        m = re.search(r"\b(\w+)\s*=\s*(\d+)\s*\*\s*(\w+)\s*\+\s*(\d+)", line)
        if m:
            chain[m.group(1)] = (int(m.group(2)), m.group(3), int(m.group(4)))
            continue
        m = re.search(r"\b(\w+)\s*=\s*(\w+)\s*\+\s*(\d+)", line)
        if m:
            chain[m.group(1)] = (1, m.group(2), int(m.group(3)))
            continue
        m = re.search(r"\b(\w+)\s*=\s*(\d+)\s*\*\s*(\w+)", line)
        if m:
            chain[m.group(1)] = (int(m.group(2)), m.group(3), 0)
    return chain


def _karr_resolve_chain(
    var: str,
    chain: Dict[str, Tuple[int, str, int]],
    visited: Optional[set] = None,
) -> Optional[Tuple[int, str, int]]:
    """沿仿射赋值链传播: 把 var 解析到最底层 (coeff, root, const).
    如 n -> m = 2*n+0, 则 buf[n+8] 中 n 可传播为 2*root+0, 写偏移 = 1*(2*root)+8.
    """
    if visited is None:
        visited = set()
    if var in visited:
        return None
    visited.add(var)
    rel = chain.get(var)
    if rel is None:
        # var 本身是根节点
        return (1, var, 0)
    a, base, b = rel
    # base 不可再传播
    if base not in chain:
        return (a, base, b)
    sub = _karr_resolve_chain(base, chain, visited)
    if sub is None:
        return (a, base, b)
    # 合并: var = a * (sub_a * root + sub_b) + b = (a*sub_a)*root + (a*sub_b + b)
    return (a * sub[0], sub[1], a * sub[2] + b)


def _karr_const_value(pseudocode: str, var: str) -> Optional[int]:
    """从赋值语句提取变量的常量值."""
    m = re.search(r"\b" + re.escape(var) + r"\s*=\s*(\d+)", pseudocode)
    return int(m.group(1)) if m else None


def _karr_propagate_eval(
    idx_var: str, scale: int, offset: int,
    pseudocode: str, a_var: str, a_coeff: int, a_const: int,
) -> Optional[Tuple[str, int, int]]:
    """沿仿射链传播后评估写点与分配的关系.
    返回 (verdict_desc, d_lo, d_hi) 或 None.
    核心思路: 把 idx_var 沿仿射链解析到与分配变量同根, 再比较系数.
    """
    chain = _karr_collect_chain(pseudocode)
    # 循环上界隐含关系: for(i=0;i<n;i++) 表示 i 取值 [0,n-1], 即 i = 1*n + (-1) 的隐含仿射
    loop_bound = _c_loop_bound(pseudocode, idx_var)
    if loop_bound is not None:
        if idx_var not in chain:
            if loop_bound == a_var:
                chain[idx_var] = (1, loop_bound, -1)
            elif re.fullmatch(r"\d+", loop_bound):
                chain[idx_var] = (0, idx_var, int(loop_bound) - 1)
    # 写侧: write = scale * idx_var + offset, 沿链传播 idx_var
    w_resolved = _karr_resolve_chain(idx_var, chain)
    if w_resolved is None:
        # 尝试常量赋值
        cv = _karr_const_value(pseudocode, idx_var)
        if cv is not None:
            w_val = scale * cv + offset
            if a_coeff == 0:
                d = w_val - a_const
                if d > 0:
                    return ("overflow", d, d)
                if d < 0:
                    return ("safe", d, d)
                return ("bounded", d, d)
        return None
    w_coeff_root, w_root, w_chain_const = w_resolved
    # 写偏移 = scale * (w_coeff_root * w_root + w_chain_const) + offset
    #         = (scale * w_coeff_root) * w_root + (scale * w_chain_const + offset)
    final_w_coeff = scale * w_coeff_root
    final_w_const = scale * w_chain_const + offset
    # 分配侧也沿链传播
    a_resolved = _karr_resolve_chain(a_var, chain)
    if a_resolved is None:
        a_final_coeff = a_coeff
        a_final_root = a_var
        a_final_const = a_const
    else:
        a_chain_coeff, a_chain_root, a_chain_const = a_resolved
        # 分配 = a_coeff * (a_chain_coeff * a_chain_root + a_chain_const) + a_const
        a_final_coeff = a_coeff * a_chain_coeff
        a_final_root = a_chain_root
        a_final_const = a_coeff * a_chain_const + a_const
    # 同根比较: 写系数 vs 分配系数
    if w_root != a_final_root:
        return None
    if a_final_coeff == 0 and final_w_coeff == 0:
        d = final_w_const - a_final_const
        if d > 0:
            return ("overflow", d, d)
        if d < 0:
            return ("safe", d, d)
        return ("bounded", d, d)
    if a_final_coeff == 0 or final_w_coeff == 0:
        return None
    # 写系数 > 分配系数 -> overflow
    if final_w_coeff > a_final_coeff:
        return ("overflow", final_w_coeff - a_final_coeff, final_w_const - a_final_const)
    # 写系数 < 分配系数 -> safe
    if final_w_coeff < a_final_coeff:
        return ("safe", final_w_coeff - a_final_coeff, final_w_const - a_final_const)
    # 系数相等: 比较常量
    d = final_w_const - a_final_const
    if d > 0:
        return ("overflow", d, d)
    if d < 0:
        return ("safe", d, d)
    return ("bounded", d, d)


def run_karr_affine_diff(
    pseudocode: str,
    func_name: str,
    existing_findings: Optional[List[dict]] = None,
) -> List[dict]:
    """Karr 仿射差判定. 返回 findings."""
    findings: List[dict] = []
    # 汇编风格: malloc/calloc/realloc(纯数字)
    m_alloc = re.search(r"(?:malloc|calloc|realloc)\s*\(\s*(\d+)", pseudocode)
    # C 风格分配
    c_alloc = _parse_c_alloc(pseudocode)

    # 汇编风格分支 (仅在存在汇编写地址时生效)
    if m_alloc:
        alloc = int(m_alloc.group(1))
        ranges: Dict[str, Tuple[int, int]] = {}
        for line in pseudocode.splitlines():
            m = re.search(r"\b(\w+)\s*=\s*(\d+)\s*;", line)
            if m:
                ranges[m.group(1)] = (int(m.group(2)), int(m.group(2)))
        rel = _collect_affine(pseudocode)
        asm_writes = []
        for ln, line in enumerate(pseudocode.splitlines(), 1):
            m = re.search(r"\[\s*\w+\s*\+\s*(\w+)\s*\]\s*(?:,|=)", line)
            if not m:
                continue
            idx = m.group(1)
            bounds = _eval_bounds(rel, ranges, idx)
            if bounds is None:
                continue
            lo, hi = bounds
            d_lo, d_hi = lo - alloc, hi - alloc
            if d_hi < 0:
                verdict, conf = "safe", 0.85
            elif d_lo > 0:
                verdict, conf = "overflow", 0.9
            else:
                verdict, conf = "bounded", 0.5
            asm_writes.append({
                "type": "heap_overflow",
                "function": func_name or "unknown",
                "severity": "medium",
                "cwe": "CWE-122",
                "confidence": conf,
                "description": f"line{ln} idx={idx} bounds={bounds} "
                               f"delta=({d_lo},{d_hi}) verdict={verdict}",
                "verdict": verdict,
                "source": "karr_affine_diff",
            })
        if asm_writes:
            return asm_writes

    # C 风格分支
    if c_alloc is None:
        return findings
    a_var, a_coeff, a_const = c_alloc

    for ln, line in enumerate(pseudocode.splitlines(), 1):
        # C 风格: buf[expr] = value 写语句 (仿射传播判定)
        m_c = re.search(r"(\w+)\s*\[\s*([^\]]+)\s*\]\s*=\s*", line)
        if m_c:
            idx_expr = m_c.group(2).strip()
            cidx = _parse_c_index_expr(idx_expr)
            if cidx is None:
                continue
            idx_var, scale, offset = cidx
            pe = _karr_propagate_eval(
                idx_var, scale, offset, pseudocode,
                a_var, a_coeff, a_const)
            if pe is None:
                continue
            verdict, d_lo, d_hi = pe
            if verdict == "bounded":
                continue
            findings.append({
                "type": "heap_overflow",
                "function": func_name or "unknown",
                "severity": "medium",
                "cwe": "CWE-122",
                "confidence": 0.9 if verdict == "overflow" else 0.85,
                "description": (
                    f"line{ln} buf[{idx_expr}] idx={idx_var} scale={scale} "
                    f"off={offset} delta=({d_lo},{d_hi}) "
                    f"propagate -> {verdict}"),
                "verdict": verdict,
                "source": "karr_affine_diff",
            })
            continue

        # C 风格: memcpy(buf, src, size) 写语句
        m_mc = re.search(
            r"memcpy\s*\(\s*(\w+)\s*,\s*\w+\s*,\s*([^)]+)\s*\)", line)
        if m_mc:
            size_expr = m_mc.group(2).strip()
            if re.fullmatch(r"\d+", size_expr):
                w = int(size_expr)
                if a_coeff == 0:
                    d_lo = w - a_const
                    d_hi = w - a_const
                    if d_lo > 0:
                        verdict = "overflow"
                    elif d_hi < 0:
                        verdict = "safe"
                    else:
                        verdict = "bounded"
                    if verdict == "bounded":
                        continue
                    findings.append({
                        "type": "heap_overflow",
                        "function": func_name or "unknown",
                        "severity": "medium",
                        "cwe": "CWE-122",
                        "confidence": 0.9 if verdict == "overflow" else 0.85,
                        "description": (
                            f"line{ln} memcpy(buf,src,{w}) alloc={a_const} "
                            f"delta=({d_lo},{d_hi}) -> {verdict}"),
                        "verdict": verdict,
                        "source": "karr_affine_diff",
                    })
            elif re.fullmatch(r"\w+", size_expr) and size_expr == a_var:
                # memcpy 大小 = 分配变量: 差 = 0 -> bounded, 不注入
                continue

    return findings


if __name__ == "__main__":
    demo = """\
p = malloc(64);
i = 2;
j = 4 * i + 0;
mov [p+j], 8;
"""
    out = run_karr_affine_diff(demo, "demo")
    for f in out:
        print(f["description"], f["verdict"])