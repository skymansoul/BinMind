"""ThreePathDisjoint - 三路径不相交 (stage 94).

不同分配点/同分配点不越界/live-range 互斥三策略的集合运算实现
(区间集合差). 与 disjointness_prover 的证明器实现不同.

设计决策:
  - 策略1: 不同分配点 -> 写区间全部不落在任一分配区间内则不相交
  - 策略2: 同分配点不越界: 写区间包含于分配区间
  - 策略3: live-range 互斥: 两写点区间不相交
  - 全部用区间集合差运算
"""

import re
from typing import List, Optional, Tuple


def _alloc_range(pseudocode: str) -> Optional[Tuple[int, int]]:
    """分配区间 [0, alloc)."""
    m = re.search(r"malloc\s*\(\s*(\d+)\s*\)", pseudocode)
    return (0, int(m.group(1))) if m else None


def _write_ranges(pseudocode: str) -> List[Tuple[int, int, int]]:
    """写区间列表 [(行号, lo, hi)]."""
    out = []
    for ln, line in enumerate(pseudocode.splitlines(), 1):
        m = re.search(r"\[\s*\w+\s*\+\s*(\d+)\s*\]\s*(?:,|=)\s*(\d+)", line)
        if m:
            off, size = int(m.group(1)), int(m.group(2))
            out.append((ln, off, off + size))
    return out


def _all_alloc_ranges(pseudocode: str) -> List[Tuple[int, int]]:
    """提取所有 malloc 分配点及其大小, 返回 [(0, size), ...]."""
    out: List[Tuple[int, int]] = []
    for m in re.finditer(r"malloc\s*\(\s*(\d+)\s*\)", pseudocode):
        out.append((0, int(m.group(1))))
    return out


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


def _c_write_ranges(
    pseudocode: str, alloc_var: str,
) -> List[Tuple[int, int, int, int, int]]:
    """C 风格写区间 -> [(行号, lo_coeff, lo_const, hi_coeff, hi_const)].
    写区间 [lo_coeff*var+lo_const, hi_coeff*var+hi_const].
    """
    out = []
    for ln, line in enumerate(pseudocode.splitlines(), 1):
        # buf[expr] = value 写语句
        m = re.search(r"(\w+)\s*\[\s*([^\]]+)\s*\]\s*=\s*", line)
        if not m:
            continue
        cidx = _parse_c_index_expr(m.group(2))
        if cidx is None:
            continue
        idx_var, scale, offset = cidx
        if idx_var == alloc_var:
            # 索引变量即分配变量: 单点写 1*var+offset
            out.append((ln, 1, offset, 1, offset))
            continue
        bound = _c_loop_bound(pseudocode, idx_var)
        if bound is not None and bound == alloc_var:
            # 循环上界为分配变量: i in [0,var-1], 偏移 [offset, scale*(var-1)+offset]
            out.append((ln, 0, offset, scale, offset - scale))
            continue
        if bound is not None and re.fullmatch(r"\d+", bound):
            b = int(bound)
            out.append((ln, 0, offset, 0, scale * (b - 1) + offset))
            continue
        m_const = re.search(
            r"\b" + re.escape(idx_var) + r"\s*=\s*(\d+)", pseudocode)
        if m_const:
            v = int(m_const.group(1))
            w = scale * v + offset
            out.append((ln, 0, w, 0, w))
            continue
        m_guard = re.search(
            r"\bif\s*\(\s*" + re.escape(idx_var) + r"\s*<\s*(\d+)\s*\)",
            pseudocode)
        if m_guard:
            v = int(m_guard.group(1))
            out.append((ln, 0, offset, 0, scale * (v - 1) + offset))
            continue
    return out


def _set_diff(a: Tuple[int, int], b: Tuple[int, int]) -> List[Tuple[int, int]]:
    """区间集合差 a - b."""
    if b[0] >= a[1] or a[0] >= b[1]:
        return [a]
    res = []
    if a[0] < b[0]:
        res.append((a[0], min(a[1], b[0])))
    if a[1] > b[1]:
        res.append((max(a[0], b[1]), a[1]))
    return res


def run_three_path_disjoint(
    pseudocode: str,
    func_name: str,
    existing_findings: Optional[List[dict]] = None,
) -> List[dict]:
    """三路径不相交. 返回 findings."""
    findings: List[dict] = []
    # 汇编风格: malloc(纯数字)
    alloc = _alloc_range(pseudocode)
    writes = _write_ranges(pseudocode)
    if alloc is not None and writes:
        # 策略1: 不同分配点 -> 写区间是否落在任一分配区间内
        alloc_points = _all_alloc_ranges(pseudocode)
        if alloc_points:
            all_outside = True
            for _ln, lo, hi in writes:
                for a_lo, a_hi in alloc_points:
                    if lo >= a_lo and hi <= a_hi:
                        all_outside = False
                        break
                if not all_outside:
                    break
            if all_outside and writes:
                findings.append({
                    "type": "heap_overflow",
                    "function": func_name or "unknown",
                    "severity": "medium",
                    "cwe": "CWE-122",
                    "confidence": 0.6,
                    "description": (
                        f"strategy1: {len(writes)} write(s) outside all "
                        f"{len(alloc_points)} alloc range(s) -> disjoint"
                    ),
                    "verdict": "disjoint_allocs",
                    "source": "three_path_disjoint",
                })
        # 策略2: 同分配点不越界
        for ln, lo, hi in writes:
            diff = _set_diff((lo, hi), alloc)
            if not diff:
                verdict, conf = "within_alloc", 0.9
            else:
                verdict, conf = "outside_alloc", 0.8
            findings.append({
                "type": "heap_overflow",
                "function": func_name or "unknown",
                "severity": "medium",
                "cwe": "CWE-122",
                "confidence": conf,
                "description": f"line{ln} range=({lo},{hi}) alloc={alloc} "
                               f"diff={diff}",
                "verdict": verdict,
                "source": "three_path_disjoint",
            })
        # 策略3: live-range 互斥 (两写点区间不相交)
        for i in range(len(writes)):
            for j in range(i + 1, len(writes)):
                a, b = writes[i], writes[j]
                if a[2] <= b[1] or b[2] <= a[1]:
                    findings.append({
                        "type": "meta_audit",
                        "function": func_name or "unknown",
                        "severity": "low",
                        "cwe": "CWE-000",
                        "confidence": 0.7,
                        "description": f"live_range_disjoint line{a[0]} vs "
                                       f"line{b[0]}",
                        "verdict": "live_disjoint",
                        "source": "three_path_disjoint",
                    })
        return findings

    # C 风格: malloc(变量/表达式) 或汇编分支无写区间
    c_alloc = _parse_c_alloc(pseudocode)
    if c_alloc is None:
        return findings
    a_var, a_coeff, a_const = c_alloc
    c_writes = _c_write_ranges(pseudocode, a_var)

    # C 风格策略2: 写区间与分配区间符号差集
    # 分配区间 [0, a_coeff*var+a_const)
    for ln, w_lo_c, lo_c, w_hi_c, hi_c in c_writes:
        # 判定写区间是否在分配区间内
        if a_coeff == 0 and w_lo_c == 0 and w_hi_c == 0:
            # 纯常量: 直接数值比较
            if lo_c >= 0 and hi_c <= a_const:
                verdict, conf = "within_alloc", 0.9
            else:
                verdict, conf = "outside_alloc", 0.8
        elif w_lo_c == 0 and w_hi_c == 0:
            # 写偏移为常量但分配为变量
            if lo_c >= 0 and a_coeff > 0:
                verdict, conf = "outside_alloc", 0.7
            else:
                verdict, conf = "outside_alloc", 0.8
        elif w_hi_c > a_coeff:
            verdict, conf = "outside_alloc", 0.8
        elif w_hi_c < a_coeff:
            verdict, conf = "within_alloc", 0.85
        else:
            # w_hi_c == a_coeff: 比较 const
            if lo_c >= 0 and hi_c < a_const:
                verdict, conf = "within_alloc", 0.9
            elif lo_c >= 0 and hi_c == a_const:
                verdict, conf = "within_alloc", 0.85
            else:
                verdict, conf = "outside_alloc", 0.8
        findings.append({
            "type": "heap_overflow",
            "function": func_name or "unknown",
            "severity": "medium",
            "cwe": "CWE-122",
            "confidence": conf,
            "description": (
                f"line{ln} write=[{w_lo_c}*v+{lo_c},{w_hi_c}*v+{hi_c}] "
                f"alloc=[0,{a_coeff}*v+{a_const}] -> {verdict}"),
            "verdict": verdict,
            "source": "three_path_disjoint",
        })

    # C 风格: memcpy(buf, src, size) 写区间检测
    for ln, line in enumerate(pseudocode.splitlines(), 1):
        m_mc = re.search(
            r"memcpy\s*\(\s*(\w+)\s*,\s*\w+\s*,\s*([^)]+)\s*\)", line)
        if not m_mc:
            continue
        size_expr = m_mc.group(2).strip()
        if re.fullmatch(r"\d+", size_expr):
            w = int(size_expr)
            if a_coeff == 0:
                verdict = "within_alloc" if w <= a_const else "outside_alloc"
                conf = 0.9 if verdict == "within_alloc" else 0.8
            else:
                verdict = "outside_alloc"
                conf = 0.7
        elif re.fullmatch(r"\w+", size_expr) and size_expr == a_var:
            verdict = "within_alloc"
            conf = 0.9
        elif re.fullmatch(r"\w+", size_expr):
            verdict = "outside_alloc"
            conf = 0.7
        else:
            verdict = "outside_alloc"
            conf = 0.7
        findings.append({
            "type": "heap_overflow",
            "function": func_name or "unknown",
            "severity": "medium",
            "cwe": "CWE-122",
            "confidence": conf,
            "description": (
                f"line{ln} memcpy(buf,src,{size_expr}) alloc="
                f"[0,{a_coeff}*v+{a_const}] -> {verdict}"),
            "verdict": verdict,
            "source": "three_path_disjoint",
        })

    return findings


if __name__ == "__main__":
    demo = """\
p = malloc(64);
mov [p+8], 4;
mov [p+32], 4;
"""
    out = run_three_path_disjoint(demo, "demo")
    for f in out:
        print(f["description"], f["verdict"])