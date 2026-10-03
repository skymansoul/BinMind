"""DeltaIntervalEval - 仿射差区间求值 (stage 100).

守卫窄化二次求值 (C 风格分支):
  第一次求值: 从写操作提取偏移区间 [lo, hi] vs 分配大小
  第二次求值: 若守卫 if (idx < N) 存在, 将 idx 上界代换为 N-1, 窄化区间后重新求值
  窄化后仍超界 -> overflow; 窄化后相容 -> safe; 无守卫退化为一次求值
与 karr_affine_diff 不同: karr 用仿射赋值链传播, 本模块用守卫上界代入窄化.
与 affine_meet_domain 不同: 本模块直接算差值并做守卫上界代换.

设计决策:
  - 一次求值: 原始偏移区间 [lo, hi] vs 分配大小
  - 二次求值: 守卫约束后代换偏移上界, 窄化区间
  - 无守卫时二次求值等于一次求值 (退化)
  - 差区间 delta = [sub_lo - alloc, sub_hi - alloc]
"""

import re
from typing import List, Optional, Tuple


def _guard_bound(pseudocode: str, idx: str = "") -> Optional[int]:
    """守卫上界: 找 if (var < N) 形式, 优先匹配指定变量."""
    if idx:
        m = re.search(r"if\s*\(\s*" + re.escape(idx) +
                      r"\s*<\s*(\d+)", pseudocode)
        if m:
            return int(m.group(1))
    m = re.search(r"if\s*\(\s*(\w+)\s*<\s*(\d+)", pseudocode)
    return int(m.group(2)) if m else None


def _extract_offset_bounds(
    pseudocode: str, line: str, idx: str
) -> Tuple[int, int]:
    """从写操作提取偏移区间 [lo, hi]."""
    lo = 0
    hi = 0
    # 常量偏移: [base+8] 或 idx = 8
    m_const = re.search(r"\[\s*\w+\s*\+\s*(\d+)\s*\]", line)
    if m_const:
        v = int(m_const.group(1))
        return (v, v)
    m_def = re.search(r"\b" + re.escape(idx) + r"\s*=\s*(\d+)\s*;", pseudocode)
    if m_def:
        v = int(m_def.group(1))
        return (v, v)
    # 变量偏移: 无常量信息时给保守上界
    m_bound = re.search(r"\b" + re.escape(idx) + r"\s*<\s*(\d+)", pseudocode)
    if m_bound:
        hi = int(m_bound.group(1)) - 1
    else:
        hi = 0
    return (lo, hi)


def _delta(lo: int, hi: int, alloc: int) -> Tuple[int, int]:
    return (lo - alloc, hi - alloc)


def _grade(d: Tuple[int, int]) -> str:
    lo, hi = d
    # 反向区间 (lo > hi): 守卫使写操作不可达 => safe
    if lo > hi:
        return "safe"
    if hi < 0:
        return "safe"
    if lo > 0:
        return "overflow"
    return "bounded"


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


# #[DEPRECATED] 旧的符号差逻辑, 由 _guard_narrow_eval 替代
def _symbolic_delta(
    idx_var: str, scale: int, offset: int,
    pseudocode: str, a_var: str, a_coeff: int, a_const: int,
) -> Optional[Tuple[int, int, int, int]]:
    """将写偏移区间与分配大小做符号差, 返回 (d_lo_coeff, d_lo_const, d_hi_coeff, d_hi_const).
    差区间 = [write_lo - alloc, write_hi - alloc].
    返回 None 表示无法确定.
    """
    # 写偏移上界 = scale * max_idx + offset, 下界 = offset (idx 从 0 开始)
    if idx_var == a_var:
        # 索引变量即分配变量: 单点写 scale*var+offset
        # 差 = (scale-a_coeff)*var + (offset-a_const) (单点)
        dc = scale - a_coeff
        return (dc, offset - a_const, dc, offset - a_const)
    bound = _c_loop_bound(pseudocode, idx_var)
    if bound is not None:
        if bound == a_var:
            # 循环上界为分配变量: max_idx = var-1
            # write_hi = scale*(var-1)+offset = scale*var + (offset-scale)
            # write_lo = offset (idx 从 0)
            # delta_lo = offset - (a_coeff*var + a_const) -> -a_coeff*var + (offset-a_const)
            # delta_hi = (scale*var + offset-scale) - (a_coeff*var + a_const) -> (scale-a_coeff)*var + (offset-scale-a_const)
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


# #[DEPRECATED] 旧的符号差评级, 由 _guard_narrow_grade 替代
def _grade_symbolic(d_lo_c: int, d_lo: int, d_hi_c: int, d_hi: int) -> str:
    """符号差区间评级: 下界>0 -> overflow, 上界<0 -> safe, 否则 bounded."""
    # 纯常量差
    if d_lo_c == 0 and d_hi_c == 0:
        if d_lo > 0:
            return "overflow"
        if d_hi < 0:
            return "safe"
        return "bounded"
    # 差区间含变量: 用系数判定主方向
    if d_hi_c > 0:
        return "overflow"
    if d_hi_c < 0:
        return "safe"
    # d_hi_c == 0, d_lo_c != 0
    if d_lo_c > 0:
        return "overflow"
    if d_lo_c < 0:
        return "safe"
    return "bounded"


def _guard_for_idx(pseudocode: str, idx: str) -> Optional[int]:
    """查找指定变量的守卫上界: if (idx < N) -> N."""
    m = re.search(
        r"if\s*\(\s*" + re.escape(idx) + r"\s*<\s*(\d+)\s*\)", pseudocode)
    return int(m.group(1)) if m else None


def _clamp_for_idx(pseudocode: str, idx: str) -> Optional[int]:
    """查找指定变量的 clamp 上界: if (idx > N) idx = N; -> N."""
    m = re.search(
        r"if\s*\(\s*" + re.escape(idx) + r"\s*>\s*(\d+)\s*\)\s*"
        + re.escape(idx) + r"\s*=\s*(\d+)", pseudocode)
    if m:
        return int(m.group(2))
    # 形式二: if (N > idx) idx = N
    m2 = re.search(
        r"if\s*\(\s*(\d+)\s*>\s*" + re.escape(idx) + r"\s*\)\s*"
        + re.escape(idx) + r"\s*=\s*(\d+)", pseudocode)
    if m2:
        return int(m2.group(2))
    return None


def _eval_write_interval(
    idx_var: str, scale: int, offset: int, pseudocode: str,
) -> Optional[Tuple[int, int]]:
    """第一次求值: 写偏移原始区间 [w_lo, w_hi].
    idx 从 0 开始, 上界由循环/赋值/守卫决定.
    """
    # 常量赋值: idx = C -> 单点
    cv = re.search(r"\b" + re.escape(idx_var) + r"\s*=\s*(\d+)", pseudocode)
    if cv:
        v = int(cv.group(1))
        w = scale * v + offset
        return (w, w)
    # 循环上界
    bound = _c_loop_bound(pseudocode, idx_var)
    if bound is not None:
        if re.fullmatch(r"\d+", bound):
            b = int(bound)
            w_lo = offset
            w_hi = scale * (b - 1) + offset
            return (w_lo, w_hi)
        # 循环上界是变量: 无法数值化, 返回符号区间 [offset, +inf]
        return (offset, _DEFAULT_HI)
    # 守卫上界: if (idx < N) -> hi = N-1
    g = _guard_for_idx(pseudocode, idx_var)
    if g is not None:
        w_lo = offset
        w_hi = scale * (g - 1) + offset
        return (w_lo, w_hi)
    # 无信息: 保守 [0, offset] 或单点
    if scale == 1 and offset == 0:
        return (0, 0)
    return (offset, offset)


def _narrow_write_interval(
    w_lo: int, w_hi: int,
    idx_var: str, scale: int, offset: int, pseudocode: str,
) -> Tuple[int, int, bool]:
    """第二次求值: 守卫代入窄化写偏移区间.
    返回 (narrow_lo, narrow_hi, narrowed).
    """
    narrowed = False
    n_lo, n_hi = w_lo, w_hi
    # 守卫窄化: if (idx < N) 代入 N-1 作为 idx 上界
    g = _guard_for_idx(pseudocode, idx_var)
    if g is not None:
        sub_hi = scale * (g - 1) + offset
        if sub_hi < n_hi:
            n_hi = sub_hi
            narrowed = True
    # clamp 窄化: if (idx > N) idx = N 代入 N 作为 idx 上界
    c = _clamp_for_idx(pseudocode, idx_var)
    if c is not None:
        sub_hi = scale * c + offset
        if sub_hi < n_hi:
            n_hi = sub_hi
            narrowed = True
    return (n_lo, n_hi, narrowed)


_DEFAULT_HI = 2**31 - 1


def _guard_narrow_grade(
    w_lo: int, w_hi: int,
    a_coeff: int, a_const: int, a_var: str,
    idx_var: str, scale: int, offset: int, pseudocode: str,
) -> Optional[Tuple[str, int, int, bool]]:
    """守卫窄化评级: 先求原始区间差, 再守卫代入窄化, 窄化后仍超界才 overflow.
    返回 (verdict, d_lo, d_hi, narrowed).
    """
    # 分配数值化: a_coeff==0 时分配为纯常量 a_const
    if a_coeff == 0:
        alloc = a_const
    elif a_coeff >= 1:
        # malloc(var) 或 malloc(var*K): 分配 = a_coeff*var + a_const
        # 检查循环上界是否为分配变量, 若是则用循环约束做同根系数比较
        loop_bound = _c_loop_bound(pseudocode, idx_var)
        if loop_bound == a_var:
            # 循环 i<var: 写偏移上界 = scale*(var-1)+offset, 分配 = a_coeff*var+a_const
            # 窄化: 守卫代入 var-1, 比较 scale*(var-1)+offset vs a_coeff*var+a_const
            # 系数比较: scale vs a_coeff
            if scale < a_coeff:
                return ("safe", scale - a_coeff, offset - scale - a_const, True)
            if scale > a_coeff:
                return ("overflow", scale - a_coeff, offset - scale - a_const, True)
            # 系数相等: 比较常量 offset-scale vs a_const
            d = (offset - scale) - a_const
            if d > 0:
                return ("overflow", d, d, True)
            if d < 0:
                return ("safe", d, d, True)
            return ("bounded", d, d, True)
        # 循环上界为常量: 写偏移可数值化为 [w_lo, w_hi], 分配仍含变量
        # 若 w_hi 已数值化且 a_coeff*var 中 var 无约束, 保守判定
        if w_hi < _DEFAULT_HI and a_coeff == 1 and a_const == 0:
            # malloc(var): 分配 = var, 写偏移上界数值化但 var 未知
            # 若写偏移上界 > 0 且无守卫约束 var, 保守 overflow
            if w_lo > w_hi:
                return ("safe", 0, 0, False)
            return ("overflow", w_lo, w_hi, False)
        return None
    else:
        return None
    # 第一次差: 原始区间 - 分配
    d_lo = w_lo - alloc
    d_hi = w_hi - alloc
    # 守卫窄化
    n_lo, n_hi, narrowed = _narrow_write_interval(
        w_lo, w_hi, idx_var, scale, offset, pseudocode)
    # 反向区间 (n_lo > n_hi): 守卫使写不可达 => safe
    if n_lo > n_hi:
        return ("safe", n_lo - alloc, n_hi - alloc, narrowed)
    nd_lo = n_lo - alloc
    nd_hi = n_hi - alloc
    # 窄化后上界 < 0: safe
    if nd_hi < 0:
        return ("safe", nd_lo, nd_hi, narrowed)
    # 窄化后下界 > 0: overflow
    if nd_lo > 0:
        return ("overflow", nd_lo, nd_hi, narrowed)
    # 跨越 0: bounded
    return ("bounded", nd_lo, nd_hi, narrowed)


def run_delta_interval_eval(
    pseudocode: str,
    func_name: str,
    existing_findings: Optional[List[dict]] = None,
) -> List[dict]:
    """守卫上界代换二次求值. 返回 findings."""
    findings: List[dict] = []
    # 汇编风格: malloc/calloc/realloc(纯数字)
    m_alloc = re.search(r"(?:malloc|calloc|realloc)\s*\(\s*(\d+)", pseudocode)
    # C 风格分配
    c_alloc = _parse_c_alloc(pseudocode)

    # 汇编风格分支 (仅在存在汇编写地址时生效)
    if m_alloc:
        alloc = int(m_alloc.group(1))
        asm_writes = []
        for ln, line in enumerate(pseudocode.splitlines(), 1):
            m = re.search(r"\[\s*\w+\s*\+\s*(\w+)\s*\]\s*(?:,|=)", line)
            if not m:
                continue
            idx = m.group(1)
            orig_lo, orig_hi = _extract_offset_bounds(pseudocode, line, idx)
            guard = _guard_bound(pseudocode, idx)
            if guard is not None:
                sub_lo = orig_lo
                sub_hi = min(orig_hi, guard - 1)
            else:
                sub_lo = orig_lo
                sub_hi = orig_hi
            d = _delta(sub_lo, sub_hi, alloc)
            verdict = _grade(d)
            narrowed = guard is not None and sub_hi < orig_hi
            asm_writes.append({
                "type": "heap_overflow",
                "function": func_name or "unknown",
                "severity": "medium",
                "cwe": "CWE-122",
                "confidence": 0.85 if narrowed else (0.8 if verdict != "bounded" else 0.5),
                "description": f"line{ln} idx={idx} alloc={alloc} guard={guard} "
                               f"orig=[{orig_lo},{orig_hi}] "
                               f"sub=[{sub_lo},{sub_hi}] "
                               f"delta={d} verdict={verdict} "
                               f"narrowed={narrowed}",
                "verdict": verdict,
                "source": "delta_interval_eval",
            })
        if asm_writes:
            return asm_writes

    # C 风格分支 (汇编分支无写地址或分配为变量时进入)
    if c_alloc is None:
        return findings
    a_var, a_coeff, a_const = c_alloc

    for ln, line in enumerate(pseudocode.splitlines(), 1):
        # C 风格: buf[expr] = value 写语句 (守卫窄化判定)
        m_c = re.search(r"(\w+)\s*\[\s*([^\]]+)\s*\]\s*=\s*", line)
        if m_c:
            idx_expr = m_c.group(2).strip()
            cidx = _parse_c_index_expr(idx_expr)
            if cidx is None:
                continue
            idx_var, scale, offset = cidx
            # 第一次求值: 写偏移原始区间
            w_int = _eval_write_interval(idx_var, scale, offset, pseudocode)
            if w_int is None:
                continue
            w_lo, w_hi = w_int
            # 守卫窄化评级
            gn = _guard_narrow_grade(
                w_lo, w_hi, a_coeff, a_const, a_var,
                idx_var, scale, offset, pseudocode)
            if gn is None:
                continue
            verdict, d_lo, d_hi, narrowed = gn
            if verdict == "bounded":
                continue
            findings.append({
                "type": "heap_overflow",
                "function": func_name or "unknown",
                "severity": "medium",
                "cwe": "CWE-122",
                "confidence": 0.85 if narrowed else (0.8 if verdict == "overflow" else 0.75),
                "description": (
                    f"line{ln} buf[{idx_expr}] idx={idx_var} scale={scale} "
                    f"off={offset} write=[{w_lo},{w_hi}] "
                    f"narrow_delta=({d_lo},{d_hi}) "
                    f"narrowed={narrowed} -> {verdict}"),
                "verdict": verdict,
                "source": "delta_interval_eval",
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
                    # 纯常量: 差 = w - a_const
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
                        "confidence": 0.8 if verdict == "overflow" else 0.75,
                        "description": (
                            f"line{ln} memcpy(buf,src,{w}) "
                            f"alloc={a_const} delta=({d_lo},{d_hi}) "
                            f"-> {verdict}"),
                        "verdict": verdict,
                        "source": "delta_interval_eval",
                    })
            elif re.fullmatch(r"\w+", size_expr) and size_expr == a_var:
                # memcpy 大小 = 分配变量: 差 = 0 -> bounded, 不注入
                continue

    return findings


if __name__ == "__main__":
    demo = """\
p = malloc(64);
if (idx < 32) { mov [p+idx], 0; }
"""
    out = run_delta_interval_eval(demo, "demo")
    for f in out:
        print(f["description"], f["verdict"])