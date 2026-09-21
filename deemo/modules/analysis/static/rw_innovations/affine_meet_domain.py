"""AffineMeetDomain - 仿射 meet 区间域 (stage 99).

区间域 meet/join/widen 仿射语义. 与 widen_threshold (stage 87) 不同:
本模块在仿射表达式 x = a*base + b 上做 meet/join 而非单纯常量区间.
C 风格分支: 真区间交运算 (写侧区间与分配侧区间做交集判定).

设计决策:
  - 从 malloc(N)/calloc(M,N)/realloc(ptr,N) 解析实际分配大小构建分配区间
  - 无分配点时保守使用 [0, 2^31-1] 作为默认区间
  - meet(交): 取两个区间交集, 空 -> 空区间 (矛盾)
  - join(并): 取下界小者, 上界大者 (区间包络)
  - widen: 单边界扩张
  - 仿射表达式映射到区间后再做 meet, 多分配点分别判定
  - C 分支 (新): 写侧/分配侧分别求值成数值区间, 做区间交运算
"""

import re
from typing import Dict, List, Optional, Tuple

# 无分配点时的保守默认上界: 2^31-1 (最大 32 位有符号整数)
_DEFAULT_MAX = 2**31 - 1


def _affine(line: str) -> Optional[Tuple[str, int, str, int]]:
    """解析 var = a*base + b 形式, 返回 (var, a, base_var, b)."""
    m = re.search(r"\b(\w+)\s*=\s*(\d+)\s*\*\s*(\w+)\s*\+\s*(\d+)", line)
    if m:
        return m.group(1), int(m.group(2)), m.group(3), int(m.group(4))
    m = re.search(r"\b(\w+)\s*=\s*(\w+)\s*\+\s*(\d+)", line)
    if m:
        return m.group(1), 1, m.group(2), int(m.group(3))
    return None


def _parse_alloc_sizes(pseudocode: str) -> List[Tuple[str, int]]:
    """从伪代码解析所有分配点的 (变量名, 分配大小).

    malloc(N) -> N
    calloc(M, N) -> M*N
    realloc(ptr, N) -> N
    """
    allocs: List[Tuple[str, int]] = []
    for line in pseudocode.splitlines():
        # malloc(N)
        m = re.search(
            r"\b(\w+)\s*=\s*(?:\([^)]*\)\s*)?malloc\s*\(\s*(\d+)\s*\)", line
        )
        if m:
            allocs.append((m.group(1), int(m.group(2))))
            continue
        # calloc(M, N) -> M*N
        m = re.search(
            r"\b(\w+)\s*=\s*(?:\([^)]*\)\s*)?calloc\s*\(\s*(\d+)\s*,\s*(\d+)\s*\)",
            line,
        )
        if m:
            allocs.append((m.group(1), int(m.group(2)) * int(m.group(3))))
            continue
        # realloc(ptr, N) -> N
        m = re.search(
            r"\b(\w+)\s*=\s*(?:\([^)]*\)\s*)?realloc\s*\(\s*\w+\s*,\s*(\d+)\s*\)",
            line,
        )
        if m:
            allocs.append((m.group(1), int(m.group(2))))
    return allocs


def _meet(a: Tuple[int, int], b: Tuple[int, int]) -> Optional[Tuple[int, int]]:
    """区间 meet: 交集."""
    lo = max(a[0], b[0])
    hi = min(a[1], b[1])
    return (lo, hi) if lo <= hi else None


def _join(a: Tuple[int, int], b: Tuple[int, int]) -> Tuple[int, int]:
    """区间 join: 包络."""
    return (min(a[0], b[0]), max(a[1], b[1]))


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


def _has_mask_op(pseudocode: str, var: str) -> bool:
    """检测变量是否经过位掩码操作 (破坏仿射可表达性)."""
    return bool(re.search(
        r"\b" + re.escape(var) + r"\s*=\s*\([^)]*\)\s*&\s*0x[0-9a-fA-F]+",
        pseudocode,
    ))


# #[DEPRECATED] 旧的线性化逻辑, 由 _interval_meet_eval 替代
def _symbolic_affine(
    idx_var: str, scale: int, offset: int,
    pseudocode: str, alloc_var: str,
) -> Optional[Tuple[int, int]]:
    """将写偏移线性化为 (coeff, const) 关于 alloc_var 的表达式.
    返回 None 表示无法确定 (如掩码破坏仿射性).
    """
    if _has_mask_op(pseudocode, idx_var):
        return None
    if idx_var == alloc_var:
        return (scale, offset)
    bound = _c_loop_bound(pseudocode, idx_var)
    if bound is not None:
        if bound == alloc_var:
            return (scale, offset - scale)
        if re.fullmatch(r"\d+", bound):
            return (0, scale * (int(bound) - 1) + offset)
    m_const = re.search(
        r"\b" + re.escape(idx_var) + r"\s*=\s*(\d+)", pseudocode)
    if m_const:
        return (0, scale * int(m_const.group(1)) + offset)
    m_guard = re.search(
        r"\bif\s*\(\s*" + re.escape(idx_var) + r"\s*<\s*(\d+)\s*\)",
        pseudocode)
    if m_guard:
        return (0, scale * int(m_guard.group(1)) + offset)
    return None


# #[DEPRECATED] 旧的符号 meet 逻辑, 由 _interval_meet_eval 替代
def _symbolic_meet(
    w_coeff: int, w_const: int, a_coeff: int, a_const: int
) -> str:
    """符号 meet: 写偏移区间 [0, w_coeff*var+w_const] 与分配区间 [0, a_coeff*var+a_const].
    返回 affine_bounded 或 affine_top.
    """
    if a_coeff == 0 and w_coeff == 0:
        return "affine_bounded" if w_const <= a_const else "affine_top"
    if a_coeff == 0 or w_coeff == 0:
        return "affine_top"
    if w_coeff < a_coeff:
        return "affine_bounded"
    if w_coeff > a_coeff:
        return "affine_top"
    return "affine_bounded" if w_const <= a_const else "affine_top"


def _eval_write_interval_c(
    idx_var: str, scale: int, offset: int, pseudocode: str,
) -> Optional[Tuple[int, int]]:
    """将写侧表达式求值为数值区间 [wlo, whi].
    常量直接区间; 变量+常量做符号区间; i*K 循环变量做循环区间.
    纯数字索引无法做区间交运算, 返回 None (保守 affine_top).
    """
    # 纯数字索引: 不做区间交运算, 保持保守
    if re.fullmatch(r"\d+", idx_var):
        return None
    # 常量赋值: idx = C
    m_const = re.search(r"\b" + re.escape(idx_var) + r"\s*=\s*(\d+)", pseudocode)
    if m_const:
        v = int(m_const.group(1))
        w = scale * v + offset
        return (w, w)
    # 循环区间: for(i=0;i<N;i++) -> i in [0, N-1]
    bound = _c_loop_bound(pseudocode, idx_var)
    if bound is not None:
        if re.fullmatch(r"\d+", bound):
            b = int(bound)
            wlo = offset
            whi = scale * (b - 1) + offset
            return (min(wlo, whi), max(wlo, whi))
        # 循环上界为变量: 无法数值化
        return None
    # 守卫上界: if(idx < N) -> hi = N-1
    m_guard = re.search(
        r"\bif\s*\(\s*" + re.escape(idx_var) + r"\s*<\s*(\d+)\s*\)", pseudocode)
    if m_guard:
        g = int(m_guard.group(1))
        wlo = offset
        whi = scale * (g - 1) + offset
        return (min(wlo, whi), max(wlo, whi))
    # 无信息: 单点
    w = scale * 0 + offset
    return (w, w)


def _eval_alloc_interval_c(
    a_var: str, a_coeff: int, a_const: int, pseudocode: str,
) -> Optional[Tuple[int, int]]:
    """将分配侧表达式求值为数值区间 [alo, ahi]."""
    if a_coeff == 0:
        return (0, a_const)
    # malloc(var) 或 malloc(var*K): 尝试取变量值
    m_val = re.search(r"\b" + re.escape(a_var) + r"\s*=\s*(\d+)", pseudocode)
    if m_val:
        alloc = a_coeff * int(m_val.group(1)) + a_const
        return (0, alloc)
    # 变量无值: 无法数值化
    return None


def _interval_meet_eval(
    idx_var: str, scale: int, offset: int,
    pseudocode: str, a_var: str, a_coeff: int, a_const: int,
) -> Optional[Tuple[str, str]]:
    """区间交运算判定: 写侧区间与分配侧区间做交集.
    返回 (verdict, detail) 或 None.
    交集非空且 whi < alo -> affine_bounded; 否则 affine_top.
    """
    w_int = _eval_write_interval_c(idx_var, scale, offset, pseudocode)
    a_int = _eval_alloc_interval_c(a_var, a_coeff, a_const, pseudocode)
    # 双侧都无法数值化时, 检查循环上界==分配变量做同根系数比较
    if w_int is None or a_int is None:
        bound = _c_loop_bound(pseudocode, idx_var)
        if bound == a_var:
            # 循环 i<var: 写区间 [offset, scale*(var-1)+offset], 分配 [0, a_coeff*var+a_const]
            # 系数比较: scale vs a_coeff
            if scale < a_coeff:
                return ("affine_bounded",
                        f"loop<{a_var} scale={scale}<a_coeff={a_coeff} interval_meet")
            if scale > a_coeff:
                return ("affine_top",
                        f"loop<{a_var} scale={scale}>a_coeff={a_coeff} interval_meet")
            d = (offset - scale) - a_const
            v = "affine_bounded" if d <= 0 else "affine_top"
            return (v, f"loop<{a_var} coeff_eq d={d} interval_meet")
        # idx==alloc_var: buf[n+8] with malloc(n)
        if idx_var == a_var:
            if scale < a_coeff:
                return ("affine_bounded",
                        f"idx=={a_var} scale={scale}<a_coeff={a_coeff} interval_meet")
            if scale > a_coeff:
                return ("affine_top",
                        f"idx=={a_var} scale={scale}>a_coeff={a_coeff} interval_meet")
            d = offset - a_const
            v = "affine_bounded" if d <= 0 else "affine_top"
            return (v, f"idx=={a_var} coeff_eq d={d} interval_meet")
        return None
    if w_int is None or a_int is None:
        return None
    wlo, whi = w_int
    alo, ahi = a_int
    # 区间交运算
    meet_lo = max(wlo, alo)
    meet_hi = min(whi, ahi)
    if meet_lo <= meet_hi:
        # 交集非空: 写侧落在分配区间内
        if whi < alo:
            return ("affine_bounded", f"write=[{wlo},{whi}] alloc=[{alo},{ahi}] meet=empty whi<alo")
        return ("affine_bounded", f"write=[{wlo},{whi}] alloc=[{alo},{ahi}] meet=[{meet_lo},{meet_hi}]")
    # 交集为空: 写侧超出分配区间
    if whi < alo:
        return ("affine_bounded", f"write=[{wlo},{whi}] alloc=[{alo},{ahi}] meet=empty whi<alo")
    return ("affine_top", f"write=[{wlo},{whi}] alloc=[{alo},{ahi}] meet=empty whi>=alo")


def run_affine_meet_domain(
    pseudocode: str,
    func_name: str,
    existing_findings: Optional[List[dict]] = None,
) -> List[dict]:
    """仿射 meet/join 区间域. 返回 findings."""
    findings: List[dict] = []
    ranges: Dict[str, Tuple[int, int]] = {}
    for line in pseudocode.splitlines():
        m = re.search(r"\b(\w+)\s*=\s*(\d+)", line)
        if m and m.group(1) not in ranges:
            ranges[m.group(1)] = (int(m.group(2)), int(m.group(2)))
    affines = []
    for line in pseudocode.splitlines():
        a = _affine(line)
        if a:
            affines.append(a)
    # 解析实际分配大小, 构建分配区间列表 (汇编风格: 纯数字)
    allocs = _parse_alloc_sizes(pseudocode)
    if allocs:
        alloc_ranges = [(0, size) for _, size in allocs]
    else:
        alloc_ranges = [(0, _DEFAULT_MAX)]

    # C 风格分配解析
    c_alloc = _parse_c_alloc(pseudocode)

    for ln, line in enumerate(pseudocode.splitlines(), 1):
        # 汇编风格: [base+idx] 写地址
        m_asm = re.search(r"\[\s*(\w+)\s*\+\s*(\w+)\s*\]\s*(?:,|=)", line)
        if m_asm:
            var, idx = m_asm.group(1), m_asm.group(2)
            base = ranges.get(idx)
            ex = None
            for name, mult, base_var, const in affines:
                if name == idx:
                    ex = (mult, base_var, const)
                    break
            if ex is None:
                if base is None:
                    continue
                ex = (1, idx, 0)
            if base is None:
                base = ranges.get(ex[1])
            if base is None:
                continue
            lo, hi = base
            wlo = ex[0] * lo + ex[2]
            whi = ex[0] * hi + ex[2]
            wlo, whi = min(wlo, whi), max(wlo, whi)
            merged = _join(ranges.get(var, (wlo, whi)), (wlo, whi))
            best_meet: Optional[Tuple[int, int]] = None
            best_alloc_range: Tuple[int, int] = (0, _DEFAULT_MAX)
            for ar in alloc_ranges:
                meet_result = _meet(merged, ar)
                if meet_result is not None:
                    if best_meet is None or meet_result[1] < best_meet[1]:
                        best_meet = meet_result
                        best_alloc_range = ar
            if best_meet is not None:
                verdict = "affine_bounded"
                meet_str = str(best_meet)
                confidence = 0.75
            else:
                verdict = "affine_top"
                meet_str = "None"
                confidence = 0.3
            findings.append({
                "type": "heap_overflow",
                "function": func_name or "unknown",
                "severity": "medium",
                "cwe": "CWE-122",
                "confidence": confidence,
                "description": f"line{ln} idx={idx} base={base} affine={ex} "
                               f"write=[{wlo},{whi}] alloc={best_alloc_range} "
                               f"meet={meet_str}",
                "verdict": verdict,
                "source": "affine_meet_domain",
            })
            continue

        # C 风格: buf[expr] = value 写语句
        m_c = re.search(r"(\w+)\s*\[\s*([^\]]+)\s*\]\s*=\s*", line)
        if m_c and c_alloc:
            idx_expr = m_c.group(2).strip()
            cidx = _parse_c_index_expr(idx_expr)
            if cidx is None:
                continue
            idx_var, scale, offset = cidx
            a_var, a_coeff, a_const = c_alloc
            # 检测掩码破坏仿射性: 索引变量经过 & 运算
            if _has_mask_op(pseudocode, idx_var):
                verdict = "affine_top"
                confidence = 0.3
                findings.append({
                    "type": "heap_overflow",
                    "function": func_name or "unknown",
                    "severity": "medium",
                    "cwe": "CWE-122",
                    "confidence": confidence,
                    "description": (
                        f"line{ln} buf[{idx_expr}] idx={idx_var} "
                        f"mask_op breaks affine -> {verdict}"),
                    "verdict": verdict,
                    "source": "affine_meet_domain",
                })
                continue
            # 区间交运算判定
            im = _interval_meet_eval(
                idx_var, scale, offset, pseudocode,
                a_var, a_coeff, a_const)
            if im is None:
                verdict = "affine_top"
                confidence = 0.3
                detail = "no_interval"
            else:
                verdict, detail = im
                confidence = 0.75 if verdict == "affine_bounded" else 0.3
            findings.append({
                "type": "heap_overflow",
                "function": func_name or "unknown",
                "severity": "medium",
                "cwe": "CWE-122",
                "confidence": confidence,
                "description": (
                    f"line{ln} buf[{idx_expr}] idx={idx_var} scale={scale} "
                    f"off={offset} {detail} -> {verdict}"),
                "verdict": verdict,
                "source": "affine_meet_domain",
            })
            continue

    return findings


if __name__ == "__main__":
    demo = """\
p = malloc(64);
i = 0;
j = 2 * i + 4;
mov [p+j], 0;
"""
    out = run_affine_meet_domain(demo, "demo")
    for f in out:
        print(f["description"], f["verdict"])
