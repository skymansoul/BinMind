"""ScaledIndexLinear - scaled-index 线性化 (stage 62).

对 [base+idx*scale+off] 写地址做 scale 相容性判定, 若 idx 的
区间宽度可整除 scale 且 end = off + hi*scale 落在分配内则安全.
C 风格分支: 步长整除性 + 槽位对齐判定 (buf[i*K] 的 K 是否整除分配宽度).
与 walk_stride_model 不同: 本模块做 scale 整除性数学, walk 做游走计数.

设计决策:
  - 解析写地址 [base + idx*scale + off]
  - base 是变量名(字符串), 不参与数值运算; 实际越界比较用 off + hi*scale
  - idx 区间估计: 常量赋值 -> [v,v]; 守卫 if(idx<N) -> hi=N; 否则保守默认
  - end = off + hi * scale; end <= alloc_size -> safe; end > alloc_size -> overflow
  - 无 alloc_size 或 scale 不整除 -> unknown
  - C 分支 (新): 步长整除性判定 + 槽位对齐 (写点是否落在对齐槽位上)
"""

import re
from typing import List, Optional, Tuple


def _parse_indexed(addr: str) -> Optional[Tuple[str, str, int, int]]:
    """解析 [base + idx*scale + off] -> (base, idx, scale, off).
    base 为变量名(字符串), 仅用于标识, 不参与数值运算.
    """
    m = re.fullmatch(
        r"\s*(\w+)\s*\+\s*(\w+)\s*\*\s*(\d+)\s*\+\s*(-?\d+)\s*", addr)
    if m:
        return m.group(1), m.group(2), int(m.group(3)), int(m.group(4))
    m2 = re.fullmatch(r"\s*(\w+)\s*\+\s*(\w+)\s*\*\s*(\d+)\s*", addr)
    if m2:
        return m2.group(1), m2.group(2), int(m2.group(3)), 0
    return None


def _estimate_idx_bounds(
    pseudocode: str, idx: str, alloc_size: Optional[int], scale: int
) -> Tuple[int, int]:
    """估计 idx 的区间 [lo, hi].
    优先级: 常量赋值 > 守卫上界 > 保守默认.
    """
    # 常量赋值: idx = C
    m_idx = re.search(r"\b" + re.escape(idx) + r"\s*=\s*(\d+)", pseudocode)
    if m_idx:
        v = int(m_idx.group(1))
        return v, v
    # 守卫上界: if (idx < N) 提取 N 作为 hi
    m_guard = re.search(
        r"\bif\s*\(\s*" + re.escape(idx) + r"\s*<\s*(\d+)\s*\)", pseudocode
    )
    if m_guard:
        n = int(m_guard.group(1))
        return 0, n
    # 保守默认: alloc_size // scale
    default_hi = (alloc_size // scale) if alloc_size and scale else 0
    return 0, default_hi


def _parse_c_alloc(pseudocode: str) -> Optional[Tuple[str, int, int]]:
    """解析 C 风格 malloc 表达式 -> (var, coeff, const).
    malloc(64) -> ('', 0, 64); malloc(n) -> ('n', 1, 0); malloc(n*4) -> ('n', 4, 0).
    """
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
    """解析 C 风格索引表达式 -> (idx_var, scale, offset).
    n+8 -> ('n',1,8); i*8 -> ('i',8,0); i -> ('i',1,0).
    """
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


def _parse_c_loop_bound(pseudocode: str, idx: str) -> Optional[str]:
    """解析 for(idx=0; idx<bound; idx++) -> bound (变量名或数字字符串)."""
    m = re.search(
        r"for\s*\(\s*(?:int\s+)?\w+\s*=\s*\d+\s*;\s*"
        + re.escape(idx) + r"\s*<\s*(\w+)\s*;",
        pseudocode,
    )
    return m.group(1) if m else None


# #[DEPRECATED] 旧的线性化逻辑, 由 _scale_divisibility_eval 替代
def _symbolic_end(
    idx_var: str, scale: int, offset: int,
    pseudocode: str, alloc_var: str,
) -> Optional[Tuple[int, int]]:
    """将写偏移线性化为 (coeff, const) 关于 alloc_var 的表达式.
    返回 None 表示无法确定.
    """
    if idx_var == alloc_var:
        # 索引变量即分配变量: write_end = scale*alloc_var + offset
        return (scale, offset)
    bound = _parse_c_loop_bound(pseudocode, idx_var)
    if bound is not None:
        if bound == alloc_var:
            # 循环上界为分配变量: max_idx = alloc_var-1
            return (scale, offset - scale)
        if re.fullmatch(r"\d+", bound):
            # 常量上界: write_end = scale*(bound-1) + offset
            return (0, scale * (int(bound) - 1) + offset)
    m_const = re.search(r"\b" + re.escape(idx_var) + r"\s*=\s*(\d+)", pseudocode)
    if m_const:
        return (0, scale * int(m_const.group(1)) + offset)
    m_guard = re.search(
        r"\bif\s*\(\s*" + re.escape(idx_var) + r"\s*<\s*(\d+)\s*\)",
        pseudocode)
    if m_guard:
        return (0, scale * int(m_guard.group(1)) + offset)
    return None


# #[DEPRECATED] 旧的系数比较逻辑, 由 _scale_divisibility_eval 替代
def _symbolic_compare(
    w_coeff: int, w_const: int, a_coeff: int, a_const: int
) -> str:
    """比较 write_end = w_coeff*var + w_const 与 alloc = a_coeff*var + a_const.
    返回 'overflow', 'safe' 或 'unknown'.
    """
    if a_coeff == 0 and w_coeff == 0:
        return "safe" if w_const <= a_const else "overflow"
    if a_coeff == 0 or w_coeff == 0:
        return "unknown"
    if w_coeff > a_coeff:
        return "overflow"
    if w_coeff < a_coeff:
        return "safe"
    return "overflow" if w_const > a_const else "safe"


def _idx_numeric_bound(pseudocode: str, idx_var: str) -> Optional[int]:
    """获取 idx 的数值上界 (常量赋值/循环上界/守卫上界)."""
    m_const = re.search(r"\b" + re.escape(idx_var) + r"\s*=\s*(\d+)", pseudocode)
    if m_const:
        return int(m_const.group(1))
    bound = _parse_c_loop_bound(pseudocode, idx_var)
    if bound is not None and re.fullmatch(r"\d+", bound):
        return int(bound) - 1
    m_guard = re.search(
        r"\bif\s*\(\s*" + re.escape(idx_var) + r"\s*<\s*(\d+)\s*\)", pseudocode)
    if m_guard:
        return int(m_guard.group(1)) - 1
    return None


def _scale_divisibility_eval(
    idx_var: str, scale: int, offset: int,
    pseudocode: str, a_var: str, a_coeff: int, a_const: int,
) -> Optional[Tuple[str, str]]:
    """步长整除性 + 槽位对齐判定.
    返回 (verdict, detail) 或 None.
    核心思路: buf[i*K] 中 K(scale) 是否整除分配宽度, 写点是否落在对齐槽位上.
    """
    # 写偏移 = scale * idx + offset
    # 分配 = a_coeff * a_var + a_const
    if a_coeff == 0:
        # 纯常量分配: 直接做整除性 + 数值比较
        alloc = a_const
        if scale > 0 and alloc > 0:
            # 整除性: 分配宽度是否能被 scale 整除
            divisible = (alloc % scale == 0) if scale != 0 else False
            idx_hi = _idx_numeric_bound(pseudocode, idx_var)
            if idx_hi is not None:
                # 写偏移上界 = scale * idx_hi + offset
                w_end = scale * idx_hi + offset
                # 槽位对齐: 写偏移是否能被 scale 整除 (offset 是否对齐)
                slot_aligned = (offset % scale == 0) if scale != 0 else True
                if w_end < alloc:
                    return ("safe", f"divisible={divisible} slot_aligned={slot_aligned} w_end={w_end}<alloc={alloc}")
                if w_end >= alloc:
                    return ("overflow", f"divisible={divisible} slot_aligned={slot_aligned} w_end={w_end}>=alloc={alloc}")
            # idx 上界未知但有循环上界 = 分配变量
            bound = _parse_c_loop_bound(pseudocode, idx_var)
            if bound == a_var:
                return ("overflow", f"loop<{a_var} scale={scale} no_const_bound")
            return ("unknown", f"divisible={divisible} no_idx_bound")
        return None
    # 变量分配: malloc(var) 或 malloc(var*K)
    # 整除性: scale 是否整除 a_coeff (分配单位宽度)
    if a_coeff > 0 and scale > 0:
        # 循环上界 == 分配变量: i < var, 写 = scale*(var-1)+offset
        bound = _parse_c_loop_bound(pseudocode, idx_var)
        if bound == a_var:
            # 写系数 = scale, 分配系数 = a_coeff
            # 整除性: scale 能否整除 a_coeff (如 scale=1, a_coeff=4 -> 整除)
            divisible = (a_coeff % scale == 0) if scale <= a_coeff else (scale % a_coeff == 0)
            if scale < a_coeff:
                return ("safe", f"divisible={divisible} scale={scale}<a_coeff={a_coeff}")
            if scale > a_coeff:
                return ("overflow", f"divisible={divisible} scale={scale}>a_coeff={a_coeff}")
            # 系数相等: 比较常量
            d = offset - a_const
            if d <= 0:
                return ("safe", f"divisible={divisible} coeff_eq d={d}")
            return ("overflow", f"divisible={divisible} coeff_eq d={d}")
        # idx 直接 == 分配变量: buf[n+8] with malloc(n)
        if idx_var == a_var:
            # 写 = scale*var + offset, 分配 = a_coeff*var + a_const
            if scale < a_coeff:
                return ("safe", f"idx==alloc_var scale={scale}<a_coeff={a_coeff}")
            if scale > a_coeff:
                return ("overflow", f"idx==alloc_var scale={scale}>a_coeff={a_coeff}")
            d = offset - a_const
            if d <= 0:
                return ("safe", f"idx==alloc_var coeff_eq d={d}")
            return ("overflow", f"idx==alloc_var coeff_eq d={d}")
        return ("unknown", f"var_alloc scale={scale} a_coeff={a_coeff} no_loop")
    return None


def run_scaled_index_linear(
    pseudocode: str,
    func_name: str,
    existing_findings: Optional[List[dict]] = None,
) -> List[dict]:
    """scaled-index 线性化判定. 返回 findings."""
    findings: List[dict] = []
    alloc_size: Optional[int] = None
    # 汇编风格: malloc(纯数字)
    m_alloc = re.search(r"malloc\s*\(\s*(\d+)\s*\)", pseudocode)
    if m_alloc:
        alloc_size = int(m_alloc.group(1))
    # C 风格: malloc(变量/表达式)
    c_alloc = _parse_c_alloc(pseudocode)

    for ln, line in enumerate(pseudocode.splitlines(), 1):
        # 汇编风格: [base + idx*scale + off] 写地址
        m_asm = re.search(r"\[([^\]]+)\]\s*[,=]", line)
        if m_asm:
            parsed = _parse_indexed(m_asm.group(1))
            if parsed:
                base, idx, scale, off = parsed
                lo, hi = _estimate_idx_bounds(pseudocode, idx, alloc_size, scale)
                width = hi - lo + 1
                is_const_idx = (lo == hi)
                if alloc_size is not None:
                    if is_const_idx:
                        end = off + hi * scale
                    elif width % scale == 0:
                        end = off + hi * scale
                    else:
                        end = None
                    verdict = "safe" if end is not None and end <= alloc_size else (
                        "overflow" if end is not None else "unknown")
                else:
                    end = None
                    verdict = "unknown"
                findings.append({
                    "type": "heap_overflow",
                    "function": func_name or "unknown",
                    "severity": "medium",
                    "cwe": "CWE-122",
                    "confidence": 0.9 if verdict == "safe" else (
                        0.7 if verdict == "overflow" else 0.4),
                    "description": (
                        f"line{ln} [base={base} idx={idx} scale={scale} "
                        f"off={off}] width={width} end="
                        f"{end if end is not None else '?'} -> {verdict}"),
                    "verdict": verdict,
                    "source": "scaled_index_linear",
                })
                continue

        # C 风格: buf[expr] = value 写语句 (步长整除性+槽位对齐判定)
        m_c = re.search(r"(\w+)\s*\[\s*([^\]]+)\s*\]\s*=\s*", line)
        if m_c and c_alloc:
            idx_expr = m_c.group(2).strip()
            cidx = _parse_c_index_expr(idx_expr)
            if cidx is None:
                continue
            idx_var, scale, offset = cidx
            a_var, a_coeff, a_const = c_alloc
            # 步长整除性 + 槽位对齐判定
            sd = _scale_divisibility_eval(
                idx_var, scale, offset, pseudocode,
                a_var, a_coeff, a_const)
            if sd is None:
                verdict = "unknown"
                detail = "no_eval"
            else:
                verdict, detail = sd
            findings.append({
                "type": "heap_overflow",
                "function": func_name or "unknown",
                "severity": "medium",
                "cwe": "CWE-122",
                "confidence": 0.9 if verdict == "safe" else (
                    0.7 if verdict == "overflow" else 0.4),
                "description": (
                    f"line{ln} buf[{idx_expr}] idx={idx_var} scale={scale} "
                    f"off={offset} {detail} -> {verdict}"),
                "verdict": verdict,
                "source": "scaled_index_linear",
            })
            continue

    return findings


if __name__ == "__main__":
    demo = """\
p = malloc(128);
idx = 2;
mov [p + idx*8 + 0], 0;
"""
    out = run_scaled_index_linear(demo, "demo")
    for item in out:
        print(item["description"], item["verdict"])