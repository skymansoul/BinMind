"""WalkStrideModel - 游走步长模型 (stage 78).

p++/p+=k 循环游走写建模 (base + i*stride), stride>1 时按 stride
对齐计算可达上界. 与 scaled_index_linear 不同: 本模块做迭代计数×步长
可达上界, scaled 做 scale 整除性判定.

设计决策:
  - 识别循环游走: p+=k 或 p++ 在循环体内
  - 建模式: 写地址 = base + i*stride
  - stride>1 时上界 = base + (count-1)*stride
  - 上界 <= alloc 大小 -> 安全
  - C 分支 (新): 游走计数×步长可达上界 = (count-1)*stride, 与分配比较
"""

import re
from typing import List, Optional, Tuple


def _extract_loop_count(pseudocode: str) -> int:
    """从循环结构提取迭代次数上限, 找不到则保守返回 1."""
    # for (int i = 0; i < N; i++) 模式
    m_for = re.search(
        r"\bfor\s*\(\s*(?:int\s+)?(\w+)\s*=\s*\d+\s*;\s*\1\s*<\s*(\w+|\d+)",
        pseudocode,
    )
    if m_for:
        bound = m_for.group(2)
        if bound.isdigit():
            return int(bound)
        # 边界为变量时尝试从赋值语句获取值
        m_bound = re.search(rf"\b{re.escape(bound)}\s*=\s*(\d+)", pseudocode)
        if m_bound:
            return int(m_bound.group(1))
    # while (i < N) 或 while (var < N) 模式
    m_while = re.search(r"\bwhile\s*\(\s*(\w+)\s*<\s*(\w+|\d+)", pseudocode)
    if m_while:
        bound = m_while.group(2)
        if bound.isdigit():
            return int(bound)
        m_bound = re.search(rf"\b{re.escape(bound)}\s*=\s*(\d+)", pseudocode)
        if m_bound:
            return int(m_bound.group(1))
    # 无循环结构, 保守单步
    return 1


def _find_stride(pseudocode: str) -> Tuple[str, int, int]:
    """返回 (游走变量, stride, 迭代次数上限)."""
    lines = pseudocode.splitlines()
    stride_var = None
    stride = 1
    for line in lines:
        # 匹配 p += k 模式 (步长为 k)
        m_add = re.search(r"\b(\w+)\s*\+=\s*(\d+)", line)
        if m_add:
            stride_var, stride = m_add.group(1), int(m_add.group(2))
        # 匹配 p++ 模式 (步长为 1)
        m_inc = re.search(r"\b(\w+)\s*\+\+", line)
        if m_inc:
            stride_var = m_inc.group(1)
            stride = 1
    if stride_var is None:
        return "", 1, 0
    # 从循环结构提取迭代次数, 而非从变量赋值
    count = _extract_loop_count(pseudocode)
    return stride_var, stride, count


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


# #[DEPRECATED] 旧的线性化逻辑, 由 _walk_count_reach 替代
def _c_symbolic_reach(
    idx_var: str, scale: int, offset: int,
    pseudocode: str, alloc_var: str,
) -> Optional[Tuple[int, int]]:
    """将写偏移上界线性化为 (coeff, const) 关于 alloc_var 的表达式."""
    if idx_var == alloc_var:
        return (scale, offset)
    bound = _c_loop_bound(pseudocode, idx_var)
    if bound is not None:
        if bound == alloc_var:
            return (scale, offset - scale)
        if re.fullmatch(r"\d+", bound):
            return (0, scale * (int(bound) - 1) + offset)
    m_const = re.search(r"\b" + re.escape(idx_var) + r"\s*=\s*(\d+)", pseudocode)
    if m_const:
        return (0, scale * int(m_const.group(1)) + offset)
    m_guard = re.search(
        r"\bif\s*\(\s*" + re.escape(idx_var) + r"\s*<\s*(\d+)\s*\)", pseudocode)
    if m_guard:
        return (0, scale * int(m_guard.group(1)) + offset)
    return None


# #[DEPRECATED] 旧的系数比较逻辑, 由 _walk_count_reach 替代
def _c_symbolic_compare(w_coeff: int, w_const: int, a_coeff: int, a_const: int) -> str:
    """比较写偏移上界与分配大小, 返回 in_bounds/maybe_overflow/unknown."""
    if a_coeff == 0 and w_coeff == 0:
        return "in_bounds" if w_const <= a_const else "maybe_overflow"
    if a_coeff == 0 or w_coeff == 0:
        return "maybe_overflow"
    if w_coeff > a_coeff:
        return "maybe_overflow"
    if w_coeff < a_coeff:
        return "in_bounds"
    return "maybe_overflow" if w_const >= a_const else "in_bounds"


def _walk_count_and_stride(
    pseudocode: str, idx_var: str, scale: int,
) -> Optional[Tuple[int, int]]:
    """从循环结构提取迭代次数上界与游走步长, 返回 (count, effective_stride).
    有效步长 = scale (索引表达式中的系数), 迭代次数 = 循环上界.
    """
    # 迭代次数: 循环上界
    bound = _c_loop_bound(pseudocode, idx_var)
    if bound is None:
        # 无循环: 单步, count=1
        return (1, scale)
    if re.fullmatch(r"\d+", bound):
        return (int(bound), scale)
    # 循环上界为变量: 尝试取变量值
    m_val = re.search(r"\b" + re.escape(bound) + r"\s*=\s*(\d+)", pseudocode)
    if m_val:
        return (int(m_val.group(1)), scale)
    # 变量上界无值: 保守返回大数
    return (None, scale)


def _walk_count_reach(
    idx_var: str, scale: int, offset: int,
    pseudocode: str, a_var: str, a_coeff: int, a_const: int,
) -> Optional[Tuple[str, int, int]]:
    """游走计数×步长可达上界判定.
    返回 (verdict, reach, alloc_val) 或 None.
    核心思路: 可达偏移上界 = (count-1)*stride + offset, 与分配比较.
    """
    cs = _walk_count_and_stride(pseudocode, idx_var, scale)
    if cs is None:
        return None
    count, eff_stride = cs
    if count is None:
        # 循环上界为未知变量: 若上界==分配变量, 保守 maybe_overflow
        bound = _c_loop_bound(pseudocode, idx_var)
        if bound == a_var:
            # 循环 i<var, 写 = scale*(var-1)+offset, 分配 = a_coeff*var+a_const
            if scale > a_coeff:
                return ("maybe_overflow", scale, a_coeff)
            if scale < a_coeff:
                return ("in_bounds", scale, a_coeff)
            d = offset - a_const
            return ("in_bounds" if d <= 0 else "maybe_overflow", scale, a_coeff)
        return None
    # 可达上界 = (count-1)*eff_stride + offset
    reach = (count - 1) * eff_stride + offset
    # 分配数值化
    if a_coeff == 0:
        alloc = a_const
        if reach < alloc:
            return ("in_bounds", reach, alloc)
        return ("maybe_overflow", reach, alloc)
    # 变量分配: 尝试从赋值获取变量值
    m_val = re.search(r"\b" + re.escape(a_var) + r"\s*=\s*(\d+)", pseudocode)
    if m_val:
        alloc = a_coeff * int(m_val.group(1)) + a_const
        if reach < alloc:
            return ("in_bounds", reach, alloc)
        return ("maybe_overflow", reach, alloc)
    # 无变量值: idx==alloc_var 时同根比较
    if idx_var == a_var:
        if scale < a_coeff:
            return ("in_bounds", scale, a_coeff)
        if scale > a_coeff:
            return ("maybe_overflow", scale, a_coeff)
        d = offset - a_const
        return ("in_bounds" if d <= 0 else "maybe_overflow", scale, a_coeff)
    return None


def run_walk_stride_model(
    pseudocode: str,
    func_name: str,
    existing_findings: Optional[List[dict]] = None,
) -> List[dict]:
    """游走步长模型. 返回 findings."""
    findings: List[dict] = []
    var, stride, count = _find_stride(pseudocode)
    # 汇编风格: malloc(纯数字)
    alloc_size = None
    m_alloc = re.search(r"malloc\s*\(\s*(\d+)\s*\)", pseudocode)
    if m_alloc:
        alloc_size = int(m_alloc.group(1))
    # C 风格: malloc(变量/表达式)
    c_alloc = _parse_c_alloc(pseudocode)

    for ln, line in enumerate(pseudocode.splitlines(), 1):
        # 汇编风格: [base+idx] 写地址
        m_asm = re.search(r"\[\s*(\w+)\s*\+\s*(\w+)\s*\]\s*(?:,|=)", line)
        if m_asm:
            base, idx = m_asm.group(1), m_asm.group(2)
            if not var or var not in (base, idx):
                pass
            else:
                if count >= 2:
                    reach = (count - 1) * stride
                else:
                    reach = stride
                if alloc_size is not None and reach < alloc_size:
                    verdict, conf = "in_bounds", 0.85
                else:
                    verdict, conf = "maybe_overflow", 0.5
                findings.append({
                    "type": "heap_overflow",
                    "function": func_name or "unknown",
                    "severity": "medium",
                    "cwe": "CWE-122",
                    "confidence": conf,
                    "description": f"line{ln} base={base} stride={stride} "
                                   f"count={count} reach={reach} alloc={alloc_size}",
                    "verdict": verdict,
                    "source": "walk_stride_model",
                })
                continue

        # C 风格: buf[expr] = value 写语句 (游走计数×步长可达上界判定)
        m_c = re.search(r"(\w+)\s*\[\s*([^\]]+)\s*\]\s*=\s*", line)
        if m_c and c_alloc:
            idx_expr = m_c.group(2).strip()
            cidx = _parse_c_index_expr(idx_expr)
            if cidx is None:
                continue
            idx_var, scale, offset = cidx
            a_var, a_coeff, a_const = c_alloc
            wr = _walk_count_reach(
                idx_var, scale, offset, pseudocode,
                a_var, a_coeff, a_const)
            if wr is None:
                verdict, conf = "maybe_overflow", 0.5
                detail = "no_count"
            else:
                verdict, reach, alloc_val = wr
                conf = 0.85 if verdict == "in_bounds" else 0.5
                detail = f"reach={reach} alloc={alloc_val}"
            findings.append({
                "type": "heap_overflow",
                "function": func_name or "unknown",
                "severity": "medium",
                "cwe": "CWE-122",
                "confidence": conf,
                "description": (
                    f"line{ln} buf[{idx_expr}] idx={idx_var} stride={scale} "
                    f"off={offset} {detail} -> {verdict}"),
                "verdict": verdict,
                "source": "walk_stride_model",
            })
            continue

        # C 风格: memcpy(buf, src, size) 写语句
        m_mc = re.search(
            r"memcpy\s*\(\s*(\w+)\s*,\s*\w+\s*,\s*([^)]+)\s*\)", line)
        if m_mc and c_alloc:
            size_expr = m_mc.group(2).strip()
            a_var, a_coeff, a_const = c_alloc
            if re.fullmatch(r"\d+", size_expr):
                # 常量写入大小: 直接数值比较
                w_const = int(size_expr)
                if a_coeff == 0:
                    verdict = "in_bounds" if w_const <= a_const else "maybe_overflow"
                else:
                    verdict = "maybe_overflow"
                conf = 0.85 if verdict == "in_bounds" else 0.5
            elif re.fullmatch(r"\w+", size_expr):
                # 变量写入大小: 与分配变量做符号比较
                if size_expr == a_var:
                    verdict = "in_bounds"
                    conf = 0.85
                else:
                    verdict = "maybe_overflow"
                    conf = 0.5
            else:
                verdict = "maybe_overflow"
                conf = 0.5
            findings.append({
                "type": "heap_overflow",
                "function": func_name or "unknown",
                "severity": "medium",
                "cwe": "CWE-122",
                "confidence": conf,
                "description": (
                    f"line{ln} memcpy(buf,src,{size_expr}) -> {verdict}"),
                "verdict": verdict,
                "source": "walk_stride_model",
            })
            continue

    return findings


if __name__ == "__main__":
    demo = """\
p = malloc(64);
for (int i = 0; i < 8; i++) {
    p++;
    mov [p+i], 0;
}
"""
    out = run_walk_stride_model(demo, "demo")
    for f in out:
        print(f["description"], f["verdict"])