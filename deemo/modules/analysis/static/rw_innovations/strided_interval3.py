"""StridedInterval3 - 三元组跨步区间 (stage 95).

lo/hi/stride 三元组域, 加法/乘法/widening 全套运算, write 在 stride
域内判定. 与 value_flow_engine.StridedInterval 不同: 独立完整域
实现 (带 widening 与 join).

设计决策:
  - 三元组 (lo, hi, stride): 表示 {lo, lo+stride, ..., hi}
  - add: (lo1+lo2, hi1+hi2, gcd(stride1,stride2))
  - mul: 常量乘
  - widening: 边界扩张
  - join: 取并集区间 (stride 取 gcd)
"""

import math
import re
from typing import List, Optional, Tuple


class StridedInterval3:
    """三元组跨步区间域."""

    def __init__(self, lo: int, hi: int, stride: int = 1):
        self.lo = lo
        self.hi = hi
        self.stride = stride

    def add(self, other: "StridedInterval3") -> "StridedInterval3":
        return StridedInterval3(
            self.lo + other.lo, self.hi + other.hi,
            math.gcd(self.stride, other.stride))

    def mul(self, k: int) -> "StridedInterval3":
        return StridedInterval3(self.lo * k, self.hi * k,
                                self.stride * k)

    def widen(self, other: "StridedInterval3") -> "StridedInterval3":
        lo = self.lo if self.lo <= other.lo else other.lo
        hi = self.hi if self.hi >= other.hi else other.hi
        stride = math.gcd(self.stride, other.stride)
        return StridedInterval3(lo, hi, stride)

    def join(self, other: "StridedInterval3") -> "StridedInterval3":
        # 并集区间: lo 取最小, hi 取最大, stride 取 gcd
        lo = min(self.lo, other.lo)
        hi = max(self.hi, other.hi)
        stride = math.gcd(self.stride, other.stride)
        return StridedInterval3(lo, hi, stride)

    def contains(self, v: int) -> bool:
        if not (self.lo <= v <= self.hi):
            return False
        if self.stride == 0:
            return v == self.lo
        return (v - self.lo) % self.stride == 0

    def __repr__(self) -> str:
        return f"SI({self.lo},{self.hi},{self.stride})"


def _extract_idx_range(pseudocode: str, idx: str) -> Tuple[int, int]:
    """提取索引变量区间 (lo, hi)."""
    lo = 0
    hi = 0
    # 常量赋值: idx = N
    m_def = re.search(r"\b" + re.escape(idx) + r"\s*=\s*(\d+)\s*;", pseudocode)
    if m_def:
        v = int(m_def.group(1))
        return (v, v)
    # 循环增量: idx++ 或 idx += K => 递增模式, 用 widen 扩展
    m_inc = re.search(r"\b" + re.escape(idx) + r"\s*\+\+|\b" +
                      re.escape(idx) + r"\s*\+=\s*(\d+)", pseudocode)
    if m_inc:
        step = int(m_inc.group(1)) if m_inc.group(1) else 1
        # 循环上界: if (idx < N) 或 for (idx = 0; idx < N; ...)
        m_bound = re.search(r"\b" + re.escape(idx) + r"\s*<\s*(\d+)", pseudocode)
        if m_bound:
            hi = int(m_bound.group(1)) - 1
        else:
            hi = 63  # 无显式上界时给保守估计
        return (lo, hi)
    # 无定义信息
    return (0, 0)


def _extract_scale(line: str) -> int:
    """从写偏移模式 [base+idx*scale] 或 [base+idx] 提取 scale."""
    m = re.search(r"\[\s*\w+\s*\+\s*\w+\s*\*\s*(\d+)\s*\]", line)
    if m:
        return int(m.group(1))
    return 1


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


def _symbolic_domain(
    idx_var: str, scale: int, offset: int,
    pseudocode: str, a_var: str, a_coeff: int, a_const: int,
) -> str:
    """判定写区间三元组是否在分配区间内, 返回 in_domain/out_domain/unknown."""
    if idx_var == a_var:
        # 索引变量即分配变量: 写偏移 = scale*var+offset
        # 写区间 [offset, scale*var+offset], 分配区间 [0, a_coeff*var+a_const]
        if a_coeff == scale and offset <= a_const:
            return "in_domain"
        if a_coeff == 0 and scale == 0:
            return "in_domain" if offset <= a_const else "out_domain"
        if scale > a_coeff:
            return "out_domain"
        if scale < a_coeff:
            return "in_domain"
        return "in_domain" if offset <= a_const else "out_domain"
    bound = _c_loop_bound(pseudocode, idx_var)
    if bound is not None:
        if bound == a_var:
            # i in [0,var-1]: 写区间 [offset, scale*(var-1)+offset]
            # 写上界 = scale*var + (offset-scale), 分配上界 = a_coeff*var + a_const
            if scale < a_coeff:
                return "in_domain"
            if scale > a_coeff:
                return "out_domain"
            return "in_domain" if (offset - scale) <= a_const else "out_domain"
        if re.fullmatch(r"\d+", bound):
            b = int(bound)
            w_hi = scale * (b - 1) + offset
            if a_coeff == 0:
                return "in_domain" if (offset >= 0 and w_hi < a_const) else "out_domain"
            return "out_domain"
    m_const = re.search(
        r"\b" + re.escape(idx_var) + r"\s*=\s*(\d+)", pseudocode)
    if m_const:
        v = int(m_const.group(1))
        w = scale * v + offset
        if a_coeff == 0:
            return "in_domain" if w <= a_const else "out_domain"
        return "out_domain"
    return "unknown"


def run_strided_interval3(
    pseudocode: str,
    func_name: str,
    existing_findings: Optional[List[dict]] = None,
) -> List[dict]:
    """三元组跨步区间域运算包含判定. 返回 findings."""
    findings: List[dict] = []
    alloc_size = None
    # 汇编风格: malloc(纯数字)
    m_alloc = re.search(r"malloc\s*\(\s*(\d+)\s*\)", pseudocode)
    if m_alloc:
        alloc_size = int(m_alloc.group(1))
    # C 风格分配
    c_alloc = _parse_c_alloc(pseudocode)

    write_intervals: List[StridedInterval3] = []
    asm_writes: List[dict] = []

    for ln, line in enumerate(pseudocode.splitlines(), 1):
        # 汇编风格: [base+idx] 或 [base+idx*scale]
        m_asm = re.search(
            r"\[\s*(\w+)\s*\+\s*(\w+)(?:\s*\*\s*(\d+))?\s*\]\s*(?:,|=)", line)
        if m_asm:
            base_var = m_asm.group(1)
            idx_var = m_asm.group(2)
            scale = int(m_asm.group(3)) if m_asm.group(3) else 1
            base_lo, base_hi = 0, 0
            m_base = re.search(r"\b" + re.escape(base_var) + r"\s*=\s*(\d+)", pseudocode)
            if m_base:
                base_lo = base_hi = int(m_base.group(1))
            base_si = StridedInterval3(base_lo, base_hi, 1)
            idx_lo, idx_hi = _extract_idx_range(pseudocode, idx_var)
            idx_si = StridedInterval3(idx_lo, idx_hi, 1)
            scaled_si = idx_si.mul(scale)
            write_si = base_si.add(scaled_si)
            m_inc = re.search(r"\b" + re.escape(idx_var) + r"\s*\+\+|\b" +
                              re.escape(idx_var) + r"\s*\+=", pseudocode)
            if m_inc:
                widened_idx = idx_si.widen(
                    StridedInterval3(idx_hi, idx_hi + 64, 1))
                widened_scaled = widened_idx.mul(scale)
                write_si = base_si.add(widened_scaled)
            write_intervals.append(write_si)
            if alloc_size is not None:
                if write_si.lo >= 0 and write_si.hi < alloc_size:
                    verdict, conf = "in_domain", 0.85
                elif write_si.lo >= alloc_size or write_si.hi >= alloc_size:
                    verdict, conf = "out_domain", 0.7
                else:
                    verdict, conf = "unknown", 0.4
            else:
                verdict, conf = "unknown", 0.4
            # 汇编分支: in_domain 注入, out_domain/unknown 不注入
            if verdict == "in_domain":
                asm_writes.append({
                    "type": "heap_overflow",
                    "function": func_name or "unknown",
                    "severity": "medium",
                    "cwe": "CWE-122",
                    "confidence": conf,
                    "description": f"line{ln} base={base_si} idx={idx_si} "
                                   f"scaled={scaled_si} write={write_si} "
                                   f"alloc={alloc_size}",
                    "verdict": verdict,
                    "source": "strided_interval3",
                })
            continue

    # 汇编 join 运算: 多写点合并
    if len(write_intervals) > 1 and alloc_size is not None:
        total = write_intervals[0]
        for wi in write_intervals[1:]:
            total = total.join(wi)
        if total.lo >= 0 and total.hi < alloc_size:
            asm_writes.append({
                "type": "heap_overflow",
                "function": func_name or "unknown",
                "severity": "info",
                "cwe": "CWE-122",
                "confidence": 0.6,
                "description": f"join_all write_intervals total={total} "
                               f"alloc={alloc_size} in_domain",
                "verdict": "in_domain",
                "source": "strided_interval3",
            })
    if asm_writes:
        return asm_writes

    # C 风格分支
    if c_alloc is None:
        return findings
    a_var, a_coeff, a_const = c_alloc
    # 枚举全部 C 风格写点, 任一 out_domain 则不产 in_domain (避免压真)
    c_write_points: List[Tuple[int, str, str]] = []

    for ln, line in enumerate(pseudocode.splitlines(), 1):
        # C 风格: buf[expr] = value 写语句
        m_c = re.search(r"(\w+)\s*\[\s*([^\]]+)\s*\]\s*=\s*", line)
        if m_c:
            idx_expr = m_c.group(2).strip()
            cidx = _parse_c_index_expr(idx_expr)
            if cidx is None:
                continue
            idx_var, scale, offset = cidx
            verdict = _symbolic_domain(
                idx_var, scale, offset, pseudocode,
                a_var, a_coeff, a_const)
            c_write_points.append((ln, idx_expr, verdict))
            continue

        # C 风格: memcpy(buf, src, size) 写语句
        m_mc = re.search(
            r"memcpy\s*\(\s*(\w+)\s*,\s*\w+\s*,\s*([^)]+)\s*\)", line)
        if m_mc:
            size_expr = m_mc.group(2).strip()
            if re.fullmatch(r"\d+", size_expr):
                w = int(size_expr)
                if a_coeff == 0:
                    verdict = "in_domain" if w <= a_const else "out_domain"
                else:
                    verdict = "out_domain"
            elif re.fullmatch(r"\w+", size_expr) and size_expr == a_var:
                verdict = "in_domain"
            else:
                verdict = "out_domain"
            c_write_points.append((ln, f"memcpy size={size_expr}", verdict))

    # 全部写点 in_domain 才产结论, 任一 out_domain 则不产 (避免压真)
    if not c_write_points or not all(
            wp[2] == "in_domain" for wp in c_write_points):
        return findings
    for ln, expr_str, verdict in c_write_points:
        findings.append({
            "type": "heap_overflow",
            "function": func_name or "unknown",
            "severity": "medium",
            "cwe": "CWE-122",
            "confidence": 0.85,
            "description": (
                f"line{ln} {expr_str} -> {verdict}"),
            "verdict": verdict,
            "source": "strided_interval3",
        })

    return findings


if __name__ == "__main__":
    demo = """\
p = malloc(64);
i = 8;
mov [p+i], 0;
"""
    out = run_strided_interval3(demo, "demo")
    for f in out:
        print(f["description"], f["verdict"])