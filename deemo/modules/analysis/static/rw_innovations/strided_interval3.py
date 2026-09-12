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


def run_strided_interval3(
    pseudocode: str,
    func_name: str,
    existing_findings: Optional[List[dict]] = None,
) -> List[dict]:
    """三元组跨步区间域运算包含判定. 返回 findings."""
    findings: List[dict] = []
    alloc_size = None
    m_alloc = re.search(r"malloc\s*\(\s*(\d+)\s*\)", pseudocode)
    if m_alloc:
        alloc_size = int(m_alloc.group(1))

    write_intervals: List[StridedInterval3] = []

    for ln, line in enumerate(pseudocode.splitlines(), 1):
        # 匹配 [base+idx] 或 [base+idx*scale]
        m = re.search(r"\[\s*(\w+)\s*\+\s*(\w+)(?:\s*\*\s*(\d+))?\s*\]\s*(?:,|=)", line)
        if not m:
            continue
        base_var = m.group(1)
        idx_var = m.group(2)
        scale = int(m.group(3)) if m.group(3) else 1

        # base 区间: 默认 [0,0] (指针起点)
        base_lo, base_hi = 0, 0
        m_base = re.search(r"\b" + re.escape(base_var) + r"\s*=\s*(\d+)", pseudocode)
        if m_base:
            base_lo = base_hi = int(m_base.group(1))
        base_si = StridedInterval3(base_lo, base_hi, 1)

        # idx 区间
        idx_lo, idx_hi = _extract_idx_range(pseudocode, idx_var)
        idx_si = StridedInterval3(idx_lo, idx_hi, 1)

        # mul 运算: idx 区间乘以 scale
        scaled_si = idx_si.mul(scale)

        # add 运算: base 区间 + scaled 区间 = 写地址区间
        write_si = base_si.add(scaled_si)

        # widen 运算: 若循环递增, 对 idx 做 widen 得到完整循环区间
        m_inc = re.search(r"\b" + re.escape(idx_var) + r"\s*\+\+|\b" +
                          re.escape(idx_var) + r"\s*\+=", pseudocode)
        if m_inc:
            widened_idx = idx_si.widen(
                StridedInterval3(idx_hi, idx_hi + 64, 1))
            widened_scaled = widened_idx.mul(scale)
            write_si = base_si.add(widened_scaled)

        write_intervals.append(write_si)

        # join 运算: 合并所有写区间得到总写区间
        # 判定: 写区间与分配区间比较
        if alloc_size is not None:
            if write_si.lo >= 0 and write_si.hi < alloc_size:
                verdict, conf = "in_domain", 0.85
            elif write_si.lo >= alloc_size or write_si.hi >= alloc_size:
                verdict, conf = "out_domain", 0.7
            else:
                verdict, conf = "unknown", 0.4
        else:
            verdict, conf = "unknown", 0.4

        findings.append({
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

    # join 运算: 多写点合并
    if len(write_intervals) > 1:
        total = write_intervals[0]
        for wi in write_intervals[1:]:
            total = total.join(wi)
        if alloc_size is not None:
            if total.lo >= 0 and total.hi < alloc_size:
                findings.append({
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
            elif total.hi >= alloc_size:
                findings.append({
                    "type": "heap_overflow",
                    "function": func_name or "unknown",
                    "severity": "high",
                    "cwe": "CWE-122",
                    "confidence": 0.75,
                    "description": f"join_all write_intervals total={total} "
                                   f"alloc={alloc_size} out_domain",
                    "verdict": "out_domain",
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