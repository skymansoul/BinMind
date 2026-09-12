"""DeltaIntervalEval - 仿射差区间求值 (stage 100).

extent-size 仿射差 + 守卫上界代换二次求值:
  第一次求值: 从写操作提取偏移区间 [lo, hi]
  第二次求值: 若守卫 if (idx < N) 存在, 将 idx 上界代换为 N-1, 重新计算偏移区间
  差区间 = [w_lo - a, w_hi - a], 上界<0 -> safe, 下界>0 -> overflow
与 karr_affine_diff 不同: karr 用仿射关系求极值, 本模块用守卫上界代换求值.
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


def run_delta_interval_eval(
    pseudocode: str,
    func_name: str,
    existing_findings: Optional[List[dict]] = None,
) -> List[dict]:
    """守卫上界代换二次求值. 返回 findings."""
    findings: List[dict] = []
    m_alloc = re.search(r"(?:malloc|calloc|realloc)\s*\(\s*(\d+)", pseudocode)
    if not m_alloc:
        return findings
    alloc = int(m_alloc.group(1))

    for ln, line in enumerate(pseudocode.splitlines(), 1):
        m = re.search(r"\[\s*\w+\s*\+\s*(\w+)\s*\]\s*(?:,|=)", line)
        if not m:
            continue
        idx = m.group(1)

        # 第一次求值: 原始偏移区间
        orig_lo, orig_hi = _extract_offset_bounds(pseudocode, line, idx)

        # 守卫上界
        guard = _guard_bound(pseudocode, idx)

        # 第二次求值: 守卫代换后区间
        if guard is not None:
            # 代换: idx 上界替换为 guard-1, 窄化偏移区间
            sub_lo = orig_lo
            sub_hi = min(orig_hi, guard - 1)
        else:
            # 无守卫: 二次求值等于一次求值 (退化)
            sub_lo = orig_lo
            sub_hi = orig_hi

        # 差区间
        d = _delta(sub_lo, sub_hi, alloc)
        verdict = _grade(d)

        # 有守卫且二次求值窄化了区间时提升置信度
        narrowed = guard is not None and sub_hi < orig_hi

        findings.append({
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
    return findings


if __name__ == "__main__":
    demo = """\
p = malloc(64);
if (idx < 32) { mov [p+idx], 0; }
"""
    out = run_delta_interval_eval(demo, "demo")
    for f in out:
        print(f["description"], f["verdict"])