"""KarrAffineDiff - Karr 仿射差 (stage 106).

write-alloc 仿射差 + eval_bounds 极值, 单维纯 Karr 表示:
  记录形如 var = a*base + b 的仿射关系, 求差区间极值判定越界.
与 delta_interval_eval 不同: 本模块用 Karr 仿射关系而非单区间.

设计决策:
  - Karr 仿射: 只记录单维 x = a*y + b 关系
  - eval_bounds: 由 y 的区间求 x 极值
  - 差 = 写极值 - 分配大小, 上界<0 safe, 下界>0 overflow
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


def run_karr_affine_diff(
    pseudocode: str,
    func_name: str,
    existing_findings: Optional[List[dict]] = None,
) -> List[dict]:
    """Karr 仿射差判定. 返回 findings."""
    findings: List[dict] = []
    m_alloc = re.search(r"(?:malloc|calloc|realloc)\s*\(\s*(\d+)", pseudocode)
    if not m_alloc:
        return findings
    alloc = int(m_alloc.group(1))
    ranges: Dict[str, Tuple[int, int]] = {}
    for line in pseudocode.splitlines():
        m = re.search(r"\b(\w+)\s*=\s*(\d+)\s*;", line)
        if m:
            ranges[m.group(1)] = (int(m.group(2)), int(m.group(2)))
    rel = _collect_affine(pseudocode)
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
        findings.append({
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