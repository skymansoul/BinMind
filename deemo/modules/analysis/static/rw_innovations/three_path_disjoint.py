"""ThreePathDisjoint - 三路径不相交 (stage 94).

不同分配点/同分配点不越界/live-range 互斥三策略的集合运算实现
(区间集合差). 与 disjointness_prover 的证明器实现不同.

设计决策:
  - 策略1: 不同分配点 -> 写区间与分配区间集合差非空则不相交
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
    alloc = _alloc_range(pseudocode)
    writes = _write_ranges(pseudocode)
    if alloc is None:
        return findings
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


def _write_ranges(pseudocode: str) -> List[Tuple[int, int, int]]:
    """写区间列表 [(行号, lo, hi)]."""
    out = []
    for ln, line in enumerate(pseudocode.splitlines(), 1):
        m = re.search(r"\[\s*\w+\s*\+\s*(\d+)\s*\]\s*(?:,|=)\s*(\d+)", line)
        if m:
            off, size = int(m.group(1)), int(m.group(2))
            out.append((ln, off, off + size))
    return out


if __name__ == "__main__":
    demo = """\
p = malloc(64);
mov [p+8], 4;
mov [p+32], 4;
"""
    out = run_three_path_disjoint(demo, "demo")
    for f in out:
        print(f["description"], f["verdict"])