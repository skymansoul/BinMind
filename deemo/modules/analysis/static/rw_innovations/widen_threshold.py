"""WidenThreshold - 阈值 widening (stage 87).

循环区间 widening 设阈值 [-4096, 4096], 超阈值判定 TOP 状态不可用
于安全证明. 与 forward_interval_prop 不同: 阈值化 widening 语义.

设计决策:
  - 区间 widening: [a,b] widen [c,d] -> [a<0?-inf:a, b>0?inf:b]
  - 阈值 [-4096, 4096]: 边界超阈值 -> TOP (不可用于安全证明)
  - TOP 状态不能判定安全
"""

import re
from typing import List, Optional, Tuple

_LO, _HI = -4096, 4096
_TOP = (None, None)


def _widen(a: Tuple[int, int], b: Tuple[int, int]) -> Tuple[int, int]:
    """标准 widening: 若下界增大到 inf, 上界减小到 -inf."""
    lo, hi = a
    clo, chi = b
    new_lo = lo if clo >= lo else None
    new_hi = hi if chi <= hi else None
    return (new_lo, new_hi)


def _topped(r: Tuple[int, int]) -> bool:
    """是否超阈值 -> TOP."""
    lo, hi = r
    if lo is None or hi is None:
        return True
    return lo < _LO or hi > _HI


def run_widen_threshold(
    pseudocode: str,
    func_name: str,
    existing_findings: Optional[List[dict]] = None,
) -> List[dict]:
    """阈值 widening. 返回 findings."""
    findings: List[dict] = []
    # 收集循环: 识别变量初始化区间与增量
    init_ranges: dict = {}
    for line in pseudocode.splitlines():
        m = re.search(r"\b(\w+)\s*=\s*(\d+)\s*;", line)
        if m:
            init_ranges[m.group(1)] = (int(m.group(2)), int(m.group(2)))
    for ln, line in enumerate(pseudocode.splitlines(), 1):
        m = re.search(r"\b(\w+)\s*\+\+\s*", line)
        if not m:
            m = re.search(r"\b(\w+)\s*\+=\s*(\d+)", line)
        if not m:
            continue
        var = m.group(1)
        base = init_ranges.get(var)
        if base is None:
            continue
        # 一次迭代后 widen
        widened = _widen(base, (base[0], base[1] + 1))
        topped = _topped(widened)
        verdict = "topped" if topped else "stable"
        findings.append({
            "type": "heap_overflow",
            "function": func_name or "unknown",
            "severity": "medium",
            "cwe": "CWE-122",
            "confidence": 0.3 if topped else 0.8,
            "description": f"line{ln} var={var} base={base} "
                           f"widen={widened} topped={topped}",
            "verdict": verdict,
            "source": "widen_threshold",
        })
    return findings


if __name__ == "__main__":
    demo = """\
i = 0;
while (i < 100) { i++; }
"""
    out = run_widen_threshold(demo, "demo")
    for f in out:
        print(f["description"], f["verdict"])