"""WriteSideFirst - 写侧优先 (stage 101).

先推写侧上界, 写侧不可知时禁止 cannot_overflow 结论.
与 delta_interval_eval 不同: 本模块把"写侧未知"作为保守硬约束.

设计决策:
  - 写侧上界: 常量偏移或守卫上界
  - 写侧不可知 (寄存器索引无守卫): 只能给 unknown, 不给 safe
  - 分配侧已知与否不影响写侧优先判定
"""

import re
from typing import List, Optional, Tuple


def _write_bound(line: str, pseudocode: str) -> Optional[Tuple[int, int]]:
    """写侧上界: [var+off] 或 [var+idx] 且守卫给上界."""
    m = re.search(r"\[\s*\w+\s*\+\s*(\d+)\s*\]", line)
    if m:
        return (int(m.group(1)), int(m.group(1)))
    m = re.search(r"\[\s*\w+\s*\+\s*(\w+)\s*\]", line)
    if m:
        idx = m.group(1)
        g = re.search(r"if\s*\(\s*" + re.escape(idx) + r"\s*<\s*(\d+)", pseudocode)
        if g:
            return (0, int(g.group(1)))
    return None


def run_write_side_first(
    pseudocode: str,
    func_name: str,
    existing_findings: Optional[List[dict]] = None,
) -> List[dict]:
    """写侧优先判定. 返回 findings."""
    findings: List[dict] = []
    for ln, line in enumerate(pseudocode.splitlines(), 1):
        m = re.search(r"\[\s*\w+\s*(\+\s*\w+)?\]\s*(?:,|=)", line)
        if not m:
            continue
        wu = _write_bound(line, pseudocode)
        if wu is None:
            findings.append({
                "type": "heap_overflow",
                "function": func_name or "unknown",
                "severity": "medium",
                "cwe": "CWE-122",
                "confidence": 0.2,
                "description": f"line{ln} write_upper=UNKNOWN "
                               f"verdict=cannot_hold",
                "verdict": "cannot_hold",
                "source": "write_side_first",
            })
            continue
        lo, hi = wu
        findings.append({
            "type": "heap_overflow",
            "function": func_name or "unknown",
            "severity": "low",
            "cwe": "CWE-122",
            "confidence": 0.6,
            "description": f"line{ln} write_upper={wu} "
                           "verdict=write_bounded",
            "verdict": "write_bounded",
            "source": "write_side_first",
        })
    return findings


if __name__ == "__main__":
    demo = """\
mov [p+idx], 0;
"""
    out = run_write_side_first(demo, "demo")
    for f in out:
        print(f["description"], f["verdict"])