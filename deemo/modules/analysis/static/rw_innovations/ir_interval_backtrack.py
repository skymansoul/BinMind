"""IrIntervalBacktrace - IR 区间回溯 (stage 104).

VarRange.at 程序点查询 + 回退最近定义快照:
  维护变量定义快照, 在任意程序点查询变量区间,
  无定义时回退到最近快照.
与 affine_meet_domain 不同: 本模块按程序点回溯而非全局映射.

设计决策:
  - 快照: {var: (区间, 定义行)}
  - at(ln, var): 取 <= ln 的最近定义
  - 无定义 -> UNKNOWN
"""

import re
from typing import Dict, List, Optional, Tuple


class VarRange:
    """变量区间快照表."""

    def __init__(self) -> None:
        self._snap: Dict[str, List[Tuple[int, Tuple[int, int]]]] = {}

    def set(self, var: str, ln: int, r: Tuple[int, int]) -> None:
        self._snap.setdefault(var, []).append((ln, r))

    def at(self, var: str, ln: int) -> Optional[Tuple[int, int]]:
        """查询 <= ln 的最近定义区间."""
        snaps = self._snap.get(var, [])
        best = None
        for sln, r in snaps:
            if sln <= ln:
                best = r
            else:
                break
        return best


def _parse_def(line: str) -> Optional[Tuple[str, int, int]]:
    m = re.search(r"\b(\w+)\s*=\s*(\d+)\s*;", line)
    if m:
        return m.group(1), int(m.group(2)), int(m.group(2))
    m = re.search(r"\b(\w+)\s*=\s*(\w+)\s*\+\s*(\d+)", line)
    if m:
        return m.group(1), 0, int(m.group(3))
    return None


def run_ir_interval_backtrace(
    pseudocode: str,
    func_name: str,
    existing_findings: Optional[List[dict]] = None,
) -> List[dict]:
    """区间点回溯. 返回 findings."""
    findings: List[dict] = []
    vr = VarRange()
    lines = pseudocode.splitlines()
    for ln, line in enumerate(lines, 1):
        d = _parse_def(line)
        if d:
            vr.set(d[0], ln, (d[1], d[2]))
    for ln, line in enumerate(lines, 1):
        m = re.search(r"\[\s*\w+\s*\+\s*(\w+)\s*\]\s*(?:,|=)", line)
        if not m:
            continue
        idx = m.group(1)
        r = vr.at(idx, ln)
        if r is None:
            verdict, conf = "unknown", 0.2
        else:
            verdict, conf = "backtraced", 0.8
        findings.append({
            "type": "heap_overflow",
            "function": func_name or "unknown",
            "severity": "medium",
            "cwe": "CWE-122",
            "confidence": conf,
            "description": f"line{ln} idx={idx} range={r} verdict={verdict}",
            "verdict": verdict,
            "source": "ir_interval_backtrack",
        })
    return findings


if __name__ == "__main__":
    demo = """\
i = 3;
mov [p+i], 0;
"""
    out = run_ir_interval_backtrace(demo, "demo")
    for f in out:
        print(f["description"], f["verdict"])