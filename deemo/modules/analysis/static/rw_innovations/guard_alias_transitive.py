"""GuardAliasTransitive - 守卫别名传递 (stage 77).

if (a<N) ... b=a; 时守卫沿赋值传递到 b, 查询 b 的守卫上界.
与 guard_correlator 不同: 守卫在别名链上传递闭包.

设计决策:
  - 收集守卫约束: if (var < N) 或 var <= N
  - 沿赋值链传播: 若 b = a 且 a 有守卫, 则 b 继承守卫
  - 写点若在守卫范围内 -> 安全
"""

import re
from typing import Dict, List, Optional, Set


def _collect_guards(pseudocode: str) -> Dict[str, int]:
    """收集 {变量: 上界} 守卫."""
    guards: Dict[str, int] = {}
    for line in pseudocode.splitlines():
        m = re.search(r"if\s*\(\s*(\w+)\s*(?:<|<=)\s*(\d+)\s*\)", line)
        if m:
            guards[m.group(1)] = int(m.group(2))
    return guards


def _propagate(pseudocode: str) -> Dict[str, int]:
    """收集守卫并沿赋值链传递闭包."""
    guards = _collect_guards(pseudocode)
    changed = True
    while changed:
        changed = False
        for line in pseudocode.splitlines():
            m = re.search(r"\b(\w+)\s*=\s*(\w+)\s*;", line)
            if not m:
                continue
            lhs, rhs = m.group(1), m.group(2)
            if rhs in guards and lhs not in guards:
                guards[lhs] = guards[rhs]
                changed = True
    return guards


def run_guard_alias_transitive(
    pseudocode: str,
    func_name: str,
    existing_findings: Optional[List[dict]] = None,
) -> List[dict]:
    """守卫别名传递. 返回 findings."""
    findings: List[dict] = []
    guards = _propagate(pseudocode)
    for ln, line in enumerate(pseudocode.splitlines(), 1):
        # [var+N] 或 [var+var2] 写点
        m = re.search(r"\[\s*(\w+)\s*\+\s*(\w+|\d+)\s*\]\s*(?:,|=)", line)
        if not m:
            continue
        var = m.group(1)
        off_txt = m.group(2)
        off = int(off_txt) if off_txt.isdigit() else None
        bound = guards.get(var)
        # 变量偏移时用守卫上界比较
        if off is not None and bound is not None and off < bound:
            verdict, conf = "guarded_safe", 0.9
        elif off is None and bound is not None:
            verdict, conf = "guarded_var_off", 0.8
        else:
            verdict, conf = "unguarded", 0.5
        findings.append({
            "type": "heap_overflow",
            "function": func_name or "unknown",
            "severity": "medium",
            "cwe": "CWE-122",
            "confidence": conf,
            "description": f"line{ln} var={var} off={off} "
                           f"guard_bound={bound}",
            "verdict": verdict,
            "source": "guard_alias_transitive",
        })
    return findings


if __name__ == "__main__":
    demo = """\
if (n < 64) { }
b = n;
mov [p+b], 0;
"""
    out = run_guard_alias_transitive(demo, "demo")
    for f in out:
        print(f["description"], f["verdict"])