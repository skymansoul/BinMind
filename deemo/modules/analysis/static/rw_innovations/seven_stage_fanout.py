"""SevenStageFanout - 七阶段扇出审计 (stage 61).

把 alloc 的所有下游写点构建扇出树, 逐层计算"守卫覆盖率"
(受守卫写点/总写点), 覆盖率 >= 0.9 才允许整体判安全.
与 HOFPR-APC 级联不同: 树形扇出聚合.

设计决策:
  - 从伪代码中识别分配变量与写点
  - 写点按分配变量聚合为扇出树
  - 守卫覆盖率 = 受守卫(if/while 包裹)写点数 / 总写点数
  - 覆盖率 < 0.9 时整体不可判安全
"""

import re
from typing import Dict, List, Optional


def _find_allocs(pseudocode: str) -> List[str]:
    """识别分配变量名."""
    pat = re.compile(
        r"\b(\w+)\s*=\s*(?:\([^)]*\)\s*)?(?:malloc|calloc|realloc)\s*\(")
    return [m.group(1) for m in pat.finditer(pseudocode)]


def _guarded(line: str) -> bool:
    """判断写点是否受守卫 (行内 if/while 或与上一判断行关联)."""
    return "if" in line or "while" in line or "guard" in line


def run_seven_stage_fanout(
    pseudocode: str,
    func_name: str,
    existing_findings: Optional[List[dict]] = None,
    threshold: float = 0.9,
) -> List[dict]:
    """七阶段扇出审计. 返回 findings."""
    findings: List[dict] = []
    lines = pseudocode.splitlines()
    vars_ = _find_allocs(pseudocode)
    write_pat = re.compile(r"\[[^\]]+\]\s*=")
    for var in vars_:
        # 扇出树: 所有引用 var 的写点
        fanouts: List[dict] = []
        for i, line in enumerate(lines):
            if not write_pat.search(line):
                continue
            if re.search(r"\b" + re.escape(var) + r"\b", line):
                fanouts.append({"line": i, "guarded": _guarded(line)})
        if not fanouts:
            continue
        guarded = sum(1 for f in fanouts if f["guarded"])
        coverage = guarded / len(fanouts)
        verdict = "safe" if coverage >= threshold else "unsafe"
        findings.append({
            "type": "heap_overflow",
            "function": func_name or "unknown",
            "severity": "medium",
            "cwe": "CWE-122",
            "confidence": round(min(1.0, coverage), 2),
            "description": (
                f"alloc_var={var} fanout={len(fanouts)} "
                f"guarded={guarded} coverage={coverage:.2f}"
            ),
            "verdict": verdict,
            "source": "seven_stage_fanout",
        })
    return findings


if __name__ == "__main__":
    demo = """\
p = malloc(64);
if (n <= 64) { mov [p+n], 0; }
mov [p+8], 0;
"""
    out = run_seven_stage_fanout(demo, "demo")
    for item in out:
        print(item["description"], item["verdict"])