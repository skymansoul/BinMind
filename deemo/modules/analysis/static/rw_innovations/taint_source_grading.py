"""TaintSourceGrading - 污点源分级 (stage 66).

scanf/recv/argv/env 分 1-4 级污点强度, 写入大小若由高级污点变量
驱动且无守卫 -> conf 提升; 低级污点 -> 降权.
与 alloc_size_taint 不同: 强度分级而非布尔污点.

设计决策:
  - 污点源分级: scanf=4, recv=3, argv=2, env=1
  - 追踪赋值链: 污点源 -> 变量
  - 若写入大小变量为高级污点且无守卫, conf 提升 0.2
  - 低级污点 (env=1) 且守卫存在, conf 降 0.2
"""

import re
from typing import Dict, List, Optional, Set

_SOURCE_GRADE = {
    "scanf": 4, "recv": 3, "read": 3, "argv": 2, "getenv": 1, "env": 1,
}


def run_taint_source_grading(
    pseudocode: str,
    func_name: str,
    existing_findings: Optional[List[dict]] = None,
) -> List[dict]:
    """污点源分级. 返回 findings."""
    findings: List[dict] = []
    sources = _collect_sources(pseudocode)
    for ln, line in enumerate(pseudocode.splitlines(), 1):
        # 写点: [指针表达式], 值 或 [指针表达式] = 值
        m = re.search(r"\[[^\]]*\]\s*(?:,|=)\s*(\w+)", line)
        if not m:
            continue
        val_var = m.group(1)
        ptr_expr = re.search(r"\[([^\]]+)\]", line).group(1)
        ptr_vars = re.findall(r"\b(\w+)\b", ptr_expr)
        grade = max((sources.get(v, 0) for v in ptr_vars), default=0)
        if val_var in sources:
            grade = max(grade, sources[val_var])
        guarded = "if" in line or "guard" in line
        if grade >= 3 and not guarded:
            conf = 0.9
            verdict = "high_taint"
        elif grade >= 2:
            conf = 0.7
            verdict = "mid_taint"
        elif grade == 1 and guarded:
            conf = 0.3
            verdict = "low_taint_guarded"
        else:
            conf = 0.5
            verdict = "unknown"
        findings.append({
            "type": "heap_overflow",
            "function": func_name or "unknown",
            "severity": "medium",
            "cwe": "CWE-122",
            "confidence": conf,
            "description": f"line{ln} taint_grade={grade} guarded={guarded}",
            "verdict": verdict,
            "source": "taint_source_grading",
        })
    return findings


def _taint_sources(pseudocode: str) -> Dict[str, int]:
    return _collect_sources(pseudocode)


def _collect_sources(pseudocode: str) -> Dict[str, int]:
    out: Dict[str, int] = {}
    for line in pseudocode.splitlines():
        for src, grade in _SOURCE_GRADE.items():
            m = re.search(r"\b(\w+)\s*=\s*[^;]*\b" + re.escape(src) + r"\b", line)
            if m:
                out[m.group(1)] = grade
    return out


if __name__ == "__main__":
    demo = """\
n = scanf("%d");
p = malloc(64);
mov [p+n], 0;
"""
    out = run_taint_source_grading(demo, "demo")
    for item in out:
        print(item["description"], item["verdict"], item["confidence"])