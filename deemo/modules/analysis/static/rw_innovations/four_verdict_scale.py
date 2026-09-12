"""FourVerdictScale - 四级判定标尺 (stage 98).

CONFIRMED/LIKELY/UNCERTAIN/FILTERED 四级判定, 用概率量化分级:
  0.85-1.0  CONFIRMED   有分配边界且写侧完全解析
  0.6-0.85  LIKELY      写侧部分解析/守卫不完整
  0.3-0.6   UNCERTAIN   信息不足
  <0.3      FILTERED    疑似但被过滤证据降级
与 four_level_adjudicator 不同: 本模块输出概率标尺而非链条.

设计决策:
  - 证据计数: alloc 证据 + 写点解析 + 守卫证据
  - 概率 = 证据加权和, 归一化到四级
  - FILTERED 特指: 有溢出嫌疑但守卫证伪 (取反路径)
"""

import re
from typing import List, Optional


def _score(line: str, pseudocode: str) -> float:
    """证据加权概率 [0,1]."""
    score = 0.0
    if re.search(r"\b(?:malloc|calloc|realloc)\s*\(", pseudocode):
        score += 0.35
    if re.search(r"\[\s*\w+\s*(\+\s*\d+)?\]", line):
        score += 0.25
    if re.search(r"\bif\s*\([^)]*\)", pseudocode):
        score += 0.30
    return min(score, 1.0)


def _filtered(line: str, pseudocode: str) -> bool:
    """是否有守卫过滤 (if 内含写点变量)."""
    m = re.search(r"\[\s*(\w+)\s*(\+\s*\w+)?\]\s*(?:,|=)", line)
    if not m:
        return False
    var = m.group(1)
    return bool(re.search(r"if\s*\([^)]*" + re.escape(var), pseudocode))


def _grade(p: float, filtered: bool) -> str:
    if filtered and p < 0.6:
        return "FILTERED"
    if p >= 0.85:
        return "CONFIRMED"
    if p >= 0.6:
        return "LIKELY"
    return "UNCERTAIN"


def run_four_verdict_scale(
    pseudocode: str,
    func_name: str,
    existing_findings: Optional[List[dict]] = None,
) -> List[dict]:
    """四级判定标尺. 返回 findings."""
    findings: List[dict] = []
    for ln, line in enumerate(pseudocode.splitlines(), 1):
        m = re.search(r"\[\s*(\w+)\s*(\+\s*\w+|\+\s*\d+)?\]\s*(?:,|=)", line)
        if not m:
            continue
        p = _score(line, pseudocode)
        verdict = _grade(p, _filtered(line, pseudocode))
        findings.append({
            "type": "heap_overflow",
            "function": func_name or "unknown",
            "severity": "medium",
            "cwe": "CWE-122",
            "confidence": round(p, 2),
            "description": f"line{ln} var={m.group(1)} prob={p:.2f} "
                           f"verdict={verdict}",
            "verdict": verdict,
            "source": "four_verdict_scale",
        })
    return findings


if __name__ == "__main__":
    demo = """\
p = malloc(64);
if (idx < 64) { mov [p+idx], 0; }
"""
    out = run_four_verdict_scale(demo, "demo")
    for f in out:
        print(f["description"], f["verdict"])