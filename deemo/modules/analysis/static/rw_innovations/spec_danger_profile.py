"""SpecDangerProfile - 格式串说明符危险画像 (stage 58).

对格式串做逐说明符 token 化, %n 权重 5/%s 3/%x 2/%p 1/其它 0.5,
累计危险分并按参数位置距栈帧顶距离衰减, 超阈值且非字面量才告警.
与 FSTP 语义分级不同: 逐 token 加权 + 位置衰减.

设计决策:
  - 说明符权重表固定, 位置衰减 = 1 / (1 + 位置)
  - 字面量格式串 (只含常量字符) 直接安全
  - 累计危险分超阈值才产出告警
"""

import re
from typing import List, Optional

_SPEC_WEIGHTS = {
    "n": 5.0, "s": 3.0, "x": 2.0, "p": 1.0,
    "d": 0.5, "u": 0.5, "c": 0.5, "f": 0.5, "e": 0.5, "g": 0.5,
}


def _tokenize_format(fmt: str) -> List[str]:
    """提取 % 说明符 token 列表."""
    return re.findall(r"%[-+ #0-9.*]*([a-zA-Z])", fmt)


def _is_literal(fmt: str) -> bool:
    """判断格式串是否全为字面量 (无 % 且无非常量内容)."""
    return "%" not in fmt


def _danger_score(fmt: str) -> float:
    """累计危险分, 按参数位置衰减."""
    tokens = _tokenize_format(fmt)
    score = 0.0
    for idx, tok in enumerate(tokens):
        w = _SPEC_WEIGHTS.get(tok, 0.5)
        score += w / (1.0 + idx)
    return score


def run_spec_danger_profile(
    pseudocode: str,
    func_name: str,
    existing_findings: Optional[List[dict]] = None,
    threshold: float = 3.0,
) -> List[dict]:
    """格式串说明符危险画像. 返回 findings."""
    findings: List[dict] = []
    fmt_pat = re.compile(r'(["\'][^"\']*["\'])\s*[,;]?\s*(?:\w+\s*=\s*)?')
    for ln, line in enumerate(pseudocode.splitlines(), 1):
        # 找格式串字面量
        m = re.search(r'(["\'][^"\']*["\'])', line)
        if not m:
            continue
        raw = m.group(1)[1:-1]
        if _is_literal(raw):
            continue
        score = _danger_score(raw)
        verdict = "danger" if score >= threshold else "benign"
        findings.append({
            "type": "format_string",
            "function": func_name or "unknown",
            "severity": "high" if verdict == "danger" else "low",
            "cwe": "CWE-134",
            "confidence": round(min(1.0, score / 6.0), 2),
            "description": f"fmt@{ln} score={score:.2f}",
            "verdict": verdict,
            "source": "spec_danger_profile",
        })
    return findings


if __name__ == "__main__":
    demo = """\
char fmt[] = "%s %n %x";
printf(fmt, buf);
"""
    out = run_spec_danger_profile(demo, "demo")
    for item in out:
        print(item["description"], item["verdict"], item["confidence"])