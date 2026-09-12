"""RootIdentityKey - 根身份键 (stage 68).

size 表达式归一化为四元组 (kind, var, coeff, const) 哈希键,
alloc 与 write 的键相等 -> 安全. 与 SI-CTA 链 id 不同:
表达式归一化哈希而非链传播.

设计决策:
  - 表达式 -> (kind, var, coeff, const): kind 为 var/const/unknown
  - alloc size 与 write size 分别归一化
  - 键相等 (var 相同且 coeff 相同) -> 身份一致 -> 安全
"""

import re
from typing import List, Optional, Tuple


def _normalize(expr: str) -> Tuple[str, str, int, int]:
    """归一化 size 表达式 -> (kind, var, coeff, const)."""
    expr = expr.strip()
    # 纯常量
    if re.fullmatch(r"0[xX][0-9a-fA-F]+|\d+", expr):
        return ("const", "", 0, int(expr, 0))
    # var * coeff + const
    m = re.fullmatch(r"(\w+)\s*\*\s*(\d+)\s*\+\s*(\d+)", expr)
    if m:
        return ("var", m.group(1), int(m.group(2)), int(m.group(3)))
    m2 = re.fullmatch(r"(\w+)\s*\+\s*(\d+)", expr)
    if m2:
        return ("var", m2.group(1), 1, int(m2.group(2)))
    m3 = re.fullmatch(r"(\w+)", expr)
    if m3:
        return ("var", m3.group(1), 1, 0)
    return ("unknown", "", 0, 0)


def _key(expr: str) -> Tuple[str, str, int, int]:
    return _normalize(expr)


def _root(expr: str) -> Tuple[str, str, int, int]:
    return _normalize(expr)


def run_root_identity_key(
    pseudocode: str,
    func_name: str,
    existing_findings: Optional[List[dict]] = None,
) -> List[dict]:
    """根身份键判定. 返回 findings."""
    findings: List[dict] = []
    alloc_expr = None
    m_alloc = re.search(r"malloc\s*\(\s*([^)]+)\)", pseudocode)
    if m_alloc:
        alloc_expr = m_alloc.group(1).strip()
    if not alloc_expr:
        return findings
    alloc_key = _root(alloc_expr)
    for ln, line in enumerate(pseudocode.splitlines(), 1):
        m = re.search(r"\[[^\]]+\]\s*=\s*(\w+)\s*;", line)
        if not m:
            continue
        write_expr = m.group(1)
        write_key = _root(write_expr)
        same = (alloc_key == write_key)
        verdict = "identity_safe" if same else "identity_diff"
        findings.append({
            "type": "heap_overflow",
            "function": func_name or "unknown",
            "severity": "medium",
            "cwe": "CWE-122",
            "confidence": 0.9 if same else 0.5,
            "description": f"line{ln} alloc_key={alloc_key} "
                           f"write_key={write_key} same={same}",
            "verdict": verdict,
            "source": "root_identity_key",
        })
    return findings


if __name__ == "__main__":
    demo = """\
p = malloc(n * 4 + 8);
mov [p+4], n;
"""
    out = run_root_identity_key(demo, "demo")
    for item in out:
        print(item["description"], item["verdict"])