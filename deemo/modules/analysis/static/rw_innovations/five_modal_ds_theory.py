"""FiveModalDSTheory - 五模态 D-S 证据理论 (stage 105).

五模态 mass 函数 (safe/overflow/unknown/conflict/filtered)
+ 双源 D-S 组合规则 + 冲突因子 K.
与 four_verdict_scale 不同: 本模块做两源 D-S 组合, four_verdict_scale 做单源概率分级.

设计决策:
  - 五模态: SAFE, OVERFLOW, UNKNOWN, CONFLICT, FILTERED
  - 证据源 A (静态分析证据): malloc/写点/守卫模式匹配
  - 证据源 B (结构证据): 写偏移 vs 分配大小, 守卫证伪
  - D-S 组合: m12(A) = sum_{B∩C=A} m1(B)m2(C) / (1-K)
  - K=冲突因子, K>=1 时证据完全冲突 -> CONFLICT
  - FILTERED: 守卫证伪 (写变量在 if 条件中被约束) 时产出
"""

import re
from typing import Dict, List, Optional

_MODES = ["SAFE", "OVERFLOW", "UNKNOWN", "CONFLICT", "FILTERED"]


def _evidence_source_a(pseudocode: str, line: str) -> Dict[str, float]:
    """证据源 A: 静态分析证据 (模式匹配构建 mass)."""
    mass: Dict[str, float] = {}
    has_malloc = bool(re.search(r"(?:malloc|calloc|realloc)\s*\(", pseudocode))
    has_write = bool(re.search(r"\[\s*\w+\s*(?:\+\s*\w+)?\s*\]\s*(?:,|=)", line))
    has_guard = bool(re.search(r"if\s*\([^)]*\)", pseudocode))

    # malloc 存在 + 写点存在 => OVERFLOW 倾向
    if has_malloc and has_write:
        mass["OVERFLOW"] = 0.45
    # if 守卫存在 => SAFE 倾向
    if has_guard:
        mass["SAFE"] = mass.get("SAFE", 0.0) + 0.35
    # 无危险特征 => SAFE
    if not has_malloc and not has_write:
        mass["SAFE"] = mass.get("SAFE", 0.0) + 0.6
    # 剩余 mass 分配给 UNKNOWN
    total = sum(mass.values())
    if total < 1.0:
        mass["UNKNOWN"] = 1.0 - total
    return mass


def _evidence_source_b(
    pseudocode: str, line: str, alloc_size: Optional[int]
) -> Dict[str, float]:
    """证据源 B: 结构证据 (写偏移 vs 分配大小, 守卫证伪)."""
    mass: Dict[str, float] = {}

    # 守卫证伪: 写变量出现在 if 条件中被约束
    m_write = re.search(r"\[\s*\w+\s*\+\s*(\w+)\s*\]", line)
    idx_var = m_write.group(1) if m_write else None
    if idx_var and re.search(r"if\s*\(\s*" + re.escape(idx_var) +
                            r"\s*[<>=!]", pseudocode):
        mass["FILTERED"] = 0.4

    # 写偏移已知且 < alloc => SAFE
    if alloc_size is not None and idx_var:
        m_const = re.search(r"\[\s*\w+\s*\+\s*(\d+)\s*\]", line)
        if m_const:
            off = int(m_const.group(1))
            if off < alloc_size:
                mass["SAFE"] = mass.get("SAFE", 0.0) + 0.45
            else:
                mass["OVERFLOW"] = mass.get("OVERFLOW", 0.0) + 0.5

    # 写偏移未知 => UNKNOWN
    if not mass:
        mass["UNKNOWN"] = 0.6

    # 补齐剩余 mass
    total = sum(mass.values())
    if total < 1.0:
        mass["UNKNOWN"] = mass.get("UNKNOWN", 0.0) + (1.0 - total)
    return mass


def _combine(m1: Dict[str, float], m2: Dict[str, float]) -> Dict[str, float]:
    """D-S 组合规则: m12(A) = sum_{B∩C=A} m1(B)m2(C) / (1-K).

    K = sum_{B∩C=空} m1(B)m2(C), 不含 UNKNOWN 交集 (UNKNOWN 与任意相交为该集合).
    """
    # 计算冲突因子 K: 不同非 UNKNOWN 模态的交集为空
    k = 0.0
    for a, va in m1.items():
        for b, vb in m2.items():
            # 非相同且都非 UNKNOWN => 交集为空
            if a != b and a != "UNKNOWN" and b != "UNKNOWN":
                k += va * vb

    if k >= 1.0:
        return {"CONFLICT": 1.0}

    denom = 1.0 - k
    out: Dict[str, float] = {}

    for a, va in m1.items():
        for b, vb in m2.items():
            if a == b:
                # 相同模态交集
                out[a] = out.get(a, 0.0) + va * vb / denom
            elif a == "UNKNOWN":
                # UNKNOWN ∩ B = B, B 的 mass 贡献
                out[b] = out.get(b, 0.0) + va * vb / denom
            elif b == "UNKNOWN":
                # A ∩ UNKNOWN = A, A 的 mass 贡献
                out[a] = out.get(a, 0.0) + va * vb / denom
            # a != b 且都非 UNKNOWN => 交集空, 已计入 K, 不产出

    # 确保有输出
    if not out:
        out["UNKNOWN"] = 1.0
    return out


def run_five_modal_ds_theory(
    pseudocode: str,
    func_name: str,
    existing_findings: Optional[List[dict]] = None,
) -> List[dict]:
    """双源五模态 D-S 证据组合. 返回 findings."""
    findings: List[dict] = []

    # 分配大小
    alloc_size = None
    m_alloc = re.search(r"(?:malloc|calloc|realloc)\s*\(\s*(\d+)", pseudocode)
    if m_alloc:
        alloc_size = int(m_alloc.group(1))

    lines = pseudocode.splitlines()
    for ln, line in enumerate(lines, 1):
        m = re.search(r"\[\s*\w+\s*(\+\s*\w+)?\]\s*(?:,|=)", line)
        if not m:
            continue

        # 构建两个独立证据源
        source_a = _evidence_source_a(pseudocode, line)
        source_b = _evidence_source_b(pseudocode, line, alloc_size)

        # D-S 组合
        combined = _combine(source_a, source_b)

        # 主导模态
        dom = max(combined, key=combined.get)
        conf = round(combined[dom], 2)
        verdict = "ds_" + dom.lower()

        findings.append({
            "type": "heap_overflow",
            "function": func_name or "unknown",
            "severity": "medium",
            "cwe": "CWE-122",
            "confidence": conf,
            "description": f"line{ln} source_a={source_a} source_b={source_b} "
                           f"combined={combined} dominant={dom}",
            "verdict": verdict,
            "source": "five_modal_ds_theory",
        })
    return findings


if __name__ == "__main__":
    demo = """\
p = malloc(64);
mov [p+8], 0;
"""
    out = run_five_modal_ds_theory(demo, "demo")
    for f in out:
        print(f["description"], f["verdict"])