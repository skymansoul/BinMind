"""

计算维度:
  1. 利用性 (Exploitability): 说明符风险 + 用户可控性 + 栈偏移
  2. 影响 (Impact): 说明符类型 + 输出目标 (stdout/file/buffer)
  3. CIA三元组: 机密性/完整性/可用性影响
  4. 人类可读评估: description + exploitation advice

设计决策: 与 FormatSpecAnalyzer 分离, 独立测试评分逻辑。
"""

from typing import Dict, List, Optional, Tuple

from analysis.format_spec_scorer import (
    SpecifierRisk, FormatSpecifier, FormatExploitAssessment,
    OUTPUT_IMPACT,
)


def compute_exploitability(
    max_risk: SpecifierRisk,
    is_user_controlled: bool = False,
    stack_offset: int = -1,
) -> float:
    """计算利用性分数 (0-10)。

    利用性 = f(说明符风险, 用户可控性, 栈偏移已知度)
    """
    base = {
        SpecifierRisk.CRITICAL: 8.5,
        SpecifierRisk.HIGH: 6.5,
        SpecifierRisk.MEDIUM: 4.5,
        SpecifierRisk.LOW: 2.5,
        SpecifierRisk.INFO: 1.0,
        SpecifierRisk.NONE: 0.0,
    }[max_risk]

    # 用户可控: +1.5 (攻击者可注入任意说明符)
    if is_user_controlled:
        base = min(10.0, base + 1.5)

    # 栈偏移已知: +0.5 (可利用直接参数访问)
    if 0 <= stack_offset <= 100:
        base = min(10.0, base + 0.5)

    return base


def compute_impact(
    specs: List[FormatSpecifier],
    format_func: str = "printf",
) -> float:
    """计算影响分数 (0-10)。

    影响 = f(最大风险, 格式化函数类型)
    """
    if not specs:
        return 2.5  # 未知 → 中等偏低

    max_risk_val = max(s.risk.value for s in specs)
    risk_to_impact = {5: 8.5, 4: 6.5, 3: 5.0, 2: 3.0, 1: 1.5, 0: 0.0}
    base = risk_to_impact.get(max_risk_val, 2.0)

    # 输出目标修正
    modifier = OUTPUT_IMPACT.get(format_func, 0.5)
    base = base * (0.6 + 0.4 * modifier)

    return round(min(10.0, base), 1)


def compute_cia_impact(
    specs: List[FormatSpecifier],
    max_risk: SpecifierRisk,
) -> Tuple[float, float, float]:
    """计算机密性/完整性/可用性三元组影响。"""
    c = i = a = 0.0

    for s in specs:
        if s.risk == SpecifierRisk.CRITICAL:  # %n
            i = max(i, 0.9)
            c = max(c, 0.6)
        elif s.risk == SpecifierRisk.HIGH:    # %hn/%ln
            i = max(i, 0.7)
            c = max(c, 0.4)
        elif s.risk == SpecifierRisk.MEDIUM:  # %s
            c = max(c, 0.7)
        elif s.risk == SpecifierRisk.LOW:     # %x/%p
            c = max(c, 0.3)
        elif s.risk == SpecifierRisk.INFO:
            c = max(c, 0.1)

    # 输出目标调整
    a = 0.3 if max_risk.value >= SpecifierRisk.CRITICAL.value else 0.0

    return (round(c, 1), round(i, 1), round(a, 1))


def generate_assessment(
    format_func: str,
    format_arg: str,
    max_risk: SpecifierRisk,
    specs: List[FormatSpecifier],
    is_user_controlled: bool,
    stack_offset: int,
    exploit: float,
    impact: float,
) -> Tuple[str, str]:
    """生成人类可读的评估描述和利用建议。"""
    risk_labels = {
        SpecifierRisk.CRITICAL: "CRITICAL — arbitrary write primitive (%n)",
        SpecifierRisk.HIGH: "HIGH — partial word write (%hn/%ln)",
        SpecifierRisk.MEDIUM: "MEDIUM — arbitrary read / info leak (%s)",
        SpecifierRisk.LOW: "LOW — stack content leak (%x/%p)",
        SpecifierRisk.INFO: "INFO — numeric data leak only",
        SpecifierRisk.NONE: "NONE — no exploitable specifier",
    }

    if not specs:
        spec_summary = (
            "format string content not statically available; "
            f"{'user-controlled → assume worst-case %n' if is_user_controlled else 'unknown risk'}"
        )
    else:
        spec_names = [s.raw for s in specs]
        spec_summary = f"specifiers found: {', '.join(spec_names[:5])}"
        if len(specs) > 5:
            spec_summary += f" (+{len(specs) - 5} more)"

    desc = (
        f"{format_func}({format_arg}) — {risk_labels[max_risk]}. "
        f"{spec_summary}. "
        f"Score: {exploit + impact:.1f}/20 "
        f"(E:{exploit:.1f}/10 I:{impact:.1f}/10)"
    )

    advice_map = {
        SpecifierRisk.CRITICAL: (
            "Arbitrary write via %n: craft format string to write target "
            "address at calculated stack offset. Use %N$n for direct "
            "parameter access to bypass positional uncertainty."
        ),
        SpecifierRisk.HIGH: (
            "Partial word write via %hn: can overwrite 2 bytes at a time. "
            "Requires multiple writes for full address overwrite. "
            "Combine with GOT entry targeting."
        ),
        SpecifierRisk.MEDIUM: (
            "Arbitrary read via %s: can leak memory contents from stack "
            "to format output. Chain with other vulnerabilities for "
            "ASLR bypass or credential extraction."
        ),
        SpecifierRisk.LOW: (
            "Stack leak via %x/%p: useful for ASLR bypass. "
            "Read return addresses, canary values, or heap pointers "
            "from stack to defeat address randomization."
        ),
    }

    advice = advice_map.get(max_risk, (
        "Limited exploitability. Verify format argument source: "
        "if user-controlled, they can inject higher-risk specifiers."
    ))

    return desc, advice


__all__ = [
    'compute_exploitability', 'compute_impact',
    'compute_cia_impact', 'generate_assessment',
]
