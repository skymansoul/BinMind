# 格式说明符约束系统 — Format Specifier Constraint System (格式说明符约束评分系统).
#
# 决策逻辑:
#   基于格式说明符解析的 CVSS 式 0-10 风险评分:
#     Score = Exploitability × Impact / 10.
#   风险分级: %n→CRITICAL(5) / %hn,%ln→HIGH(4) / %s→MEDIUM(3) /
#             %x,%p→LOW(2) / %d,%u→INFO(1) / %%→NONE(0).
#   输出目标加权: stdout 0.4 / file 0.5 / buffer 0.7 / snprintf 0.3.
#   阈值判定: overall_score ≥ 3.0 → KEEP, 否则 FILTER.
#
#   本文件实现格式说明符约束系统核心管线: 评分函数 (格式说明符) → 分析器, 内联阈值过滤.


import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple


class SpecifierRisk(Enum):
    """格式说明符的利用风险等级。"""
    CRITICAL = 5   # %n — 任意地址写入
    HIGH = 4       # %hn — 2字节写入, %ln — 8字节写入
    MEDIUM = 3     # %s — 任意地址读取/信息泄露
    LOW = 2        # %x, %p — 栈内容泄露
    INFO = 1       # %d, %u, %c — 基本数值泄露
    NONE = 0       # %% — 无害


# 格式说明符 → 风险等级映射
SPECIFIER_RISK_MAP: Dict[str, SpecifierRisk] = {
    '%n':  SpecifierRisk.CRITICAL,
    '%hn': SpecifierRisk.HIGH,
    '%ln': SpecifierRisk.HIGH,
    '%lln': SpecifierRisk.HIGH,
    '%s':  SpecifierRisk.MEDIUM,
    '%ls': SpecifierRisk.MEDIUM,
    '%S':  SpecifierRisk.MEDIUM,
    '%x':  SpecifierRisk.LOW,
    '%lx': SpecifierRisk.LOW,
    '%llx': SpecifierRisk.LOW,
    '%p':  SpecifierRisk.LOW,
    '%X':  SpecifierRisk.LOW,
    '%d':  SpecifierRisk.INFO,
    '%u':  SpecifierRisk.INFO,
    '%i':  SpecifierRisk.INFO,
    '%ld': SpecifierRisk.INFO,
    '%lu': SpecifierRisk.INFO,
    '%c':  SpecifierRisk.INFO,
    '%f':  SpecifierRisk.INFO,
    '%e':  SpecifierRisk.INFO,
    '%g':  SpecifierRisk.INFO,
    '%%':  SpecifierRisk.NONE,
}

# 格式化函数的输出破坏性
OUTPUT_IMPACT: Dict[str, float] = {
    'printf':  0.4,    # stdout — 仅信息泄露
    'fprintf': 0.5,    # 文件输出 — 可能日志注入
    'dprintf': 0.5,    # fd输出
    'sprintf': 0.7,    # 缓冲区输出 — 栈/堆溢出可能
    'snprintf': 0.3,   # 带长度限制 — 限制破坏
    'syslog':  0.6,    # syslog — 日志注入+权限提升
}

# 格式说明符约束系统阈值: overall_score ≥ 3.0 → KEEP.
FSCS_KEEP_THRESHOLD = 3.0


@dataclass
class FormatSpecifier:
    """单个格式说明符的解析结果。"""
    raw: str                 # 原始文本, 如 "%02x"
    risk: SpecifierRisk
    width: int = 0           # 宽度字段
    precision: int = -1      # 精度字段 (-1 = 未指定)
    length_mod: str = ""     # 长度修饰符 (h/l/ll/z/t)
    position: int = 0        # 在格式字符串中的位置 (0-indexed)


@dataclass
class FormatExploitAssessment:
    """格式字符串漏洞的利用性评估。"""
    format_func: str                    # 格式化函数名
    format_arg: str                     # 格式参数变量名
    specifiers: List[FormatSpecifier] = field(default_factory=list)
    max_risk: SpecifierRisk = SpecifierRisk.NONE
    exploitability_score: float = 0.0   # 0-10
    impact_score: float = 0.0           # 0-10
    overall_score: float = 0.0          # exploitability * impact / 10
    confidence: float = 0.5

    # CVSS映射
    confidentiality_impact: float = 0.0
    integrity_impact: float = 0.0
    availability_impact: float = 0.0

    description: str = ""
    exploitation_advice: str = ""


# 评分函数

def compute_exploitability(
    max_risk: SpecifierRisk,
    is_user_controlled: bool = False,
    stack_offset: int = -1,
) -> float:
    """计算利用性分数 (0-10).

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
    """计算影响分数 (0-10).

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


# 分析器

class FormatSpecAnalyzer:
    """格式字符串说明符解析与分析引擎。

    解析C格式字符串, 提取所有说明符, 基于说明符类型量化利用性。
    """

    # 格式说明符正则: %[flags][width][.precision][length]specifier
    _SPEC_PATTERN = re.compile(
        r'%'
        r'([-+ #0]+)?'         # flags (optional)
        r'(\d+|\*)?'            # width (optional)
        r'(?:\.(\d+|\*))?'      # .precision (optional)
        r'(hh?|ll?|l|L|z|j|t)?'  # length modifier (optional)
        r'([diouxXeEfFgGaAcspnSCSm%])',  # specifier character
    )

    @classmethod
    def parse_format_string(cls, fmt_str: str) -> List[FormatSpecifier]:
        """解析格式字符串, 提取所有说明符。"""
        specs = []
        pos = 0
        for m in cls._SPEC_PATTERN.finditer(fmt_str):
            flags = m.group(1) or ''
            width = m.group(2) or ''
            precision = m.group(3) or ''
            length = m.group(4) or ''
            spec_char = m.group(5)

            raw = m.group(0)
            risk = cls._classify_specifier(raw, spec_char, length)

            w = int(width) if width and width != '*' else 0
            p = int(precision) if precision and precision != '*' else -1

            specs.append(FormatSpecifier(
                raw=raw, risk=risk, width=w, precision=p,
                length_mod=length, position=pos,
            ))
            pos += 1
        return specs

    @classmethod
    def assess_exploitability(
        cls,
        format_func: str,
        format_arg: str,
        format_string_content: str = "",
        is_user_controlled: bool = False,
        stack_offset: int = -1,
    ) -> FormatExploitAssessment:
        """对格式字符串漏洞进行完整的利用性评估。"""
        specs = cls.parse_format_string(format_string_content) if format_string_content else []

        max_risk = SpecifierRisk.NONE
        for s in specs:
            if s.risk.value > max_risk.value:
                max_risk = s.risk

        # 没有静态格式字符串但用户可控 → 假设最坏情况
        if not specs and is_user_controlled:
            max_risk = SpecifierRisk.CRITICAL  # 用户可注入 %n

        exploit = compute_exploitability(max_risk, is_user_controlled, stack_offset)
        impact = compute_impact(specs, format_func)

        # 路径约束收集验证 (Path Constraint Collection Verification) 修正: 用户可控但无静态内容时, impact 默认 2.5 会使
        # overall = 10*2.5/10 = 2.5 < 3.0 → FN; 取 max(exploit, ...).
        if not specs and is_user_controlled:
            overall = max(exploit, (exploit * impact) / 10.0)
        else:
            overall = (exploit * impact) / 10.0

        cia = compute_cia_impact(specs, max_risk)

        desc, advice = generate_assessment(
            format_func, format_arg, max_risk, specs,
            is_user_controlled, stack_offset, exploit, impact,
        )

        return FormatExploitAssessment(
            format_func=format_func,
            format_arg=format_arg,
            specifiers=specs,
            max_risk=max_risk,
            exploitability_score=round(exploit, 1),
            impact_score=round(impact, 1),
            overall_score=round(overall, 1),
            confidence=0.85 if specs else 0.40,
            confidentiality_impact=cia[0],
            integrity_impact=cia[1],
            availability_impact=cia[2],
            description=desc,
            exploitation_advice=advice,
        )

    @classmethod
    def _classify_specifier(cls, raw: str, spec_char: str,
                            length: str) -> SpecifierRisk:
        """分类单个格式说明符的利用风险。"""
        if spec_char == '%':
            return SpecifierRisk.NONE

        # 精确匹配: %n, %hn, %ln, %lln
        if spec_char == 'n':
            if length in ('hh',):
                return SpecifierRisk.LOW    # 单字节写入
            if length in ('h',):
                return SpecifierRisk.HIGH   # 2字节写入
            return SpecifierRisk.CRITICAL   # 4/8字节写入

        key = f'%{length}{spec_char}' if length else f'%{spec_char}'
        risk = SPECIFIER_RISK_MAP.get(key)
        if risk is None:
            risk = SPECIFIER_RISK_MAP.get(f'%{spec_char}', SpecifierRisk.INFO)
        return risk


def analyze_format_string_risk(
    func_name: str,
    fmt_arg: str,
    fmt_content: str = "",
    user_controlled: bool = False,
    offset: int = -1,
) -> FormatExploitAssessment:
    """便捷函数: 单次调用评估格式字符串利用性。"""
    return FormatSpecAnalyzer.assess_exploitability(
        format_func=func_name,
        format_arg=fmt_arg,
        format_string_content=fmt_content,
        is_user_controlled=user_controlled,
        stack_offset=offset,
    )


def filter_by_fscs_threshold(
    assessments: List[FormatExploitAssessment],
    threshold: float = FSCS_KEEP_THRESHOLD,
) -> Tuple[List[FormatExploitAssessment], List[FormatExploitAssessment]]:
    """格式说明符约束系统阈值判定: overall_score ≥ threshold → KEEP, 否则 FILTER."""
    kept, filtered = [], []
    for a in assessments:
        if a.overall_score >= threshold:
            kept.append(a)
        else:
            filtered.append(a)
    return kept, filtered


__all__ = [
    'SpecifierRisk', 'FormatSpecifier', 'FormatExploitAssessment',
    'FormatSpecAnalyzer', 'analyze_format_string_risk',
    'filter_by_fscs_threshold', 'FSCS_KEEP_THRESHOLD',
    'compute_exploitability', 'compute_impact', 'compute_cia_impact',
    'generate_assessment', 'SPECIFIER_RISK_MAP', 'OUTPUT_IMPACT',
]
