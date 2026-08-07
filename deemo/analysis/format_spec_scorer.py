"""格式串漏洞利用性评分 — 基于格式说明符解析的 0-10 风险评估.

Score = Exploitability × Impact, 区分 %n/%s/%x/%d 的危险等级.
"""

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

    # 参数位置模式: %N$specifier (POSIX)
    _POSIX_POS_PATTERN = re.compile(r'%(\d+)\$')

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

            # 提取宽度/精度
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
        """对格式字符串漏洞进行完整的利用性评估。

        Args:
            format_func: 格式化函数名 (printf/sprintf/...)
            format_arg: 格式参数变量名
            format_string_content: 如果能静态提取格式字符串内容
            is_user_controlled: 格式字符串是否来自用户输入
            stack_offset: 格式字符串在栈上的参数位置 (-1=未知)

        Returns:
            FormatExploitAssessment with 0-10 scores
        """
        specs = cls.parse_format_string(format_string_content) if format_string_content else []

        # 计算最大风险
        max_risk = SpecifierRisk.NONE
        for s in specs:
            if s.risk.value > max_risk.value:
                max_risk = s.risk

        # 如果没有静态格式字符串但用户可控 → 假设最坏情况
        if not specs and is_user_controlled:
            max_risk = SpecifierRisk.CRITICAL  # 用户可注入 %n

        # 计算利用性分数 (0-10)
        exploit = cls._compute_exploitability(max_risk, is_user_controlled, stack_offset)

        # 计算影响分数 (0-10)
        impact = cls._compute_impact(specs, format_func)

        # CVSS-style overall — FCPV 修正: 当格式串用户可控但无静态内容时,
        # impact 默认值 2.5 会导致 overall = 10*2.5/10 = 2.5 < 3.0 → FN.
        # 修正: 用户可控时 overall 取 max(exploit, exploit*impact/10).
        if not specs and is_user_controlled:
            overall = max(exploit, (exploit * impact) / 10.0)
        else:
            overall = (exploit * impact) / 10.0

        # 机密性/完整性/可用性
        cia = cls._compute_cia_impact(specs, max_risk)

        desc, advice = cls._generate_assessment(
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
        # 构建查找键
        if spec_char == '%':
            return SpecifierRisk.NONE

        # 精确匹配: %n, %hn, %ln, %lln
        if spec_char == 'n':
            if length in ('hh',):
                return SpecifierRisk.LOW    # 单字节写入
            if length in ('h',):
                return SpecifierRisk.HIGH   # 2字节写入
            return SpecifierRisk.CRITICAL   # 4/8字节写入

        # 通用查找
        key = f'%{length}{spec_char}' if length else f'%{spec_char}'
        risk = SPECIFIER_RISK_MAP.get(key)
        if risk is None:
            # 尝试无长度修饰符的版本
            risk = SPECIFIER_RISK_MAP.get(f'%{spec_char}', SpecifierRisk.INFO)
        return risk

    @classmethod
    def _compute_exploitability(cls, max_risk: SpecifierRisk,
                                 is_user_controlled: bool,
                                 stack_offset: int) -> float:
        """计算利用性分数 (0-10) —— 委托给 format_impact_calculator。"""
        from analysis.format_impact_calculator import compute_exploitability
        return compute_exploitability(max_risk, is_user_controlled, stack_offset)

    @classmethod
    def _compute_impact(cls, specs: List[FormatSpecifier],
                        format_func: str) -> float:
        """计算影响分数 (0-10) —— 委托给 format_impact_calculator。"""
        from analysis.format_impact_calculator import compute_impact
        return compute_impact(specs, format_func)

    @classmethod
    def _compute_cia_impact(cls, specs: List[FormatSpecifier],
                            max_risk: SpecifierRisk) -> Tuple[float, float, float]:
        """计算CIA三元组影响 —— 委托给 format_impact_calculator。"""
        from analysis.format_impact_calculator import compute_cia_impact
        return compute_cia_impact(specs, max_risk)

    @classmethod
    def _generate_assessment(cls, format_func: str, format_arg: str,
                              max_risk: SpecifierRisk,
                              specs: List[FormatSpecifier],
                              is_user_controlled: bool,
                              stack_offset: int,
                              exploit: float, impact: float) -> Tuple[str, str]:
        """生成评估描述 —— 委托给 format_impact_calculator。"""
        from analysis.format_impact_calculator import generate_assessment
        return generate_assessment(
            format_func, format_arg, max_risk, specs,
            is_user_controlled, stack_offset, exploit, impact)


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


__all__ = [
    'SpecifierRisk', 'FormatSpecifier', 'FormatExploitAssessment',
    'FormatSpecAnalyzer', 'analyze_format_string_risk',
    'SPECIFIER_RISK_MAP', 'OUTPUT_IMPACT',
]
