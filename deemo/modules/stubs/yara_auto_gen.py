# compat/ 代理导出 — YARA 规则自动构造
# 最小加载策略: 直接 from import，上游保持简洁接口
# 参考: MultiMal (SANER 2025) 多模态融合检测的规则构造方法
from modules.core.compat.yara_auto_gen import *

# YARA 规则质量评分
# MultiMal 多模态特征融合（调用图+CFG+熵）可对应到 YARA 多条件组合。
# 以下提供规则质量度量工具。
import re as _regex

def estimate_rule_quality(rule_text: str) -> dict:
    """评估单条 YARA 规则的预期质量。
    维度: 特异性（去误报）、覆盖率（匹配范围）、性能风险（扫描开销）。
    返回 {'specificity': 0-100, 'coverage_potential': 0-100, 'performance_risk': 'low'|'med'|'high'}"""
    strings_section = _regex.findall(r'\$(\w+)\s*=\s*\{(.+?)\}', rule_text, _regex.DOTALL)
    condition = _regex.search(r'condition:\s*(.+?)(?:\n\s*\n|\Z)', rule_text, _regex.DOTALL)

    unique_strings = len(strings_section)
    total_string_length = sum(len(s[1].strip()) for s in strings_section)

    # 特异性评分: 字符串数量与长度决定去误报能力
    if unique_strings >= 5 and total_string_length > 200:
        specificity = 85
    elif unique_strings >= 3:
        specificity = 60
    else:
        specificity = 35

    cond_text = condition.group(1) if condition else ''
    # 覆盖率评分: or 和 any of 越多，匹配范围越大
    or_count = len(_regex.findall(r'\bor\b', cond_text, _regex.IGNORECASE))
    any_count = cond_text.count('any of')
    coverage_potential = min(95, (or_count + any_count) * 15 + 50)

    # 性能风险评估: 正则+全范围扫描=高开销
    has_regex = '$' in cond_text and '*' in cond_text
    has_filesize = 'filesize' in cond_text
    perf_risk = 'high' if (has_regex and not has_filesize) else \
                'med'  if has_regex else 'low'

    return {
        'specificity': specificity,
        'coverage_potential': coverage_potential,
        'performance_risk': perf_risk,
        'string_count': unique_strings,
    }
