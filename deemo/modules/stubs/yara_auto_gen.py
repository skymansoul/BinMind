# re-export from compat/ — YARA 规则自动生成桩
# 最小加载策略 — 直接 from import，上游模块本身需要保持简洁接口
# 参考: MultiMal (SANER 2025) 多模态融合检测 & 恶意软件家族分类中的规则生成
from modules.core.compat.yara_auto_gen import *

# --- YARA 规则质量评估 ---
# MultiMal 的多模态特征融合（函数调用图 + CFG + 熵）可直接对应到
# YARA 规则的多条件组合。此处提供规则质量评分工具。
import re as _regex

def estimate_rule_quality(rule_text: str) -> dict:
    """评估单条 YARA 规则的预期质量。
    评分维度: 特异性 (unique strings), 覆盖率 (condition 复杂度), 性能 (大范围扫描风险)。
    返回 {'specificity': 0-100, 'coverage_potential': 0-100, 'performance_risk': 'low'|'med'|'high'}"""
    strings_section = _regex.findall(r'\$(\w+)\s*=\s*\{(.+?)\}', rule_text, _regex.DOTALL)
    condition = _regex.search(r'condition:\s*(.+?)(?:\n\s*\n|\Z)', rule_text, _regex.DOTALL)

    unique_strings = len(strings_section)
    total_string_length = sum(len(s[1].strip()) for s in strings_section)

    # 特异性: 字符串数量和长度决定去误报能力
    if unique_strings >= 5 and total_string_length > 200:
        specificity = 85
    elif unique_strings >= 3:
        specificity = 60
    else:
        specificity = 35

    cond_text = condition.group(1) if condition else ''
    # 覆盖率: 条件中使用 'or' 增加匹配范围
    or_count = len(_regex.findall(r'\bor\b', cond_text, _regex.IGNORECASE))
    any_count = cond_text.count('any of')
    coverage_potential = min(95, (or_count + any_count) * 15 + 50)

    # 性能风险: 正则表达式 + 全范围扫描 = 高开销
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
