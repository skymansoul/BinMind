"""
二进制特化修复难度评分 — CFG复杂度 + 调用面影响 + 加固交互。

问题定义:
  IBM VRC 专利 提供了软件层面的修复复杂度评分，
  但未考虑二进制特有因素:
    1. stripped binary → 无符号表 → 定位修复点的额外成本
    2. PLT/GOT 影响 — 修复影响了多少外部调用点
    3. 加固交互 — 修复后是否需要重新调整编译标志
    4. 调用面扇入 — 修复此函数会影响多少调用者

  本模块提供多因素修复难度评分 (0-10)，因子权重可调。

评分模型 (加法分解):
  difficulty = w_cc × CC_factor + w_fanin × fanin_factor
             + w_stripped × strip_penalty + w_plt × PLT_factor
             + w_hardening × hardening_interaction

与 IBM VRC 的区别:
  IBM VRC 使用 CVE 元数据 + 组织成熟度 + 资产价值。
  本模块使用二进制逆向分析数据 (CFG/调用图/导入表/加固状态)。
  IBM 面向企业 IT 资产管理，本模块面向逆向工程师和安全研究员。

修改记录:
  2024-11-05 13:41 - 初始版本，五因素加法模型
"""

import math
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple


DEFAULT_WEIGHTS = {
    'cc': 0.30,        # 圈复杂度
    'fanin': 0.25,     # 调用面扇入
    'stripped': 0.15,  # stripped 二进制惩罚
    'plt': 0.20,       # PLT/GOT 影响面
    'hardening': 0.10, # 加固交互复杂度
}


@dataclass
class RemediationScore:
    """单个漏洞的修复难度评分。"""
    function_name: str
    vuln_type: str
    difficulty: float              # 0-10, 综合评分
    cc_factor: float               # 圈复杂度贡献
    fanin_factor: float             # 调用面贡献
    strip_penalty: float            # stripped 惩罚
    plt_factor: float               # PLT 影响贡献
    hardening_interaction: float    # 加固交互贡献
    effort_estimate: str = ''       # 人力估算 (小时/天/周)

    def __post_init__(self):
        if self.difficulty <= 2.0:
            self.effort_estimate = 'hours'
        elif self.difficulty <= 5.0:
            self.effort_estimate = 'days'
        elif self.difficulty <= 8.0:
            self.effort_estimate = 'weeks'
        else:
            self.effort_estimate = 'months'


def _cc_factor(cyclomatic_complexity: int) -> float:
    """
    圈复杂度 → [0, 1] 归一化因子。

    McCabe 建议: ≤10 低风险, 11-20 中风险, >20 高风险。
    超线性映射: 修复难度随 CC 增长非线性加速 (复杂函数中的改动
    更容易引入回归缺陷)。
    """
    if cyclomatic_complexity <= 5:
        return 0.0
    # 平方根压缩: √ / √45, ceil at 50
    clamped = min(cyclomatic_complexity, 50)
    return round(math.sqrt(clamped - 5) / math.sqrt(45), 4)


def _fanin_factor(callers: int) -> float:
    """
    调用面扇入 → 归一化因子。

    每增加一个调用者 → 回归测试面 +1。
    对数压缩: 1-2 个调用者影响小, 50+ 影响极大。
    """
    if callers <= 1:
        return 0.05  # 最小基数 (至少调用者自身)
    return round(min(math.log2(callers) / math.log2(100), 1.0), 4)


def _strip_penalty(has_symbols: bool, is_stripped: Optional[bool] = None) -> float:
    """
    stripped 二进制惩罚。

    无符号表 → 函数边界模糊 → 修复后验证困难 (需额外反汇编)。
    完全 stripped → 0.8 惩罚, 部分 stripped → 0.4, 有符号 → 0.0。
    """
    if is_stripped is True:
        return 0.8
    if has_symbols:
        return 0.0
    return 0.4  # 不确定 — 保守假设部分 stripped


def _plt_factor(plt_entries: int, is_exported: bool = False) -> float:
    """
    PLT/GOT 影响面 → 归一化因子。

    修复函数在 PLT 中有条目 → 外部可见 → ABI 兼容性约束。
    导出函数 → 修复可能破坏下游二进制。
    """
    base = min(plt_entries / 20.0, 1.0) if plt_entries > 0 else 0.0
    if is_exported:
        base = max(base, 0.5)  # 导出函数最少 0.5 的 PLT 影响
    return round(base, 4)


def _hardening_interaction(
    vuln_type: str,
    current_checksec: Dict[str, Any],
    fix_requires_rebuild: bool = True,
) -> float:
    """
    加固交互复杂度。

    修复此漏洞是否需要重新配置加固标志?
    例: 修复 GOT overwrite 后需要启用 Full RELRO → 检查当前 RELRO 状态。
    """
    if not fix_requires_rebuild:
        return 0.0

    vtype = vuln_type.lower()
    interaction = 0.0

    # 漏洞类型 → 推荐加固 → 检查是否已启用
    if 'stack' in vtype or 'overflow' in vtype:
        if not current_checksec.get('Canary', False):
            interaction += 0.25
        if not current_checksec.get('NX', False):
            interaction += 0.10
    if 'got' in vtype or 'overwrite' in vtype:
        if 'full' not in current_checksec.get('RELRO', '').lower():
            interaction += 0.35
    if 'format' in vtype:
        if not current_checksec.get('FORTIFY', False):
            interaction += 0.20

    return round(min(interaction, 1.0), 4)


def score_remediation(
    function_name: str,
    vuln_type: str,
    cyclomatic_complexity: int = 1,
    callers: int = 0,
    has_symbols: bool = True,
    is_stripped: Optional[bool] = None,
    plt_entries: int = 0,
    is_exported: bool = False,
    current_checksec: Optional[Dict[str, Any]] = None,
    weights: Optional[Dict[str, float]] = None,
) -> RemediationScore:
    """
    计算单个漏洞的修复难度。

    返回 RemediationScore (0-10, 综合评分)。
    """
    w = weights or DEFAULT_WEIGHTS
    checksec = current_checksec or {}

    cc_f = _cc_factor(cyclomatic_complexity)
    fanin_f = _fanin_factor(callers)
    strip_f = _strip_penalty(has_symbols, is_stripped)
    plt_f = _plt_factor(plt_entries, is_exported)
    hard_f = _hardening_interaction(vuln_type, checksec)

    raw = (
        w['cc'] * cc_f +
        w['fanin'] * fanin_f +
        w['stripped'] * strip_f +
        w['plt'] * plt_f +
        w['hardening'] * hard_f
    )
    difficulty = round(raw * 10.0, 1)

    return RemediationScore(
        function_name=function_name,
        vuln_type=vuln_type,
        difficulty=difficulty,
        cc_factor=round(cc_f * 10.0, 1),
        fanin_factor=round(fanin_f * 10.0, 1),
        strip_penalty=round(strip_f * 10.0, 1),
        plt_factor=round(plt_f * 10.0, 1),
        hardening_interaction=round(hard_f * 10.0, 1),
    )


def batch_score(
    vulnerabilities: List[Dict[str, Any]],
    checksec: Optional[Dict[str, Any]] = None,
) -> List[RemediationScore]:
    """
    批量评分 — 按 difficulty + CVSS 加权排序 (优先修复高危+易修复)。
    """
    results = []
    for v in vulnerabilities:
        score = score_remediation(
            function_name=v.get('function_name', v.get('name', 'unknown')),
            vuln_type=v.get('type', 'unknown'),
            cyclomatic_complexity=v.get('cyclomatic_complexity', 1),
            callers=v.get('callers', v.get('fan_in', 0)),
            has_symbols=v.get('has_symbols', True),
            is_stripped=v.get('is_stripped'),
            plt_entries=v.get('plt_entries', 0),
            is_exported=v.get('is_exported', False),
            current_checksec=checksec,
        )
        results.append(score)
    return results


def prioritize(
    scores: List[RemediationScore],
    cvss_scores: Optional[Dict[str, float]] = None,
) -> List[Dict[str, Any]]:
    """
    修复优先级排序: CVSS 高 + difficulty 低 → 优先修复。

    返回排序后的摘要列表，可直接嵌入报告。
    """
    cvss_map = cvss_scores or {}
    ranked = []
    for s in scores:
        cvss = cvss_map.get(s.function_name, 5.0)
        # 优先级分 = CVSS / (difficulty + 0.5) → 高风险+易修复=高分
        priority = cvss / (s.difficulty + 0.5)
        ranked.append({
            'function': s.function_name,
            'vuln_type': s.vuln_type,
            'difficulty': s.difficulty,
            'effort': s.effort_estimate,
            'cvss': cvss,
            'priority_score': round(priority, 2),
            'breakdown': {
                'cc': s.cc_factor,
                'fanin': s.fanin_factor,
                'stripped': s.strip_penalty,
                'plt': s.plt_factor,
                'hardening': s.hardening_interaction,
            },
        })
    ranked.sort(key=lambda r: r['priority_score'], reverse=True)
    return ranked
