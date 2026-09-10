"""
函数级安全债务评分 — 复杂度×漏洞复发×调用关键度×修复年龄衰减。

问题定义:
  安全团队需要知道"哪些函数承载了最大的安全债务?" —
  不是问"哪些函数现在有漏洞"(那是 risk_surface.py)，而是问
  "哪些函数的开发实践和历史表明它们将来会有漏洞?"

  现有技术债务工具 (SonarQube, CodeClimate) 度量的是可维护性债务，
  不是安全债务。安全债务的特殊性:
    - 一次修复不等于债务清零 — 历史有漏洞的函数有复发倾向
    - 调用关键度放大债务 — hub 函数的债务波及所有调用者
    - 安全债务随时间指数累积 (每新增一个依赖→债务叠加)

  四维安全债务评分:
    1. 复杂度债务 — McCabe 圈复杂度
    2. 复发风险 — 该函数历史上被修补的次数 (漏洞复发信号)
    3. 调用关键度 — 调用面扇入/扇出 (hub 函数放大效应)
    4. 修复年龄衰减 — 最近一次修复距今时间 (旧修复=偿债充分)

  安全债务 = w1×complexity + w2×recurrence + w3×criticality
            - w4×age_attenuation

  SonarQube Technical Debt: 可维护性，非安全性.
  CWE-1126: 安全债务概念 (非定量).

修改记录:
  2025-02-06 09:37 - 初始版本，四维安全债务模型
"""

import math
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

DEFAULT_DEBT_WEIGHTS = (0.30, 0.35, 0.25, 0.10)
# complexity, recurrence, criticality, age_attenuation

@dataclass
class SecurityDebt:
    """单个函数的安全债务评分。"""
    function_name: str
    debt_score: float              # 0-10
    complexity_debt: float         # 复杂度贡献
    recurrence_risk: float         # 复发风险贡献
    criticality_debt: float        # 调用关键度贡献
    age_credit: float              # 修复年龄信用 (负值=降低债务)
    debt_trend: str = 'stable'     # rising / stable / declining
    recommendation: str = ''

def _complexity_debt(cyclomatic_complexity: int) -> float:
    """圈复杂度→安全债务映射。CC>20→高债务。"""
    if cyclomatic_complexity <= 5:
        return 0.5  # 简单函数也有基线债务
    if cyclomatic_complexity >= 50:
        return 10.0
    # 平方根映射使中等复杂度区分度更高
    return round(0.5 + (cyclomatic_complexity - 5) / 45 * 9.5, 1)

def _recurrence_risk(
    past_vuln_count: int,
    past_fix_count: int,
    months_since_last_vuln: float,
) -> float:
    """
    复发风险 — 函数历史上的漏洞/修复次数。

    每次历史漏洞→未来复发概率上升。但长期无漏洞→风险衰减。
    months_since_last_vuln > 24 → 衰减至 50%。
    """
    if past_vuln_count == 0:
        return 0.0

    # 累积复发: 每多一个历史漏洞→+2.0分, 最多 8.0
    raw = min(past_vuln_count * 2.0, 8.0)

    # 修复次数的影响: 多次修复同一函数→暗示深层问题
    if past_fix_count >= 3:
        raw += 1.5

    # 时间衰减
    if months_since_last_vuln > 24:
        raw *= 0.5
    elif months_since_last_vuln > 12:
        raw *= 0.7
    elif months_since_last_vuln > 6:
        raw *= 0.85

    return round(min(raw, 10.0), 1)

def _criticality_debt(fan_in: int, fan_out: int, is_exported: bool) -> float:
    """
    调用关键度 — hub 函数的安全债务影响更大。

    fan_in > 20 → 高关键度 (很多调用者依赖此函数)。
    is_exported → 外部可见→关键度+2.0。
    """
    raw = 0.0
    if fan_in <= 1:
        raw += 1.0  # 叶节点 — 基线
    elif fan_in <= 5:
        raw += 2.5
    elif fan_in <= 20:
        raw += 4.0
    else:
        raw += 6.0 + min((fan_in - 20) / 80 * 4.0, 4.0)

    # fan_out: 该函数依赖多少外部函数
    # 高 fan_out → 受外部变化影响大
    if fan_out > 20:
        raw += min((fan_out - 20) / 30 * 2.0, 2.0)

    if is_exported:
        raw += 2.0

    return round(min(raw, 10.0), 1)

def _age_credit(months_since_last_fix: float) -> float:
    """
    修复年龄信用 — 基于 Ebbinghaus 遗忘曲线变体。

    最近修复 (< 1 月) → 信用为 0 (还没时间验证修复质量)。
    修复后 6-24 月 → 信用最高 (修复已充分验证)。
    超过 36 月 → 信用开始下降 (代码可能又积累了新问题)。
    """
    m = months_since_last_fix
    if m < 1:
        return 0.0       # 刚刚修复 — 无信用
    if m < 6:
        return m / 6 * 2.0  # 线性累积 → 最多 2.0
    if m <= 24:
        return 2.0 + (m - 6) / 18 * 2.0  # → 最多 4.0
    # > 36 月 — 信用缓慢下降
    return max(1.5, 4.0 - (m - 36) / 24 * 2.5)

def score_security_debt(
    function_name: str = '',
    cyclomatic_complexity: int = 1,
    past_vuln_count: int = 0,
    past_fix_count: int = 0,
    months_since_last_vuln: float = 99.0,
    months_since_last_fix: float = 99.0,
    fan_in: int = 0,
    fan_out: int = 0,
    is_exported: bool = False,
    weights: Optional[Tuple[float, float, float, float]] = None,
) -> SecurityDebt:
    """
    计算单函数的安全债务评分。

    返回 SecurityDebt (0-10)，含四项因子分解。
    """
    w = weights or DEFAULT_DEBT_WEIGHTS

    cd = _complexity_debt(cyclomatic_complexity)
    rr = _recurrence_risk(past_vuln_count, past_fix_count, months_since_last_vuln)
    crd = _criticality_debt(fan_in, fan_out, is_exported)
    ac = _age_credit(months_since_last_fix)

    raw = w[0]*cd + w[1]*rr + w[2]*crd - w[3]*ac
    score = round(max(0.0, min(10.0, raw)), 1)

    # 趋势判定
    if rr >= 5.0 and months_since_last_vuln < 6:
        trend = 'rising'
    elif ac >= 3.0 and rr <= 2.0:
        trend = 'declining'
    else:
        trend = 'stable'

    # 推荐
    if score >= 7.0:
        rec = '高安全债务 — 建议: 1) 代码审计; 2) 增加单元测试覆盖; 3) 评估重构可行性'
    elif score >= 4.0:
        rec = '中等安全债务 — 建议: 增加模糊测试覆盖此函数'
    else:
        rec = '低安全债务 — 维持现有监控'

    return SecurityDebt(
        function_name=function_name or 'unknown',
        debt_score=score,
        complexity_debt=cd,
        recurrence_risk=rr,
        criticality_debt=crd,
        age_credit=round(ac, 1),
        debt_trend=trend,
        recommendation=rec,
    )

def debt_summary(scores: List[SecurityDebt]) -> Dict[str, Any]:
    """安全债务统计摘要。"""
    if not scores:
        return {'total': 0, 'mean_debt': 0, 'critical_functions': []}

    high = [s for s in scores if s.debt_score >= 7.0]
    rising = [s for s in scores if s.debt_trend == 'rising']

    return {
        'total_functions': len(scores),
        'mean_debt': round(sum(s.debt_score for s in scores) / len(scores), 1),
        'max_debt': max(s.debt_score for s in scores),
        'high_debt_count': len(high),
        'rising_trend_count': len(rising),
        'top_debt_functions': [
            {'function': s.function_name, 'debt': s.debt_score,
             'trend': s.debt_trend, 'rec': s.recommendation}
            for s in sorted(scores, key=lambda x: x.debt_score, reverse=True)[:5]
        ],
    }
