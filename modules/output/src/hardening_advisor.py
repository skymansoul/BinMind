"""
Pareto 最优加固顾问 — 二元组 (安全增益, 重建成本) 的多目标优化。

问题定义:
  安全团队面对 checksec 输出的五项加固措施 (NX/PIE/Canary/RELRO/FORTIFY)，
  需要回答: 给定有限的 rebuild 预算，先开哪个？
  现有工具 (checksec, hardening-check) 只报告当前状态，不做 ROI 分析。

  每个加固措施的安全增益不是常数 — 它取决于:
    1. 二进制中实际存在的漏洞类型 (栈溢出 → Canary 高增益；GOT覆写 → RELRO 高增益)
    2. 二进制在传染图中的位置 (处于 contagion hub 的二进制加固收益更大)
    3. 当前加固基线 (已开启 4/5 → 最后一个的边际增益递减)

Pareto 前沿构建:
  option_i = (security_gain_i, rebuild_cost_i)
  option_i 被 option_j 支配: gain_i <= gain_j AND cost_i >= cost_j (至少一个严格不等)
  前沿 = 所有不被任何其他 option 支配的 option 集合。

  Cyber ITL Binary Hardening in IoT Firmware 提供加固分布统计但无 ROI 模型。

修改记录:
  2024-09-02 09:35 - 初始版本，单二进制加固 ROI
"""

import math
from dataclasses import dataclass, field
from typing import Any, Dict, FrozenSet, List, Optional, Set, Tuple

# 漏洞类型 → 各加固措施的收益权重 [0, 1]
# 权重含义: 该加固措施对该类漏洞的缓解程度
# 1.0 = 完全无效 (加固与此漏洞无关), 0.0 = 完全缓解
_VULN_HARDENING_MATRIX: Dict[str, Dict[str, float]] = {
    'stack_overflow':       {'Canary': 0.85, 'NX': 0.15, 'PIE': 0.25, 'RELRO': 0.05, 'FORTIFY': 0.30},
    'heap_overflow':        {'Canary': 0.05, 'NX': 0.40, 'PIE': 0.20, 'RELRO': 0.15, 'FORTIFY': 0.45},
    'format_string':        {'Canary': 0.15, 'NX': 0.10, 'PIE': 0.20, 'RELRO': 0.50, 'FORTIFY': 0.60},
    'use_after_free':       {'Canary': 0.10, 'NX': 0.50, 'PIE': 0.30, 'RELRO': 0.20, 'FORTIFY': 0.15},
    'integer_overflow':     {'Canary': 0.20, 'NX': 0.10, 'PIE': 0.15, 'RELRO': 0.05, 'FORTIFY': 0.55},
    'null_ptr_deref':       {'Canary': 0.05, 'NX': 0.60, 'PIE': 0.05, 'RELRO': 0.05, 'FORTIFY': 0.10},
    'got_overwrite':        {'Canary': 0.05, 'NX': 0.10, 'PIE': 0.30, 'RELRO': 0.95, 'FORTIFY': 0.05},
    'code_execution':       {'Canary': 0.30, 'NX': 0.75, 'PIE': 0.45, 'RELRO': 0.20, 'FORTIFY': 0.25},
}

MEASURES = ('NX', 'PIE', 'Canary', 'RELRO', 'FORTIFY')

# 相对重建成本 (归一化, 0-1)
# RELRO/FORTIFY 仅需重链 → 低成本
# PIE 需重编译+可能 ABI 调整 → 高成本
_DEFAULT_COSTS = {'NX': 0.10, 'PIE': 0.55, 'Canary': 0.25, 'RELRO': 0.15, 'FORTIFY': 0.20}

@dataclass
class HardeningOption:
    """单个加固选项 — Pareto 前沿的一个候选点。"""
    measure: str
    security_gain: float          # CVSS 环境评分预期降幅 [0, 10]
    cost: float                   # 归一化重建成本 [0, 1]
    affected_vuln_count: int      # 该措施影响的漏洞数
    efficiency: float             # gain / (cost + ε)，性价比
    rationale: str = ""

    def dominates(self, other: 'HardeningOption') -> bool:
        """self Pareto-支配 other: gain ≥ 且 cost ≤，至少一个严格。"""
        better_gain = self.security_gain >= other.security_gain
        better_cost = self.cost <= other.cost
        strictly = (self.security_gain > other.security_gain or
                    self.cost < other.cost)
        return better_gain and better_cost and strictly

def _measure_enabled(checksec: Dict[str, Any], measure: str) -> bool:
    if measure == 'RELRO':
        return 'full' in checksec.get('RELRO', '').lower()
    return bool(checksec.get(measure, False))

def compute_hardening_gains(
    vulnerabilities: List[Dict[str, Any]],
    current_checksec: Dict[str, Any],
    contagion_weight: float = 1.0,
    costs: Optional[Dict[str, float]] = None,
) -> List[HardeningOption]:
    """
    为每个未启用的加固措施计算安全增益。

    gain(measure) = Σ_i cvss_i × matrix[type_i][measure] ×
    contagion_weight × marginal_decay(already_enabled_count)。

    参数: vulnerabilities 漏洞列表, current_checksec checksec
    输出, contagion_weight ≥1.0 放大枢纽二进制的加固收益,
    costs 可选成本覆盖; 返回按 efficiency 降序的
    HardeningOption 列表。
    """
    cost_map = costs or _DEFAULT_COSTS
    already = sum(1 for m in MEASURES if _measure_enabled(current_checksec, m))
    # 已启用较多时，剩余措施的边际收益递减
    marginal = max(0.3, 1.0 - already * 0.15)

    options: List[HardeningOption] = []

    for measure in MEASURES:
        if _measure_enabled(current_checksec, measure):
            continue

        total_gain = 0.0
        affected = 0
        for vuln in vulnerabilities:
            vtype = vuln.get('type', '').lower()
            cvss = vuln.get('cvss_base', vuln.get('cvss_score', 5.0))

            # 矩阵匹配: 优先精确，回退部分匹配
            weight = 0.1  # 默认低权重
            for key, weights in _VULN_HARDENING_MATRIX.items():
                if key in vtype or vtype in key:
                    weight = weights.get(measure, 0.1)
                    break

            if weight > 0.1:  # 至少有一些缓解效果
                affected += 1
            # gain = CVSS × 缓解权重 × 传染放大 × 边际递减
            total_gain += cvss * weight * contagion_weight * marginal

        # 上限: 单措施最多降低 CVSS 总分 3 分 (现实约束)
        total_gain = min(total_gain, 3.0)

        cost = cost_map.get(measure, 0.2)
        efficiency = total_gain / (cost + 0.01) if total_gain > 0 else 0.0

        options.append(HardeningOption(
            measure=measure,
            security_gain=round(total_gain, 2),
            cost=round(cost, 2),
            affected_vuln_count=affected,
            efficiency=round(efficiency, 2),
            rationale=_build_rationale(measure, affected, total_gain, contagion_weight),
        ))

    options.sort(key=lambda o: o.efficiency, reverse=True)
    return options

def _build_rationale(measure: str, affected: int, gain: float,
                     contagion_w: float) -> str:
    """构造人类可读的推荐理由。"""
    base = f"{measure} 启用: 影响 {affected} 个漏洞, 预期 CVSS 降幅 {gain:.1f}"
    if contagion_w > 1.0:
        base += f", 传染权重 {contagion_w:.1f}x"
    return base

def pareto_frontier(options: List[HardeningOption]) -> List[HardeningOption]:
    """从 options 中提取 Pareto 前沿 — 所有非支配点。"""
    frontier: List[HardeningOption] = []
    for opt in options:
        dominated = any(other.dominates(opt) for other in options if other is not opt)
        if not dominated:
            frontier.append(opt)
    frontier.sort(key=lambda o: o.efficiency, reverse=True)
    return frontier

def recommend(
    vulnerabilities: List[Dict[str, Any]],
    current_checksec: Dict[str, Any],
    budget: float = 0.5,
    contagion_weight: float = 1.0,
) -> Dict[str, Any]:
    """
    给定预算约束，返回推荐加固方案。

    budget: 0-1 归一化总成本预算。
    贪心选择效率最高的措施直到预算耗尽。

    返回值可直接嵌入 Markdown/JSON 报告。
    """
    all_options = compute_hardening_gains(
        vulnerabilities, current_checksec, contagion_weight
    )

    if not all_options:
        return {
            'enabled_count': sum(1 for m in MEASURES if _measure_enabled(current_checksec, m)),
            'remaining_measures': 0,
            'recommendations': [],
            'total_gain': 0.0,
            'total_cost': 0.0,
            'pareto_frontier': [],
        }

    frontier = pareto_frontier(all_options)

    selected = []
    spent = 0.0
    total_gain = 0.0
    for opt in all_options:
        if spent + opt.cost <= budget:
            selected.append(opt)
            spent += opt.cost
            total_gain += opt.security_gain

    return {
        'enabled_count': sum(1 for m in MEASURES if _measure_enabled(current_checksec, m)),
        'remaining_measures': len(all_options),
        'recommendations': [
            {'measure': o.measure, 'gain': o.security_gain,
             'cost': o.cost, 'efficiency': o.efficiency,
             'rationale': o.rationale}
            for o in selected
        ],
        'total_gain': round(total_gain, 2),
        'total_cost': round(spent, 2),
        'pareto_frontier': [
            {'measure': o.measure, 'gain': o.security_gain, 'cost': o.cost}
            for o in frontier
        ],
    }
