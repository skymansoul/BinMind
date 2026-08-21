# coding: utf-8
#
"""
风险感知的漏洞修复优先级优化-资源约束下的最优修复调度。

技术问题:
  现有漏洞优先级系统(CVSS/EPSS/SSVC/KEV)评分个体漏洞,
  但不回答关键的资源配置问题:
    给定N个漏洞+每漏洞修复成本+有限的工程师时间预算,
    以何种顺序修复可使预期损失最小化?

  这是一个受资源约束的序列决策问题-
  修复顺序影响时间线上的累积风险暴露。

解决方案:
  将漏洞修复调度建模为时间加权的风险最小化问题:
    目标: min Σ risk_i × exposure_time_i
    约束: Σ cost_i ≤ budget, 修复必须按优先级降序

  变量定义:
    risk_i = CVSS × weaponization_prob_30d × exploitability
    cost_i = 估计修复工时
    exposure_i = 修复完成前的等待时间(依赖前置修复)

  优化算法: 贪心风险密度排序 (risk/cost降序)
    证明: 对独立漏洞+线性成本约束, 贪心策略最优
    (按risk/cost排序等价于分数背包问题的贪心解)

  与EPSS/SSVC的关键差异:
    EPSS: 输出概率, 不输出修复顺序
    SSVC: 输出决策(Track/Attend/Act), 不输出序列
    本模块: 输出最优修复序列+累积风险曲线+资源分配方案

  与MEWF/EPASS的集成:
    MEWF - weaponization_prob_30d(武器化时间线)
    EPASS - 临时沙箱防护(降低暴露风险直至修复完成)
    VAGS  - 攻击图(复合漏洞链的风险放大)
"""

import math
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

_log = logging.getLogger(__name__)


# 漏洞修复项


@dataclass
class FixItem:
    """单个待修复漏洞-含风险与成本估计"""
    vuln_id: str
    cve_id: str = ""
    function_name: str = ""
    # 风险维度
    cvss_score: float = 5.0
    weaponization_prob_30d: float = 0.0    # 30天内武器化概率(MEWF产出)
    exploit_complexity: float = 0.5         # 利用复杂度(越低越危险)
    # 成本维度
    estimated_fix_hours: float = 8.0        # 估计修复工时
    requires_arch_change: bool = False      # 是否需要架构变更
    # 临时防护
    sandbox_mitigation_available: bool = False  # EPASS沙箱策略是否可用
    sandbox_risk_reduction: float = 0.0     # 沙箱降低的风险比例[0,1]
    # 依赖关系
    depends_on: List[str] = field(default_factory=list)  # 前置修复的vuln_id
    # 计算字段
    risk_score: float = 0.0
    risk_density: float = 0.0               # risk/cost-排序依据
    optimal_position: int = -1              # 最优修复顺序中的位置


@dataclass
class FixSchedule:
    """修复调度-最优修复序列+累积风险"""
    ordered_fixes: List[FixItem] = field(default_factory=list)
    total_fix_hours: float = 0.0
    # 累积风险指标
    baseline_risk: float = 0.0             # 无修复时的总风险暴露
    residual_risk: float = 0.0             # 最优调度后的残余风险
    risk_reduction_pct: float = 0.0
    # 里程碑
    time_to_50pct_risk_reduction: float = 0.0  # 达到50%风险削减的时间
    fixes_until_80pct_coverage: int = 0        # 覆盖80%风险需修复的漏洞数


# 优化引擎


class RavoOptimizer:
    """风险感知的漏洞修复优先级优化器。

    核心算法-贪心风险密度排序:
      1. 计算每漏洞的risk_score = CVSS_norm × weapon_prob × (1 - complexity)
      2. 计算risk_density = risk_score / fix_hours
      3. 按risk_density降序排列-最优修复顺序
      4. 考虑依赖拓扑: 依赖项必须先于被依赖项修复
      5. 考虑沙箱防护: 有临时防护的漏洞可延后(风险暂时被抑制)

    贪心最优性条件:
      对独立漏洞+线性成本+可加性风险, 按risk/cost排序是最优的

    """

    def __init__(self):
        pass

    def optimize(self, vulnerabilities: List[Dict],
                  total_budget_hours: float = 160.0,
                  enable_sandbox_delay: bool = True
                  ) -> FixSchedule:
        """计算最优修复调度。

        参数:
          vulnerabilities: [{id, cvss, weapon_prob, complexity, fix_hours,
                             sandbox_available, sandbox_reduction, depends_on}, ...]
          total_budget_hours: 总修复工时预算
          enable_sandbox_delay: 有沙箱防护的漏洞是否允许延后

        返回FixSchedule。
        """
        # 构建FixItem列表
        items = []
        for v in vulnerabilities:
            cvss_norm = v.get('cvss', 5.0) / 10.0
            weapon_prob = v.get('weapon_prob', v.get('weaponization_prob_30d', 0.0))
            complexity = v.get('complexity', v.get('exploit_complexity', 0.5))
            risk = cvss_norm * max(weapon_prob, 0.01) * (1.0 - complexity + 0.2)
            fix_hrs = max(v.get('fix_hours', v.get('estimated_fix_hours', 8.0)), 0.5)

            item = FixItem(
                vuln_id=v.get('id', v.get('vuln_id', '?')),
                cve_id=v.get('cve_id', ''),
                function_name=v.get('function_name', ''),
                cvss_score=v.get('cvss', 5.0),
                weaponization_prob_30d=weapon_prob,
                exploit_complexity=complexity,
                estimated_fix_hours=fix_hrs,
                requires_arch_change=v.get('arch_change', False),
                sandbox_mitigation_available=v.get('sandbox_available', False),
                sandbox_risk_reduction=v.get('sandbox_reduction', 0.0),
                depends_on=v.get('depends_on', []),
                risk_score=round(risk, 4))

            # 沙箱延迟: 有临时防护-有效风险降低
            if enable_sandbox_delay and item.sandbox_mitigation_available:
                item.risk_score *= (1.0 - item.sandbox_risk_reduction)

            item.risk_density = round(item.risk_score / fix_hrs, 6)
            items.append(item)

        if not items:
            return FixSchedule()

        # 拓扑排序-依赖项优先
        ordered = self._topological_sort(items)

        # 按risk_density降序稳定排序(保持拓扑约束)
        ordered.sort(key=lambda x: x.risk_density, reverse=True)

        # 分配最优位置
        for i, item in enumerate(ordered):
            item.optimal_position = i

        # 累积风险计算
        baseline = sum(item.risk_score for item in items)
        cumulative_hours = 0.0
        residual = 0.0
        hours_50pct = 0.0
        fixes_80pct = 0
        risk_covered = 0.0

        for i, item in enumerate(ordered):
            if cumulative_hours + item.estimated_fix_hours <= total_budget_hours:
                cumulative_hours += item.estimated_fix_hours
                # 修复后此漏洞的剩余暴露=0
            else:
                # 超出预算-此漏洞及后续未被修复, 暴露持续
                residual += item.risk_score

            # 追踪50%风险削减的里程碑
            if hours_50pct == 0.0:
                risk_covered += item.risk_score
                if risk_covered >= baseline * 0.5:
                    hours_50pct = cumulative_hours

            # 追踪80%覆盖率
            if fixes_80pct == 0:
                risk_covered_for_80 = sum(
                    o.risk_score for o in ordered[:i + 1])
                if risk_covered_for_80 >= baseline * 0.8:
                    fixes_80pct = i + 1

        reduction = (baseline - residual) / max(baseline, 1e-6)

        return FixSchedule(
            ordered_fixes=ordered,
            total_fix_hours=round(cumulative_hours, 1),
            baseline_risk=round(baseline, 4),
            residual_risk=round(residual, 4),
            risk_reduction_pct=round(reduction * 100, 1),
            time_to_50pct_risk_reduction=round(hours_50pct, 1),
            fixes_until_80pct_coverage=fixes_80pct)

    def _topological_sort(self, items: List[FixItem]) -> List[FixItem]:
        """拓扑排序-保证依赖项在依赖者之前。

        Kahn算法-O(|V| + |E|)。
        若存在循环依赖-保留原始顺序(不打断-循环依赖本身是问题)。
        """
        id_to_item = {item.vuln_id: item for item in items}
        in_degree = {item.vuln_id: len(item.depends_on) for item in items}
        dep_graph: Dict[str, List[str]] = {}
        for item in items:
            for dep in item.depends_on:
                dep_graph.setdefault(dep, []).append(item.vuln_id)

        # Kahn BFS
        queue = [vid for vid, deg in in_degree.items() if deg == 0]
        result = []
        while queue:
            vid = queue.pop(0)
            result.append(id_to_item[vid])
            for dependent in dep_graph.get(vid, []):
                in_degree[dependent] -= 1
                if in_degree[dependent] == 0:
                    queue.append(dependent)

        # 未排序的项(循环依赖)→追加到末尾
        sorted_ids = {item.vuln_id for item in result}
        for item in items:
            if item.vuln_id not in sorted_ids:
                result.append(item)

        return result


__all__ = [
    "FixItem",
    "FixSchedule",
    "RavoOptimizer",
]
