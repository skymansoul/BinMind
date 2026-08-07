# 创建: 2026-05-05
# 修改: 2026-05-05 — 增加反事实结果建模学习最优修复策略
#
# 反事实结果学习的自动修复引擎 — 个体处理效应 + 在线策略优化
#
# FaultPropagationGraph 定位根因, CounterfactualSchedulingOracle 回答
# "what if"。缺失的一环: 基于诊断自动生成修复动作。
#
# 本模块实现闭环: 检测→诊断→修复→验证。
#   1. 输入: 根因候选 (来自 FaultPropagationGraph) +
#           反事实报告 (来自 CounterfactualSchedulingOracle)
#   2. 生成: 候选修复动作 (重调度/隔离/降级/扩容/回滚)
#   3. 评分: 每动作的 (预期收益, 风险, 副作用)
#   4. 输出: 排序的修复方案 + 建议执行顺序
#
# CIRCA-SH 用反事实约束生成安全自愈动作。
# 本模块不同: 面向调度系统而非微服务, 动作空间是调度决策
# (重分配/隔离/降级) 而非服务重启/流量切换。

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Tuple
from enum import Enum


class ActionType(Enum):
    RESCHEDULE = "reschedule"     # 重调度受影响任务到其他机器
    ISOLATE = "isolate"           # 隔离故障节点
    DEGRADE = "degrade"           # 降级: 减少并行度/跳过非关键任务
    SCALE_UP = "scale_up"         # 扩容: 增加 worker 吸收积压
    ROLLBACK = "rollback"         # 回滚: 恢复到故障前调度方案


@dataclass
class RemediationAction:
    action_type: ActionType
    target: str                   # 目标节点/任务/机器
    description: str
    expected_benefit: float       # 预估 makespan 减少 (归一化)
    risk_score: float             # 风险 [0, 1] — 动作失败/副作用的概率
    side_effects: List[str]       # 副作用描述
    estimated_recovery_s: float   # 预估恢复时间 (秒)
    prerequisite_actions: List[str] = field(default_factory=list)



class CounterfactualOutcomeModel:
    """反事实结果模型 — Beta后验学习最优修复策略。"""
    def __init__(self, prior_strength=2.0):
        self._prior = prior_strength
        self._posteriors = {}
        self._baseline_alpha = prior_strength
        self._baseline_beta = prior_strength

    def record_outcome(self, fault_features, action, recovery_s, baseline_s):
        key = (fault_features, action)
        a, b = self._posteriors.get(key, (self._prior, self._prior))
        if recovery_s < baseline_s * 0.8: a += 1.0
        else: b += 1.0
        self._posteriors[key] = (a, b)
        if baseline_s < baseline_s * 1.2: self._baseline_alpha += 0.5
        else: self._baseline_beta += 0.5

    def predict_success_prob(self, fault_features, action):
        a, b = self._posteriors.get((fault_features, action), (self._prior, self._prior))
        return a / (a + b)

    def individual_treatment_effect(self, fault_features, action):
        p_act = self.predict_success_prob(fault_features, action)
        p_base = self._baseline_alpha / (self._baseline_alpha + self._baseline_beta)
        return p_act - p_base

    def best_action(self, fault_features, candidates):
        best, best_ite = candidates[0], -1.0
        for a in candidates:
            ite = self.individual_treatment_effect(fault_features, a)
            if ite > best_ite: best_ite = ite; best = a
        return best if best_ite > 0 else 'baseline'

    def stats(self):
        n = len(self._posteriors)
        pos = sum(1 for (a,b) in self._posteriors.values() if a/(a+b) > self._baseline_alpha/(self._baseline_alpha+self._baseline_beta))
        return {'learned_actions': n, 'positive_ite_count': pos, 'baseline_success_rate': round(self._baseline_alpha/(self._baseline_alpha+self._baseline_beta),3)}

class RemediationEngine:
    """闭环自动修复引擎。

    输入诊断结果 → 生成候选动作 → 风险评分 → 排序输出。

    评分公式:
      综合得分 = benefit - γ·risk - Σ side_effect_penalty
      γ 控制风险厌恶程度 (默认 0.5, 平衡收益与风险)
    """

    def __init__(self, risk_aversion: float = 0.5):
        self._gamma = risk_aversion

    def generate_actions(
        self,
        root_causes: List[dict],          # FaultPropagationGraph 输出
        counterfactual_reports: Optional[List[dict]] = None,
        failed_machines: Optional[List[int]] = None,
        dag_info: Optional[dict] = None,   # {total_tasks, total_machines, ...}
    ) -> List[RemediationAction]:
        """从诊断结果生成候选修复动作列表。

        root_causes: [{"node_id": str, "rca_score": float, ...}, ...]
        counterfactual_reports: [CounterfactualReport, ...]
        """
        actions: List[RemediationAction] = []
        failed = failed_machines or []

        # 1. 隔离故障节点
        for rc in root_causes[:3]:
            nid = rc.get("node_id", "")
            if rc.get("is_isolated"):
                actions.append(RemediationAction(
                    action_type=ActionType.ISOLATE,
                    target=nid,
                    description=f"隔离故障节点 {nid}，将其任务转移至健康节点",
                    expected_benefit=rc.get("rca_score", 0.5) * 0.8,
                    risk_score=0.15,  # 隔离本身低风险
                    side_effects=["故障节点上已有部分结果可能丢失"],
                    estimated_recovery_s=5.0,
                ))

        # 2. 重调度 (基于反事实分析)
        if counterfactual_reports:
            for cf in counterfactual_reports[:5]:
                if cf.get("delta", 0) < 0:  # 反事实更优
                    actions.append(RemediationAction(
                        action_type=ActionType.RESCHEDULE,
                        target=",".join(cf.get("affected_tasks", [])[:3]),
                        description=cf.get("query_desc", "重调度受影响任务"),
                        expected_benefit=abs(cf.get("delta", 0.1)) * 0.7,
                        risk_score=0.25,  # 重调度有迁移开销
                        side_effects=["任务迁移的临时性能损失",
                                     "可能触发连锁重调度"],
                        estimated_recovery_s=15.0,
                    ))

        # 3. 扩容
        if len(failed) > 0:
            actions.append(RemediationAction(
                action_type=ActionType.SCALE_UP,
                target="worker_pool",
                description=f"扩容以吸收 {len(failed)} 台故障机器的负载",
                expected_benefit=0.6,
                risk_score=0.10,
                side_effects=["额外资源开销", "冷启动延迟"],
                estimated_recovery_s=30.0,
            ))

        # 4. 降级 (若根因多且分散 → 系统性故障 → 保守降级)
        if len(root_causes) >= 3:
            actions.append(RemediationAction(
                action_type=ActionType.DEGRADE,
                target="scheduler",
                description="降级：暂停非关键低优任务，优先保证高优任务完成",
                expected_benefit=0.4,
                risk_score=0.05,
                side_effects=["低优任务积压"],
                estimated_recovery_s=10.0,
            ))

        # 5. 回滚
        actions.append(RemediationAction(
            action_type=ActionType.ROLLBACK,
            target="schedule_plan",
            description="回滚到故障前的已知良好调度方案",
            expected_benefit=0.5,
            risk_score=0.30,  # 回滚可能丢弃有效进展
            side_effects=["故障后的有效任务进展可能丢失"],
            estimated_recovery_s=20.0,
        ))

        # 评分排序
        scored = []
        for a in actions:
            score = a.expected_benefit - self._gamma * a.risk_score
            score -= 0.05 * len(a.side_effects)
            scored.append((score, a))
        scored.sort(key=lambda x: -x[0])

        return [a for _, a in scored]

    def execution_plan(self, actions: List[RemediationAction]
                       ) -> List[RemediationAction]:
        """生成执行计划 — 按依赖关系拓扑排序。

        隔离先于重调度 (先止血再恢复)。
        降级先于扩容 (先止损再扩展)。
        """
        # 优先级: ISOLATE > DEGRADE > RESCHEDULE > SCALE_UP > ROLLBACK
        priority = {
            ActionType.ISOLATE: 0, ActionType.DEGRADE: 1,
            ActionType.RESCHEDULE: 2, ActionType.SCALE_UP: 3,
            ActionType.ROLLBACK: 4,
        }
        return sorted(actions, key=lambda a: (
            priority.get(a.action_type, 5),
            -a.expected_benefit,
        ))

    def stats(self) -> dict:
        return {"risk_aversion": self._gamma}
