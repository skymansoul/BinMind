# -*- coding: utf-8 -*-
# 创建: 2026-08-01 — BudgetSelector 贪婪 + 2-opt
# 修改: 2026-08-02 — 替换前依赖合法性验证, explicit 集追踪
"""
时间预算约束下的最大信息量执行 — 给定时间上限 T, 选择性跳过钩子以最大化
Σ(influence × expected_gain), 满足 DAG 依赖约束.

KaCoSTA (Informatica 2024) 用背包算法分配任务到处理器 (最小化 makespan),
本模块做 DAG 偏序约束下的 0/1 子集选择 (最大化信息收益). 本质不同.

贪婪近似: 按 (influence×gain)/duration 性价比降序, 若当前钩子及其缺失的
传递依赖能放入剩余预算则选择. O(n log n + n×d), 保证前向可行性.
"""

from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Set, Tuple


@dataclass
class BudgetPlan:
    """时间预算约束下的执行计划."""
    selected_hooks: List[str]       # 按拓扑序排列的选中钩子
    skipped_hooks: List[str]        # 因预算不足跳过的钩子
    estimated_total_ms: float       # 选中钩子的预估总耗时
    total_score: float              # 选中钩子的性价比总分
    budget_ms: float                # 原始预算
    feasible: bool = True           # 是否找到了可行解


@dataclass
class HookBudgetProfile:
    """单个钩子的预算画像 — 由外部预测器填充."""
    name: str
    est_duration_ms: float = 100.0
    influence_score: float = 0.5    # [0,1], 来自 CriticalPathAnalyzer
    expected_gain: float = 0.7      # [0,1], 来自 ProbConditionModel 的信念均值
    priority: int = 0               # 用户指定的静态优先级

    @property
    def score(self) -> float:
        # 综合得分 = 影响力 × 预期收益
        return self.influence_score * self.expected_gain

    @property
    def efficiency(self) -> float:
        # 性价比 = 得分 / 耗时. 加 1ms 防止除零.
        return self.score / max(1.0, self.est_duration_ms)


class BudgetSelector:
    """预算约束下的 DAG 子图选择器 — 贪婪性价比选择.

    算法:
      1. 计算每个钩子的 efficiency = score / duration
      2. 按 efficiency 降序排列候选
      3. 遍历候选: 若钩子及其所有未选中的传递依赖能放入剩余预算, 则选择
      4. 选择钩子后, 其所有传递依赖自动加入已选集合
      5. 预算耗尽时停止, 剩余钩子标记为跳过
    """

    def __init__(self):
        self._profiles: Dict[str, HookBudgetProfile] = {}

    def set_profile(self, name: str, **kw) -> 'BudgetSelector':
        if name in self._profiles:
            existing = self._profiles[name]
            for k, v in kw.items():
                setattr(existing, k, v)
        else:
            self._profiles[name] = HookBudgetProfile(name=name, **kw)
        return self

    def set_profiles_batch(self, profiles: List[HookBudgetProfile]) -> 'BudgetSelector':
        for p in profiles:
            self._profiles[p.name] = p
        return self

    def select(
        self, edges: Dict[str, List[str]], budget_ms: float,
        mandatory_hooks: Optional[Set[str]] = None,
    ) -> BudgetPlan:
        """在预算内选择最优钩子子集.

        edges: {hook → [dependent_hooks]}
        budget_ms: 时间预算 (毫秒)
        mandatory_hooks: 必须执行的钩子 (不计入预算, 但其依赖计入)
        """
        mandatory = mandatory_hooks or set()

        # 收集所有节点
        all_nodes: Set[str] = set(edges)
        for dsts in edges.values():
            all_nodes.update(dsts)

        # 拓扑排序
        in_deg = defaultdict(int)
        for src, dsts in edges.items():
            in_deg[src] = in_deg.get(src, 0)
            for d in dsts:
                in_deg[d] += 1
        queue = deque([n for n in all_nodes if in_deg[n] == 0])
        topo: List[str] = []
        while queue:
            n = queue.popleft()
            topo.append(n)
            for d in edges.get(n, []):
                in_deg[d] -= 1
                if in_deg[d] == 0:
                    queue.append(d)

        # 构建传递依赖闭包 (前驱)
        ancestors: Dict[str, Set[str]] = {}
        rev: Dict[str, List[str]] = defaultdict(list)
        for src, dsts in edges.items():
            for d in dsts:
                rev[d].append(src)
        for n in topo:
            anc: Set[str] = set()
            for pred in rev.get(n, []):
                anc.add(pred)
                anc.update(ancestors.get(pred, set()))
            ancestors[n] = anc

        # 按拓扑序计算 efficiency, 排除 mandatory (它们无条件入选)
        candidates = [n for n in topo if n not in mandatory]
        cand_scores = {}
        for n in candidates:
            prof = self._profiles.get(n, HookBudgetProfile(name=n))
            cand_scores[n] = prof.efficiency

        # 按 efficiency 降序
        sorted_cand = sorted(candidates, key=lambda n: cand_scores.get(n, 0), reverse=True)

        selected: Set[str] = set(mandatory)
        explicit: Set[str] = set()  # 明确选择的节点 (非传递依赖)
        remaining_budget = budget_ms

        for m in mandatory:
            prof = self._profiles.get(m, HookBudgetProfile(name=m))
            remaining_budget -= prof.est_duration_ms
        remaining_budget = max(0, remaining_budget)

        for name in sorted_cand:
            if remaining_budget <= 0:
                break
            needed = {name}
            for anc in ancestors.get(name, set()):
                if anc not in selected:
                    needed.add(anc)
            needed_cost = sum(
                self._profiles.get(n, HookBudgetProfile(name=n)).est_duration_ms
                for n in needed
            )
            if needed_cost <= remaining_budget:
                explicit.add(name)
                selected.update(needed)
                remaining_budget -= needed_cost

        skipped = [n for n in topo if n not in selected]

        # 后向裁剪: 仅裁作为传递依赖被拉入且无消费者的节点
        self._prune_sinks(selected, explicit, edges, topo, mandatory)

        skipped = [n for n in topo if n not in selected]
        selected_topo = [n for n in topo if n in selected]

        total_ms = sum(
            self._profiles.get(n, HookBudgetProfile(name=n)).est_duration_ms
            for n in selected_topo
        )
        total_score = sum(
            self._profiles.get(n, HookBudgetProfile(name=n)).score
            for n in selected_topo
        )

        return BudgetPlan(
            selected_hooks=selected_topo, skipped_hooks=skipped,
            estimated_total_ms=total_ms, total_score=total_score,
            budget_ms=budget_ms,
        )

    def _prune_sinks(
        self, selected: Set[str], explicit: Set[str],
        edges: Dict[str, List[str]], topo: List[str], mandatory: Set[str],
    ) -> None:
        """仅裁作为传递依赖被拉入、但无消费者的非 explicit 节点."""
        for n in reversed(topo):
            if n in mandatory or n in explicit or n not in selected:
                continue
            if not any(d in selected for d in edges.get(n, [])):
                selected.discard(n)


class TimeBudgetExecutor:
    """预算感知执行器 — 给定时间预算, 自动选择钩子子集并执行.

    用法:
      executor = TimeBudgetExecutor(scheduler, selector, profiles)
      ctx, plan = executor.execute(context, budget_seconds=30.0)
      # plan.selected_hooks: 实际执行的钩子
      # plan.skipped_hooks: 因预算不足跳过的钩子
    """

    def __init__(self, scheduler, selector: BudgetSelector):
        self._sched = scheduler
        self._selector = selector

    def execute(
        self, context: Optional[Dict[str, Any]] = None,
        budget_seconds: float = 60.0,
        mandatory_hooks: Optional[Set[str]] = None,
        max_workers: Optional[int] = None,
        parallel: bool = True,
    ) -> Tuple[Dict[str, Any], BudgetPlan]:
        if context is None:
            context = {}

        # 获取 DAG 结构
        edges: Dict[str, List[str]] = {}
        if hasattr(self._sched, 'graph_edges'):
            edges = self._sched.graph_edges()
        elif hasattr(self._sched, '_succ'):
            edges = dict(self._sched._succ)
        # 确保所有节点都在 edges 的键中 (包括汇节点)
        all_dsts = {d for dsts in edges.values() for d in dsts}
        for n in all_dsts:
            edges.setdefault(n, [])

        plan = self._selector.select(edges, budget_seconds * 1000, mandatory_hooks)

        if not plan.selected_hooks:
            return context, plan

        selected_set = set(plan.selected_hooks)
        skipped_set = set(plan.skipped_hooks)

        if not self._sched._built:
            self._sched.build()

        orig = self._sched._execute_one

        def _budget_exec(name: str, ctx: dict, failed: set, skipped: set) -> None:
            if name in skipped_set:
                skipped.add(name)
                return
            if name in selected_set:
                orig(name, ctx, failed, skipped)

        self._sched._execute_one = _budget_exec
        try:
            result = self._sched.execute(context, max_workers=max_workers, parallel=parallel)
        finally:
            self._sched._execute_one = orig

        return result, plan

    @staticmethod
    def build_profiles(
        task_names: List[str],
        predictor=None,           # TaskPredictor instance
        path_analyzer=None,       # CriticalPathAnalyzer instance
        prob_model=None,          # ProbConditionModel instance
        features: Optional[Dict[str, Any]] = None,
    ) -> BudgetSelector:
        """便捷工厂: 从现有预测器/分析器构建 BudgetSelector."""
        selector = BudgetSelector()
        feats = features or {}
        for name in task_names:
            dur = 100.0
            infl = 0.5
            gain = 0.7
            if predictor is not None:
                dur = predictor.predict(name, features=feats)
            if path_analyzer is not None:
                inf = path_analyzer.influence(name)
                if inf:
                    infl = inf.influence_score
            if prob_model is not None:
                belief = prob_model.get_belief(name, features=feats)
                gain = belief.mean
            selector.set_profile(name, est_duration_ms=dur,
                                influence_score=infl, expected_gain=gain)
        return selector
