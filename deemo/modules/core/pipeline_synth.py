# coding: utf-8
"""
管道自动合成 — 给定二进制特征与钩子池, 自动构造最优 DAG 拓扑.

AutoML 管道构造 (如 TPOT, Auto-Sklearn) 面向 ML 模型选择与超参调优,
使用遗传算法搜索管道空间. 本模块的不同:
  1. 搜索空间是 DAG 拓扑而非线性管道 — 节点间存在偏序约束
  2. 合法性由钩子模式签名自动判定 — 输入的 required_reads 必须被上游产出
  3. 优化目标复合: 预期信息增益 / 预估耗时, 受时间预算约束
  4. 构造 + 2-opt 局部搜索, 而非遗传算法 (避免过长搜索时间)

算法:
  1. 从初始可用键集出发, 筛选所有依赖满足的候选钩子
  2. 贪心选择 (expected_gain × influence) / duration 最大者
  3. 所选钩子的产出键加入可用集, 解锁新的候选
  4. 重复至预算耗尽或无候选
  5. 2-opt: 尝试用单个未选钩子替换已选钩子, 若提升效用且满足预算则保留
"""

from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from modules.core.schema_inference import SchemaModel, HookSignature


@dataclass
class SynthesizedPipeline:
    """自动合成的管道描述."""
    edges: Dict[str, List[str]]           # 合成的 DAG 邻接表
    selected_hooks: List[str]             # 拓扑序排列
    skipped_hooks: List[str]              # 因依赖不满足或预算不足跳过的钩子
    estimated_duration_ms: float
    total_utility: float                  # Σ(gain × influence)
    budget_ms: float


class PipelineSynthesizer:
    """管道合成器 — 从钩子池 + 二进制特征自动构造 DAG.

    用法:
      synth = PipelineSynthesizer(schema_model)
      synth.set_hook_profile('taint', duration_ms=500, gain=0.9, influence=0.8)
      pipeline = synth.synthesize(
          initial_keys={'binary_path', 'arch', 'format', 'size'},
          budget_ms=5000, features={'arch': 'x86_64', 'size': 2097152},
      )
    """

    def __init__(self, schema_model: SchemaModel):
        self._model = schema_model
        # 钩子画像: {name → {duration_ms, gain, influence, priority}}
        self._profiles: Dict[str, Dict[str, float]] = {}

    def set_hook_profile(self, name: str, **kw) -> 'PipelineSynthesizer':
        self._profiles[name] = {
            'duration_ms': kw.get('duration_ms', 100.0),
            'gain': kw.get('gain', 0.7),
            'influence': kw.get('influence', 0.5),
            'priority': kw.get('priority', 0),
        }
        return self

    def set_profiles_from_predictors(
        self, hook_names: List[str],
        predictor=None, prob_model=None, path_analyzer=None,
        features: Optional[Dict[str, Any]] = None,
    ) -> 'PipelineSynthesizer':
        """从既有预测器批量设置画像."""
        feats = features or {}
        for name in hook_names:
            dur = 100.0; gain = 0.7; infl = 0.5
            if predictor is not None:
                dur = predictor.predict(name, features=feats)
            if prob_model is not None:
                gain = prob_model.get_belief(name, features=feats).mean
            if path_analyzer is not None:
                inf = path_analyzer.influence(name)
                if inf: infl = inf.influence_score
            self.set_hook_profile(name, duration_ms=dur, gain=gain, influence=infl)
        return self

    def synthesize(
        self, initial_keys: Set[str], budget_ms: float = 10000.0,
        mandatory_hooks: Optional[Set[str]] = None,
        features: Optional[Dict[str, Any]] = None,
    ) -> SynthesizedPipeline:
        """从初始键集出发, 贪心构造最优 DAG.

        initial_keys: 管道入口即存在的键 (如 'binary_path', 'arch').
        budget_ms: 时间预算 (毫秒).
        mandatory_hooks: 必须包含的钩子 (不计入预算).
        """
        mandatory = mandatory_hooks or set()
        features = features or {}

        # 获取所有可用钩子
        all_sigs = self._model.all_signatures()
        if not all_sigs:
            return SynthesizedPipeline({}, [], [], 0, 0, budget_ms)

        # 计算每个钩子的效用得分
        scores: Dict[str, float] = {}
        durations: Dict[str, float] = {}
        for name, sig in all_sigs.items():
            prof = self._profiles.get(name, {})
            dur = prof.get('duration_ms', 100.0)
            gain = prof.get('gain', 0.7)
            infl = prof.get('influence', 0.5)
            scores[name] = gain * infl
            durations[name] = dur

        # 初始化
        available_keys: Set[str] = set(initial_keys)
        selected: Set[str] = set(mandatory)
        remaining_budget = budget_ms

        # 先计入 mandatory 的耗时
        for m in mandatory:
            dur = durations.get(m, 100.0)
            remaining_budget -= dur
            sig = all_sigs.get(m)
            if sig:
                available_keys.update(sig.written_keys)
        remaining_budget = max(0, remaining_budget)

        # 依赖图: 追踪 "谁产出了哪个键" → 用于构造 edges
        key_producers: Dict[str, str] = {}  # key → hook_name (最近产出者)

        # 贪心构造
        changed = True
        while changed:
            changed = False
            best_name = ''
            best_efficiency = 0.0

            for name, sig in all_sigs.items():
                if name in selected:
                    continue
                dur = durations.get(name, 100.0)
                if dur > remaining_budget:
                    continue
                # 依赖检查: required_reads 必须在 available_keys 中
                if not sig.required_reads.issubset(available_keys):
                    continue
                eff = scores.get(name, 0.5) / max(1.0, dur)
                if eff > best_efficiency:
                    best_efficiency = eff
                    best_name = name

            if best_name:
                selected.add(best_name)
                remaining_budget -= durations.get(best_name, 100.0)
                sig = all_sigs[best_name]
                for k in sig.written_keys:
                    key_producers[k] = best_name
                available_keys.update(sig.written_keys)
                changed = True

        # 后优化: 2-opt 局部搜索
        selected, remaining_budget = self._two_opt(
            selected, all_sigs, scores, durations,
            available_keys, initial_keys, mandatory, remaining_budget, budget_ms,
        )

        # 构建 edges: 对每个选中的钩子, 找其 required_reads 的产出者 → 添加边
        edges: Dict[str, List[str]] = defaultdict(list)
        for name in selected:
            sig = all_sigs.get(name)
            if sig is None:
                continue
            for rk in sig.required_reads:
                producer = key_producers.get(rk, '')
                if producer and producer != name and producer in selected:
                    if name not in edges[producer]:
                        edges[producer].append(name)
            edges.setdefault(name, [])

        # 拓扑排序选中的钩子
        topo = self._topo_subset(edges, selected)

        skipped = [n for n in all_sigs if n not in selected]
        total_dur = sum(durations.get(n, 100.0) for n in selected)
        total_util = sum(scores.get(n, 0.5) for n in selected)

        return SynthesizedPipeline(
            edges=dict(edges), selected_hooks=topo, skipped_hooks=skipped,
            estimated_duration_ms=total_dur, total_utility=total_util,
            budget_ms=budget_ms,
        )

    def _two_opt(
        self, selected: Set[str], all_sigs: Dict[str, HookSignature],
        scores: Dict[str, float], durations: Dict[str, float],
        available_keys: Set[str], initial_keys: Set[str],
        mandatory: Set[str], remaining_budget: float, total_budget: float,
    ) -> Tuple[Set[str], float]:
        """2-opt: 尝试用未选钩子替换低效已选钩子, 保持依赖合法性."""
        # 计算当前 selected 中每个钩子产出对下游的依赖影响
        produced: Dict[str, Set[str]] = {}  # name → keys produced
        consumed: Dict[str, Set[str]] = {}  # name → keys consumed by downstream
        for name in selected:
            sig = all_sigs.get(name)
            produced[name] = set(sig.written_keys) if sig else set()
        for name in selected:
            needed = set()
            for other in selected:
                if other == name: continue
                osig = all_sigs.get(other)
                if osig and produced[name] & osig.required_reads:
                    needed.update(produced[name] & osig.required_reads)
            consumed[name] = needed

        unselected = [n for n in all_sigs if n not in selected and n not in mandatory]
        if not unselected: return selected, remaining_budget

        unsel_eff = [(n, scores.get(n, 0.5) / max(1.0, durations.get(n, 100.0)))
                     for n in unselected]
        unsel_eff.sort(key=lambda x: x[1], reverse=True)

        for cand_name, _ in unsel_eff[:20]:
            cand_sig = all_sigs.get(cand_name)
            if cand_sig is None: continue
            cand_dur = durations.get(cand_name, 100.0)
            # 仅替换无下游消费者的钩子 (consumed[name] 为空) — 安全替换
            replaceable = [
                n for n in selected - mandatory
                if not consumed.get(n, set())
                and durations.get(n, 100.0) >= cand_dur * 0.5
            ]
            if not replaceable: continue
            worst = min(replaceable,
                       key=lambda n: scores.get(n, 0.5) / max(1.0, durations.get(n, 100.0)))
            worst_dur = durations.get(worst, 100.0)
            worst_score = scores.get(worst, 0.5)
            cand_score = scores.get(cand_name, 0.5)
            delta_dur = cand_dur - worst_dur
            delta_score = cand_score - worst_score
            # 候选钩子的依赖必须已被满足 (移除 worst 后)
            dep_ok = cand_sig.required_reads.issubset(
                set(initial_keys) | {
                    k for n in selected - {worst}
                    for k in (all_sigs.get(n, HookSignature(hook_name='')).written_keys)
                })
            if delta_score > 0 and remaining_budget - delta_dur >= 0 and dep_ok:
                selected.discard(worst); selected.add(cand_name)
                remaining_budget -= delta_dur
                produced[cand_name] = set(cand_sig.written_keys) if cand_sig else set()

        return selected, remaining_budget

    @staticmethod
    def _topo_subset(edges: Dict[str, List[str]], nodes: Set[str]) -> List[str]:
        in_deg = {n: 0 for n in nodes}
        for src, dsts in edges.items():
            if src not in nodes:
                continue
            for d in dsts:
                if d in nodes:
                    in_deg[d] = in_deg.get(d, 0) + 1
        q = deque([n for n in nodes if in_deg.get(n, 0) == 0])
        order = []
        while q:
            n = q.popleft(); order.append(n)
            for d in edges.get(n, []):
                if d in nodes:
                    in_deg[d] -= 1
                    if in_deg[d] == 0:
                        q.append(d)
        return order
