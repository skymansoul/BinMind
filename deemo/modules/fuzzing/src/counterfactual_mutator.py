"""因果变异优化器 (Causal Mutation Optimizer, CMO) — 线性因果效应估计 + 反事实推断.

修改记录:
2025-07-28 15:37 - 线性因果效应估计 + counterfactual ranking 框架
2025-07-30 10:44 - 历史变异 what-if 重估, 无需重新执行
2025-08-01 14:08 - bootstrap 置信区间过滤低信度推断
2025-08-20 09:13 - 修正: 标注线性近似假设, 区分于 Pearl formal counterfactual

  Pearl "Causality" §7 — 反事实的形式化基础
  Peters, Janzing & Schölkopf "Elements of Causal Inference" §6

技术路线:
  在线性 SCM 假设下, 反事实期望简化为 E[Y_{x'}|x,y] = y + β·(x'-x),
  其中 β 是历史观测中估计的平均因果效应 (ATE)。
  此简化避免了完整 Pearl 三阶段 (Abduction→Action→Prediction) 的计算开销,
  但不捕获非线性效应。适合单字节局部变异覆盖效果的快速推断。
"""

import math
import random
import time
from collections import defaultdict
from typing import Dict, FrozenSet, List, Optional, Set, Tuple

from .causal_graph import CausalDAG
from .counterfactual_types import (
    MutationObservation, CounterfactualEstimate, generate_cf_values, std_dev,
    _MAX_HISTORY, _MIN_SAMPLES_FOR_CAUSAL, _CF_CONFIDENCE_THRESHOLD,
    _BOOTSTRAP_SAMPLES,
)

class CounterfactualMutator:
    """反事实变异优化器 — 基于因果推断的字节级变异决策.

    通过消费变异→覆盖反馈的历史记录, 构建因果模型,
    对每个变异做反事实 what-if 评估, 用评估结果指导后续变异选择。
    """

    def __init__(self, max_history: int = _MAX_HISTORY):
        self.max_history = max_history
        self._observations: List[MutationObservation] = []
        self._causal_dag = CausalDAG()
        self._causal_effects: Dict[int, float] = {}
        self._effect_confidence: Dict[int, float] = {}
        self._total_observations: int = 0
        self._structure_stale: bool = True
        self._last_learn_time: float = 0.0
        self._cf_cache: Dict[Tuple[int, int, int], CounterfactualEstimate] = {}

    def observe(self, byte_offset: int, original_value: int,
                mutated_value: int, mutation_type: str,
                coverage_delta: int, new_edge_ids: Set[int],
                execution_time_ms: float = 10.0,
                is_crash: bool = False) -> None:
        """记录一次变异→执行→覆盖反馈的完整观测."""
        obs = MutationObservation(
            byte_offset=byte_offset, original_value=original_value,
            mutated_value=mutated_value, mutation_type=mutation_type,
            coverage_delta=coverage_delta, new_edge_ids=frozenset(new_edge_ids),
            execution_time_ms=execution_time_ms, is_crash=is_crash,
        )
        self._observations.append(obs)
        self._total_observations += 1
        self._structure_stale = True
        if len(self._observations) > self.max_history:
            self._observations = self._observations[-self.max_history:]
        if (len(self._observations) >= _MIN_SAMPLES_FOR_CAUSAL
                and time.time() - self._last_learn_time > 30.0):
            self._learn_causal_structure()

    def _learn_causal_structure(self) -> None:
        """在观测数据上学习因果图 + 估计平均因果效应."""
        if len(self._observations) < _MIN_SAMPLES_FOR_CAUSAL:
            return
        offsets_seen = sorted(set(o.byte_offset for o in self._observations))
        data: Dict[str, List[float]] = {
            "cov_gain": [float(o.coverage_delta) for o in self._observations],
            "crash": [1.0 if o.is_crash else 0.0 for o in self._observations],
        }
        for off in offsets_seen[:min(len(offsets_seen), 32)]:
            col = []
            for o in self._observations:
                col.append(float(o.mutated_value) if o.byte_offset == off else 0.0)
            data[f"byte_{off}"] = col
        self._causal_dag.learn_structure(data)
        self._last_learn_time = time.time()
        self._structure_stale = False
        self._causal_effects.clear()
        self._effect_confidence.clear()
        for off in offsets_seen:
            effect, conf = self._estimate_causal_effect(off)
            self._causal_effects[off] = effect
            self._effect_confidence[off] = conf

    def _estimate_causal_effect(self, byte_offset: int) -> Tuple[float, float]:
        """估计单字节位置的平均因果效应 (ATE)。Bootstrap 估算置信区间."""
        related = [o for o in self._observations if o.byte_offset == byte_offset]
        if len(related) < 5:
            return 0.0, 0.0
        effects = [float(o.coverage_delta) for o in related]
        mean_effect = sum(effects) / len(effects)
        n = len(effects)
        rng = random.Random(byte_offset)
        bootstrap_means = [
            sum(effects[rng.randint(0, n - 1)] for _ in range(n)) / n
            for _ in range(min(_BOOTSTRAP_SAMPLES, n * 10))
        ]
        se = std_dev(bootstrap_means)
        if se < 1e-12:
            return mean_effect, 0.9 if abs(mean_effect) > 0 else 0.3
        margin = 1.96 * se
        confidence = 1.0 - min(1.0, margin / max(0.01, abs(mean_effect) + margin))
        return mean_effect, max(0.0, min(1.0, confidence))

    def counterfactual_query(self, byte_offset: int,
                             actual_value: int, cf_value: int,
                             actual_coverage_delta: int) -> CounterfactualEstimate:
        """反事实查询: 给定实际变异产生了 coverage_delta,
        如果设为 cf_value 代替 actual_value, 覆盖增益会是多少?

        线性 SCM 近似: E[Y_{x'}|x,y] = y + β·(x'-x)
        """
        cache_key = (byte_offset, actual_value, cf_value)
        if cache_key in self._cf_cache:
            return self._cf_cache[cache_key]
        beta = self._causal_effects.get(byte_offset, 0.0)
        conf = self._effect_confidence.get(byte_offset, 0.0)
        normalized_delta = (cf_value - actual_value) / 255.0
        expected_delta = max(-1.0, min(10.0,
            actual_coverage_delta + beta * normalized_delta * 10.0))
        sign = (1 if expected_delta > actual_coverage_delta
                else (-1 if expected_delta < actual_coverage_delta else 0))
        estimate = CounterfactualEstimate(
            byte_offset=byte_offset, actual_value=actual_value,
            cf_value=cf_value, expected_delta=expected_delta,
            confidence=conf, causal_effect_sign=sign,
        )
        self._cf_cache[cache_key] = estimate
        if len(self._cf_cache) > 2000:
            keys = list(self._cf_cache.keys())
            for k in random.sample(keys, len(keys) // 2):
                del self._cf_cache[k]
        return estimate

    def batch_counterfactual_ranking(self,
                                     recent_observations: List[MutationObservation],
                                     top_k: int = 10) -> List[Tuple[int, int, float]]:
        """批量反事实重估 — 返回最有"后悔值"的位置.

        后悔值 = max(反事实期待 - 实际观测, 0)。高后悔值 = "当初应该做不同的变异".
        """
        if len(self._observations) < _MIN_SAMPLES_FOR_CAUSAL:
            return []
        regrets: List[Tuple[int, int, float, float]] = []
        for obs in recent_observations[-50:]:
            offset = obs.byte_offset
            conf = self._effect_confidence.get(offset, 0.0)
            if conf < _CF_CONFIDENCE_THRESHOLD:
                continue
            best_regret, best_val = 0.0, obs.mutated_value
            for alt_val in generate_cf_values(obs.original_value, obs.mutated_value):
                cf = self.counterfactual_query(
                    offset, obs.mutated_value, alt_val, obs.coverage_delta)
                regret = max(0.0, cf.expected_delta - obs.coverage_delta)
                if regret > best_regret:
                    best_regret, best_val = regret, alt_val
            if best_regret > 0.05:
                regrets.append((offset, best_val, best_regret, conf))
        regrets.sort(key=lambda x: x[2], reverse=True)
        return [(off, val, regret) for off, val, regret, _ in regrets[:top_k]]

    def suggest_mutations(self, seed_data: bytes,
                          top_k: int = 8) -> List[Tuple[int, int, str, float]]:
        """为给定种子数据生成反事实指导的变异建议.

        返回 [(byte_offset, suggested_value, rationale, priority_score), ...].
        rationale ∈ {"counterfactual_regret", "causal_effect", "exploratory"}
        """
        if len(seed_data) == 0:
            return []
        suggestions: List[Tuple[int, int, str, float]] = []
        # 策略1: 高后悔值位置
        if len(self._observations) >= _MIN_SAMPLES_FOR_CAUSAL:
            regrets = self.batch_counterfactual_ranking(
                self._observations, top_k=top_k)
            for offset, suggested_val, regret in regrets:
                if 0 <= offset < len(seed_data):
                    suggestions.append(
                        (offset, suggested_val, "counterfactual_regret", regret))
        # 策略2: 高因果效应位置
        if not suggestions and self._causal_effects:
            sorted_effects = sorted(
                self._causal_effects.items(), key=lambda x: abs(x[1]), reverse=True)
            for offset, effect in sorted_effects[:top_k]:
                if (0 <= offset < len(seed_data)
                        and self._effect_confidence.get(offset, 0)
                        > _CF_CONFIDENCE_THRESHOLD):
                    suggestions.append(
                        (offset, seed_data[offset] ^ 0x01, "causal_effect", abs(effect)))
        # 策略3: 未探索的位置
        if not suggestions:
            explored = {o.byte_offset for o in self._observations}
            unexplored = [i for i in range(len(seed_data)) if i not in explored]
            if unexplored:
                for off in random.sample(unexplored, min(top_k, len(unexplored))):
                    suggestions.append(
                        (off, seed_data[off] ^ (1 << random.randint(0, 7)),
                         "exploratory", 0.1))
        return suggestions[:top_k]

    def evaluate_past_decision(self, byte_offset: int, actual_value: int,
                               actual_result: int,
                               n_alternatives: int = 5) -> List[CounterfactualEstimate]:
        """事后评估一次已完成的变异决策."""
        original = actual_value ^ (1 << random.randint(0, 7))
        alternatives = generate_cf_values(original, actual_value)
        results = [self.counterfactual_query(
            byte_offset, actual_value, alt, actual_result)
            for alt in alternatives[:n_alternatives]]
        results.sort(key=lambda x: x.expected_delta, reverse=True)
        return results

    def stats(self) -> dict:
        n_obs = len(self._observations)
        sig = sum(1 for e in self._causal_effects.values() if abs(e) > 0.1)
        hc = sum(1 for c in self._effect_confidence.values()
                 if c > _CF_CONFIDENCE_THRESHOLD)
        return {
            "total_observations": self._total_observations,
            "history_size": n_obs,
            "causal_graph": self._causal_dag.stats(),
            "bytes_with_effect": len(self._causal_effects),
            "significant_effects": sig,
            "high_confidence_effects": hc,
            "mean_causal_effect": (
                sum(self._causal_effects.values())
                / max(1, len(self._causal_effects))
            ),
            "cf_cache_size": len(self._cf_cache),
            "structure_stale": self._structure_stale,
        }

    def clear(self) -> None:
        self._observations.clear()
        self._causal_dag = CausalDAG()
        self._causal_effects.clear()
        self._effect_confidence.clear()
        self._cf_cache.clear()
        self._total_observations = 0
        self._structure_stale = True
