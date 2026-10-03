# FTRL+Entropy 在线凸优化 + surprise bonus
"""在线遗憾最小化变异集成 (Regret-Minimizing Ensemble, ARME).

参考: Shalev-Shwartz, Hazan, Cesa-Bianchi & Lugosi

与 mutation_ensemble.py (EG/Hedge) 的区分:
  EG 隐式假设平稳奖励。实测 fuzzing 中程序行为随探索推进而变化,
  本模块使用 FTRL 更新权重, 在非平稳环境中比 EG 更稳健。
  Surprise bonus 和 regret-triggered reset 是针对 fuzzing 场景的适配。

  注: 遗憾界为理论参照, 非平稳环境中实际遗憾可能更高。"""

import math
import random
import time
from collections import defaultdict
from typing import Dict, List, Optional, Tuple

from .regret_strategies import (
    StrategyState, RegretSnapshot, build_strategies,
    _DEFAULT_LR, _ENTROPY_LAMBDA, _REGRET_WINDOW,
    _SURPRISE_THRESHOLD, _RESET_REGRET_RATIO,
)

MutatorFn = __import__('typing').Callable[[bytes], Tuple[bytes, List[int]]]


class RegretMinimizingEnsemble:
    """对抗性遗憾最小化突变策略集成.

    FTRL+Entropy 解: w_{t+1,i} ∝ exp(η·Σ_{s≤t} r_{s,i})
    即累积奖励的 softmax + 熵正则化防退化。
    """

    def __init__(self, learning_rate: float = _DEFAULT_LR,
                 ent_lambda: float = _ENTROPY_LAMBDA):
        self.lr = learning_rate
        self.ent_lambda = ent_lambda
        self._strategies: Dict[str, StrategyState] = {}
        self._mutators = build_strategies()
        for name in self._mutators:
            self._strategies[name] = StrategyState(name=name)
        self._round: int = 0
        self._cumulative_reward: float = 0.0
        self._best_fixed_cumulative: Dict[str, float] = defaultdict(float)
        self._regret_history: List[RegretSnapshot] = []
        self._global_reward_ema: float = 0.0
        self._surprise_log: List[Tuple[str, float, float]] = []
        self._recalc_probs()

    def select(self, context_hint: Optional[str] = None) -> str:
        self._round += 1
        probs = [s.prob for s in self._strategies.values()]
        names = list(self._strategies.keys())
        if context_hint:
            adjusted = list(probs)
            for i, name in enumerate(names):
                ctx = self._strategies[name].context_stats.get(context_hint, (0, 0))
                if ctx[0] >= 5:
                    adjusted[i] *= (1.0 + 0.2 * ctx[1] / ctx[0])
            total_adj = sum(adjusted)
            if total_adj > 0:
                probs = [a / total_adj for a in adjusted]
        r = random.random(); cum = 0.0
        for i, p in enumerate(probs):
            cum += p
            if r <= cum:
                return names[i]
        return names[-1]

    def mutate(self, data: bytes, strategy_name: Optional[str] = None,
               context_hint: Optional[str] = None) -> Tuple[bytes, List[int], str]:
        if strategy_name is None:
            strategy_name = self.select(context_hint=context_hint)
        mutator = self._mutators.get(strategy_name)
        if mutator is None:
            strategy_name = list(self._mutators.keys())[0]
            mutator = self._mutators[strategy_name]
        result, positions = mutator(data)
        self._strategies[strategy_name].calls += 1
        return result, positions, strategy_name

    def update(self, strategy_name: str, reward: float,
               context_hint: Optional[str] = None) -> None:
        strat = self._strategies.get(strategy_name)
        if strat is None:
            return
        reward = max(0.0, min(2.0, reward))
        strat.cumulative_reward += reward
        self._cumulative_reward += reward
        if reward > 0.5:
            strat.success_count += 1
        alpha = 0.1
        strat.reward_ema = (1 - alpha) * strat.reward_ema + alpha * reward
        self._global_reward_ema = ((1 - alpha) * self._global_reward_ema
                                   + alpha * reward)
        if context_hint:
            ctx = strat.context_stats[context_hint]
            strat.context_stats[context_hint] = (
                ctx[0] + 1, ctx[1] + (1 if reward > 0.5 else 0))
        # Surprise 检测
        if (strat.reward_ema > 0.1 and reward > _SURPRISE_THRESHOLD * strat.reward_ema
                and reward > 0.8):
            strat.surprise_count += 1
            self._surprise_log.append((strategy_name, reward, strat.reward_ema))
            if len(self._surprise_log) > 100:
                self._surprise_log = self._surprise_log[-50:]
        # Best-in-hindsight 更新
        for name in self._strategies:
            self._best_fixed_cumulative[name] += (
                reward if name == strategy_name else 0.0)
        # FTRL 权重
        excess = reward - self._global_reward_ema
        strat.weight *= math.exp(self.lr * excess)
        n = len(self._strategies)
        for s in self._strategies.values():
            s.weight = max(0.01, s.weight * (1 - self.ent_lambda)
                          + self.ent_lambda * (1.0 / n))
        max_w = 100.0
        if any(s.weight > max_w for s in self._strategies.values()):
            scale = max_w / max(s.weight for s in self._strategies.values())
            for s in self._strategies.values():
                s.weight = max(0.01, s.weight * scale)
        self._recalc_probs()
        if self._round % _REGRET_WINDOW == 0:
            self._update_regret()
        # 遗憾重置检查
        if len(self._regret_history) >= 2:
            recent = self._regret_history[-1].cumulative_regret
            prev = self._regret_history[-2].cumulative_regret
            if prev > 0 and recent / prev > 1.0 + _RESET_REGRET_RATIO:
                self._reset_on_regime_change()

    def _update_regret(self) -> None:
        if self._round == 0:
            return
        best_fixed = max(self._best_fixed_cumulative.values())
        regret = max(0.0, best_fixed - self._cumulative_reward)
        best_name = max(self._best_fixed_cumulative,
                       key=lambda k: self._best_fixed_cumulative[k])
        self._regret_history.append(RegretSnapshot(
            timestamp=time.time(), cumulative_regret=regret,
            per_step_regret=regret / max(1, self._round),
            best_fixed_strategy=best_name,
            best_fixed_reward=self._best_fixed_cumulative[best_name],
        ))

    def _reset_on_regime_change(self) -> None:
        for s in self._strategies.values():
            s.weight = 1.0; s.cumulative_reward = 0.0; s.reward_ema = 0.0
        self._best_fixed_cumulative.clear()
        self._global_reward_ema = 0.0
        self._recalc_probs()

    def _recalc_probs(self) -> None:
        names = list(self._strategies.keys())
        weights = [self._strategies[n].weight for n in names]
        max_w = max(weights) if weights else 1.0
        exps = [math.exp(w - max_w) for w in weights]
        total = sum(exps)
        for i, name in enumerate(names):
            self._strategies[name].prob = exps[i] / max(1e-12, total)

    def get_surprise_strategies(self) -> List[str]:
        return list({name for name, _, _ in self._surprise_log[-10:]})

    def stats(self) -> dict:
        strat_stats = {}
        for name, s in self._strategies.items():
            strat_stats[name] = {
                "weight": round(s.weight, 3), "prob": round(s.prob, 3),
                "calls": s.calls,
                "success_rate": round(s.success_count / max(1, s.calls), 3),
                "avg_reward": round(s.cumulative_reward / max(1, s.calls), 3),
                "surprises": s.surprise_count,
            }
        current_regret = (self._regret_history[-1].cumulative_regret
                         if self._regret_history else 0.0)
        return {
            "round": self._round,
            "cumulative_reward": round(self._cumulative_reward, 2),
            "global_reward_ema": round(self._global_reward_ema, 3),
            "current_regret": round(current_regret, 3),
            "per_step_regret": round(current_regret / max(1, self._round), 4),
            "surprise_events": len(self._surprise_log),
            "strategies": strat_stats,
            "learning_rate": self.lr, "entropy_lambda": self.ent_lambda,
        }

    def export_weights(self) -> Dict[str, float]:
        return {n: s.weight for n, s in self._strategies.items()}

    def import_weights(self, weights: Dict[str, float]) -> None:
        for name, w in weights.items():
            if name in self._strategies:
                self._strategies[name].weight = w
        self._recalc_probs()

    def reset(self) -> None:
        for s in self._strategies.values():
            s.weight = 1.0; s.calls = 0; s.success_count = 0
            s.cumulative_reward = 0.0; s.reward_ema = 0.0
            s.surprise_count = 0; s.context_stats.clear()
        self._round = 0; self._cumulative_reward = 0.0
        self._best_fixed_cumulative.clear()
        self._regret_history.clear()
        self._global_reward_ema = 0.0
        self._surprise_log.clear()
        self._recalc_probs()
