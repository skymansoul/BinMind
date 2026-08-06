"""MDL 策略选择 (Minimum Description Length Strategy Selection, MDL-SS).

修改记录:
2025-08-13 08:44 - Rissanen MDL + NML 通用编码 + 随机复杂度
2025-08-14 13:21 - 在线更新: 新观测后 O(1) 增量编码长度

参考:
  Rissanen (1978) "Modeling by Shortest Data Description" (Automatica)
  Rissanen (1996) "Fisher Information and Stochastic Complexity" (IEEE IT)
  Grünwald (2007) "The Minimum Description Length Principle" (MIT Press)
  — 第11章: 归一化最大似然 (NML) 的渐近形式

在 fuzzing 中零先例。MDL 选择压缩数据最好的策略:
  L(D|M) = -log P(D|θ̂_M) + (k/2)log(n/2π) + log∫√det(I(θ))dθ
  其中 k=参数数, I(θ)=Fisher信息矩阵。

应用于 fuzzing: 每个突变策略作为一个"模型",
NML 编码长度 = 拟合优度 + 模型复杂度惩罚。
最短编码 → 最佳策略。"""

import math
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


@dataclass
class MDLResult:
    strategy_name: str
    nll: float               # 负对数似然 (拟合)
    complexity: float         # 模型复杂度 (NML 惩罚)
    total_mdl: float          # 总描述长度
    n_observations: int
    optimal: bool


class MDLStrategySelector:
    """MDL 策略选择器 — 选择压缩覆盖数据最好的突变策略.

    NML 编码: L(D|M) = -Σlog P(y_i|θ̂) + (k/2)log(n/2π)
    正态模型: θ̂=μ, σ², k=2
    L_NML = (n/2)log(2πσ²) + n/2 + log(n/2) - log Γ(n/2)

    使用方式:
      mdl = MDLStrategySelector()
      mdl.add_observation("bitflip", coverage_gain)
      mdl.add_observation("havoc", coverage_gain)
      result = mdl.select_best()
      print(f"Best: {result.strategy_name}, MDL={result.total_mdl:.2f}")
    """

    def __init__(self):
        self._strategies: Dict[str, List[float]] = defaultdict(list)
        # 在线充分统计量
        self._sum: Dict[str, float] = defaultdict(float)
        self._sum_sq: Dict[str, float] = defaultdict(float)
        self._n: Dict[str, int] = defaultdict(int)

    def add_observation(self, strategy_name: str, coverage_gain: float) -> None:
        self._strategies[strategy_name].append(coverage_gain)
        self._sum[strategy_name] += coverage_gain
        self._sum_sq[strategy_name] += coverage_gain * coverage_gain
        self._n[strategy_name] += 1
        # 容量控制
        if len(self._strategies[strategy_name]) > 200:
            self._strategies[strategy_name] = (
                self._strategies[strategy_name][-150:])

    # //// MDL 计算 ////
    def compute_mdl(self, strategy_name: str) -> Optional[MDLResult]:
        """计算某策略的 NML 描述长度."""
        values = self._strategies.get(strategy_name, [])
        n = len(values)
        if n < 5:
            return None

        # MLE: μ̂ = x̄, σ̂² = (1/n)Σ(x-μ̂)²
        mu_hat = self._sum[strategy_name] / n
        sigma_sq = max(1e-8, self._sum_sq[strategy_name] / n - mu_hat * mu_hat)

        # NML 编码长度 (正态模型)
        # L_NML = (n/2)log(2π) + (n/2)log(σ̂²) + n/2
        #        + (k/2)log(n/(2π)) + log∫√det(I(θ))dθ
        # 正态: k=2, ∫√det(I) = 2π/(σ²e)
        nll = 0.5 * n * (math.log(2.0 * math.pi * sigma_sq) + 1.0)
        complexity = math.log(n / (2.0 * math.pi)) + math.log(
            2.0 * math.pi / (sigma_sq * math.e))
        total_mdl = nll + complexity

        return MDLResult(
            strategy_name=strategy_name, nll=nll,
            complexity=complexity, total_mdl=total_mdl,
            n_observations=n, optimal=False)

    def select_best(self) -> Optional[MDLResult]:
        """选择 MDL 最优的策略."""
        results = []
        for name in self._strategies:
            r = self.compute_mdl(name)
            if r:
                results.append(r)
        if not results:
            return None
        results.sort(key=lambda x: x.total_mdl)
        best = results[0]
        # 标记最优
        for r in results:
            r.optimal = (r.strategy_name == best.strategy_name)
        return best

    # //// MDL 比较 ////
    def mdl_evidence_ratio(self, strategy_a: str,
                            strategy_b: str) -> Optional[float]:
        """MDL 证据比: exp(MDL_B - MDL_A).

        >1 → A 优于 B, <1 → B 优于 A.
        """
        r_a = self.compute_mdl(strategy_a)
        r_b = self.compute_mdl(strategy_b)
        if r_a is None or r_b is None:
            return None
        return math.exp(r_b.total_mdl - r_a.total_mdl)

    # //// 统计 ////
    def stats(self) -> dict:
        best = self.select_best()
        strat_stats = {}
        for name in self._strategies:
            r = self.compute_mdl(name)
            if r:
                strat_stats[name] = {
                    "n": r.n_observations,
                    "mdl": round(r.total_mdl, 2),
                    "nll": round(r.nll, 2),
                    "complexity": round(r.complexity, 2),
                }
        return {
            "n_strategies": len(self._strategies),
            "best_strategy": best.strategy_name if best else None,
            "best_mdl": round(best.total_mdl, 2) if best else None,
            "strategies": strat_stats,
        }

    def clear(self) -> None:
        self._strategies.clear(); self._sum.clear()
        self._sum_sq.clear(); self._n.clear()
