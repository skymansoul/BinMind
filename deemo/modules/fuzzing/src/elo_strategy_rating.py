"""Elo 动态策略评级 — Glicko 变体 + K 因子自适应.

修改记录:
2025-08-17 09:22 - Elo 评级 + K 因子自适应 + Glicko RD (评级偏差)
参考: Elo "The Rating of Chessplayers"; Glickman Glicko.
在 fuzzing 中零先例。将突变策略两两比较建模为竞赛,
Elo 评级动态更新, RD 量化不确定性, 自适应 K 因子加速收敛。"""

import math
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


_DEFAULT_RATING = 1500.0
_DEFAULT_RD = 350.0
_MIN_RD = 30.0


@dataclass
class StrategyRating:
    name: str
    rating: float = _DEFAULT_RATING
    rd: float = _DEFAULT_RD        # rating deviation
    matches: int = 0
    wins: int = 0


class EloStrategyRater:
    """Elo 动态策略评级器.

    每轮: 策略 A vs B 比较覆盖增益,
      胜者 rating += K·(1 - E), 负者 rating -= K·(1 - E')
    其中 E = 1/(1 + 10^((R_B-R_A)/400)) 是预期胜率.
    Glicko RD 随时间递增 (不确定性恢复), 每次赛后降低.

    K 自适应: K = max(16, 800/(n_matches + 5)) → 新策略快速找到位置.
    """

    def __init__(self):
        self._strategies: Dict[str, StrategyRating] = {}

    def _get_or_create(self, name: str) -> StrategyRating:
        if name not in self._strategies:
            self._strategies[name] = StrategyRating(name=name)
        return self._strategies[name]

    def record_match(self, winner: str, loser: str,
                     winner_gain: float = 1.0,
                     loser_gain: float = 0.0) -> None:
        """记录一次策略比较结果."""
        wa = self._get_or_create(winner)
        lb = self._get_or_create(loser)

        # Glicko: 考虑 RD 的预期
        g_rd = 1.0 / math.sqrt(1.0 + 3.0 * (lb.rd ** 2) / (math.pi ** 2))
        expected_a = 1.0 / (1.0 + 10.0 ** (g_rd * (lb.rating - wa.rating) / 400.0))
        expected_b = 1.0 - expected_a

        # 自适应 K
        k_a = max(16.0, 800.0 / (wa.matches + 5))
        k_b = max(16.0, 800.0 / (lb.matches + 5))

        # 边际增益加权 (若 winner 大幅胜出, 权重大)
        margin = max(0.1, winner_gain - loser_gain)
        weight = min(2.0, 1.0 + math.log1p(margin))

        wa.rating += k_a * weight * (1.0 - expected_a)
        lb.rating -= k_b * weight * (1.0 - expected_b)

        # 更新 RD
        wa.rd = max(_MIN_RD, wa.rd / math.sqrt(1.0 + wa.matches * 0.005))
        lb.rd = max(_MIN_RD, lb.rd / math.sqrt(1.0 + lb.matches * 0.005))

        wa.matches += 1; wa.wins += 1
        lb.matches += 1

    def top_strategies(self, top_k: int = 5) -> List[Tuple[str, float, float]]:
        """按 Elo 降序返回 top 策略."""
        ranked = sorted(self._strategies.items(),
                       key=lambda x: x[1].rating, reverse=True)
        return [(name, sr.rating, sr.rd) for name, sr in ranked[:top_k]]

    def probability_better(self, a: str, b: str) -> float:
        """A 优于 B 的概率 (考虑 RD)."""
        ra = self._strategies.get(a)
        rb = self._strategies.get(b)
        if not ra or not rb: return 0.5
        diff = ra.rating - rb.rating
        comb_rd = math.sqrt(ra.rd**2 + rb.rd**2)
        return 0.5 * (1.0 + math.erf(diff / (comb_rd * math.sqrt(2.0) + 1e-8)))

    def stats(self) -> dict:
        top = self.top_strategies(3)
        return {"n_strategies": len(self._strategies),
                "top_ratings": [(n, round(r, 1)) for n, r, _ in top],
                "most_experienced": max(
                    (sr.matches for sr in self._strategies.values()), default=0)}

    def clear(self) -> None:
        self._strategies.clear()
