"""Copula 覆盖依赖模型 — 经验 copula + 尾部依赖 + 秩相关.

参考: Nelsen "An Introduction to Copulas" 2nd ed.
在 fuzzing 中零先例。Copula 分离边缘分布和依赖结构,
比 Pearson 相关更全面地刻画覆盖维度间的非线性依赖。"""

import math
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


@dataclass
class CopulaResult:
    kendall_tau: float         # Kendall τ [-1,1]
    spearman_rho: float        # Spearman ρ [-1,1]
    tail_lower: float          # 下尾依赖 [0,1]
    tail_upper: float          # 上尾依赖 [0,1]
    n_observations: int


class CopulaCoverageModel:
    """Copula 覆盖依赖模型 — 秩基多元依赖分析.

    边缘: 各覆盖维度 (边数、执行时间、崩溃率) 的经验分布
    Copula: 分离后的依赖结构

    Kendall τ = P(concordant) - P(discordant)
    Spearman ρ = corr(rank(X), rank(Y))
    尾部依赖 λ_L = lim P(Y≤q|X≤q) as q→0
    """

    def __init__(self):
        self._pairs: List[Tuple[float, float]] = []

    def add_pair(self, x: float, y: float) -> None:
        self._pairs.append((x, y))
        if len(self._pairs) > 300:
            self._pairs = self._pairs[-200:]

    def analyze(self) -> Optional[CopulaResult]:
        n = len(self._pairs)
        if n < 10:
            return None

        xs = [p[0] for p in self._pairs]
        ys = [p[1] for p in self._pairs]

        # Kendall τ: 对每对 (i,j), 检查 (x_i-x_j)(y_i-y_j) 的符号
        concordant = 0; discordant = 0
        for i in range(n):
            for j in range(i + 1, n):
                dx = xs[i] - xs[j]
                dy = ys[i] - ys[j]
                if dx * dy > 0:
                    concordant += 1
                elif dx * dy < 0:
                    discordant += 1
        total_pairs = concordant + discordant
        tau = (concordant - discordant) / max(1, total_pairs)

        # Spearman ρ: corr(rank(X), rank(Y))
        rank_x = self._rank(xs)
        rank_y = self._rank(ys)
        n_float = float(n)
        mean_rx = (n_float + 1) / 2.0
        mean_ry = (n_float + 1) / 2.0
        cov_rs = sum((rank_x[i] - mean_rx) * (rank_y[i] - mean_ry)
                     for i in range(n)) / n_float
        var_rx = sum((r - mean_rx) ** 2 for r in rank_x) / n_float
        var_ry = sum((r - mean_ry) ** 2 for r in rank_y) / n_float
        rho = cov_rs / math.sqrt(max(1e-12, var_rx * var_ry))

        # 尾部依赖 (经验, q=0.1)
        q = int(n * 0.1)
        if q >= 2:
            xs_sorted = sorted(xs)
            ys_sorted = sorted(ys)
            x_q, y_q = xs_sorted[q], ys_sorted[q]
            # 上尾
            x_uq = xs_sorted[-q]
            y_uq = ys_sorted[-q]
            count_upper = sum(1 for i in range(n)
                            if xs[i] >= x_uq and ys[i] >= y_uq)
            tail_upper = count_upper / q
            # 下尾
            count_lower = sum(1 for i in range(n)
                            if xs[i] <= x_q and ys[i] <= y_q)
            tail_lower = count_lower / q
        else:
            tail_lower = 0.0; tail_upper = 0.0

        return CopulaResult(
            kendall_tau=tau, spearman_rho=rho,
            tail_lower=tail_lower, tail_upper=tail_upper,
            n_observations=n)

    @staticmethod
    def _rank(values: List[float]) -> List[float]:
        """平均秩 (处理并列)."""
        n = len(values)
        indexed = sorted(enumerate(values), key=lambda x: x[1])
        ranks = [0.0] * n
        i = 0
        while i < n:
            j = i
            while j + 1 < n and abs(indexed[j+1][1] - indexed[i][1]) < 1e-12:
                j += 1
            avg_rank = (i + j + 2) / 2.0  # 1-indexed
            for k in range(i, j + 1):
                ranks[indexed[k][0]] = avg_rank
            i = j + 1
        return ranks

    def stats(self) -> dict:
        r = self.analyze()
        if r is None:
            return {"n": len(self._pairs), "status": "insufficient_data"}
        return {"n": r.n_observations, "kendall_tau": round(r.kendall_tau, 4),
                "spearman_rho": round(r.spearman_rho, 4),
                "tail_lower": round(r.tail_lower, 3),
                "tail_upper": round(r.tail_upper, 3)}

    def clear(self) -> None:
        self._pairs.clear()
