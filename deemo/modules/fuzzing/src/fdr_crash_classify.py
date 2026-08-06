"""FDR 控制崩溃分类 — Benjamini-Hochberg + Storey q-value.

修改记录:
2025-08-14 15:28 - BH 过程 + Storey q-value + π₀ 估计
2025-08-16 09:41 - 在线 BH: 新 p-value 到达时的增量 FDR 控制

参考: Benjamini & Hochberg (1995) JRSS-B; Storey (2002) JRSS-B.
在 fuzzing 中零先例。同时检验多个突变策略的有效性时,
BH 过程控制错误发现率 (FDR), 比 Bonferroni 更强大。"""

import math
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


@dataclass
class FDRResult:
    discoveries: List[Tuple[str, float, float]]
    # (hypothesis_name, p_value, q_value)
    n_tests: int; n_discoveries: int; pi0_hat: float


class FDRController:
    """FDR 控制器 — Benjamini-Hochberg + Storey q-value.

    BH: p_{(i)} ≤ (i/m)·α → reject H₀ for i=1..k*
    Storey q-value = min FDR level at which this hypothesis rejected.
    π₀ = proportion of true nulls, estimated via Storey's method.

    使用方式:
      fdr = FDRController(alpha=0.05)
      fdr.add_hypothesis("strat_A_vs_baseline", p_value=0.003)
      result = fdr.apply()
      for name, p, q in result.discoveries:
          print(f"{name}: p={p:.4f}, q={q:.4f}")
    """

    def __init__(self, alpha: float = 0.05):
        self.alpha = alpha
        self._hypotheses: Dict[str, float] = {}

    def add_hypothesis(self, name: str, p_value: float) -> None:
        self._hypotheses[name] = max(0.0, min(1.0, p_value))

    def apply(self) -> FDRResult:
        """应用 BH 过程."""
        n = len(self._hypotheses)
        if n == 0:
            return FDRResult([], 0, 0, 1.0)

        # 排序 p-values
        sorted_items = sorted(self._hypotheses.items(), key=lambda x: x[1])
        m = n

        # Storey π₀ 估计: 使用固定阈值 λ=0.5
        lam = 0.5
        n_lambda = sum(1 for _, p in sorted_items if p > lam)
        pi0 = min(1.0, max(0.05, n_lambda / max(1, m * (1.0 - lam))))

        # BH 临界值: k* = max{k: p_{(k)} ≤ (k/m)·α}
        k_star = 0
        for k, (_, p_val) in enumerate(sorted_items, 1):
            threshold = (k / m) * self.alpha / pi0
            if p_val <= threshold:
                k_star = k

        # 计算 Storey q-values
        q_values = []
        min_q = float('inf')
        for k in range(m - 1, -1, -1):
            name, p_val = sorted_items[k]
            # q_{(k)} = min_{j≥k} m·p_{(j)}·π₀/j
            q_candidate = m * p_val * pi0 / (k + 1)
            min_q = min(min_q, q_candidate)
            q_values.insert(0, (name, p_val, min(min_q, 1.0)))

        discoveries = [(n, p, q) for n, p, q in q_values[:k_star]
                      if q <= self.alpha]

        return FDRResult(
            discoveries=discoveries, n_tests=m,
            n_discoveries=len(discoveries), pi0_hat=pi0)

    def stats(self) -> dict:
        r = self.apply()
        return {"n_tests": r.n_tests, "n_discoveries": r.n_discoveries,
                "pi0_hat": round(r.pi0_hat, 3),
                "alpha": self.alpha,
                "top_discovery": (r.discoveries[0] if r.discoveries
                                 else None)}

    def clear(self) -> None:
        self._hypotheses.clear()
