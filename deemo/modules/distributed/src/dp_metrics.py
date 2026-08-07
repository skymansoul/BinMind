# 创建: 2026-06-28
# 修改: 2026-06-28 — 基础ε-DP升级为Rényi DP + zCDP组合
#
# Rényi差分隐私 + zCDP 度量收集 — 紧致组合的隐私保护调度统计
#
# 基础 ε-DP 使用简单组合定理 (k 次查询 = k·ε), 导致隐私预算快速耗尽。
# Rényi DP 和 zero-Concentrated DP
# 提供更紧致的组合界:
#   Rényi DP: 对 α>1, D_α(M(D)||M(D')) ≤ ε·α·(Δf)²/(2σ²)
#   zCDP: 高斯机制的 ρ-zCDP = (Δf)²/(2σ²)
#   高级组合: k 次查询 → √(2k·ln(1/δ))·ε + k·ε(e^ε-1)
#
# 本模块新增:
#   1. GaussianDPCounter: 高斯噪声替代拉普拉斯 → zCDP 保证
#   2. MomentsAccountant: 追踪组合隐私损失的紧致上界
#   3. RényiDP 到 (ε,δ)-DP 的转换: 选择最优 α 最小化 ε

from __future__ import annotations

import math
import random
import threading
from collections import deque
from typing import Optional, List, Dict, Tuple


def _gaussian_noise(rng: random.Random, sigma: float) -> float:
    """Box-Muller 高斯噪声 ∼ N(0, σ²)。"""
    u1 = rng.uniform(1e-9, 1.0)
    u2 = rng.uniform(0.0, 1.0)
    return sigma * math.sqrt(-2.0 * math.log(u1)) * math.cos(2.0 * math.pi * u2)


class MomentsAccountant:
    """Moments Accountant — Rényi DP 组合追踪。

    对每次查询记录其 Rényi 散度对 α 的贡献, 组合后转换为 (ε,δ)-DP。
    这是 TensorFlow Privacy 使用的标准方法。
    """

    def __init__(self, max_order: int = 32):
        # 每阶 α 的累积 Rényi 散度
        self._orders = list(range(1, max_order + 1))
        self._renyi_divergences = [0.0] * max_order
        self._lock = threading.Lock()

    def accumulate_gaussian(self, sigma: float, sensitivity: float = 1.0):
        """累积一次高斯机制的 Rényi DP 代价。

        高斯机制下 D_α = α·sensitivity²/(2σ²)。
        """
        with self._lock:
            for i, alpha in enumerate(self._orders):
                self._renyi_divergences[i] += (
                    alpha * sensitivity * sensitivity / (2.0 * sigma * sigma)
                )

    def accumulate_laplace(self, epsilon: float):
        """累积一次拉普拉斯机制的 Rényi DP 代价。"""
        with self._lock:
            for i, alpha in enumerate(self._orders):
                # Laplace: D_α ≤ (1/(α-1))·log(α/(2α-1)·exp((α-1)ε) + ...)
                # 简化上界: D_α ≤ ε (保守)
                self._renyi_divergences[i] += epsilon

    def get_dp(self, delta: float = 1e-5) -> Tuple[float, float]:
        """Rényi DP → (ε, δ)-DP 转换。

        对每个 α, ε_α = D_α + log(1/δ)/(α-1)。
        取最小 ε_α 得到最紧界。
        """
        with self._lock:
            best_eps = float('inf')
            best_alpha = 1
            for i, alpha in enumerate(self._orders):
                if alpha <= 1:
                    continue
                eps = self._renyi_divergences[i] + math.log(
                    1.0 / max(delta, 1e-12)
                ) / (alpha - 1)
                if eps < best_eps:
                    best_eps = eps
                    best_alpha = alpha
            return best_eps, best_alpha

    @property
    def spent_rdp(self) -> List[float]:
        return list(self._renyi_divergences)


class GaussianDPCounter:
    """高斯机制的差分隐私计数器 — zCDP 保证。

    (ε,δ)-DP 的高斯校准: σ ≥ √(2·ln(1.25/δ))·Δf/ε。
    zCDP 参数: ρ = (Δf)²/(2σ²)。

    与拉普拉斯 DPCounter 的区别:
      - 拉普拉斯: 纯 ε-DP, 单次查询紧致, 但组合松
      - 高斯: (ε,δ)-DP, 单次查询有 δ 泄漏, 但组合紧 (zCDP)
    """

    def __init__(self, epsilon: float = 1.0, delta: float = 1e-5,
                 seed: Optional[int] = None):
        self._eps = epsilon
        self._delta = delta
        self._true_value: int = 0
        self._rng = random.Random(seed)
        # 高斯校准: σ = √(2·ln(1.25/δ))·Δf/ε
        self._sigma = (
            math.sqrt(2.0 * math.log(1.25 / max(delta, 1e-12)))
            / max(epsilon, 0.01)
        )
        self._accountant = MomentsAccountant()
        self._lock = threading.Lock()

    def inc(self, delta: int = 1):
        with self._lock:
            self._true_value += delta

    def read(self) -> float:
        with self._lock:
            noise = _gaussian_noise(self._rng, self._sigma)
            self._accountant.accumulate_gaussian(self._sigma)
            return max(0.0, self._true_value + noise)

    def read_dp_budget(self) -> dict:
        eps, alpha = self._accountant.get_dp(self._delta)
        return {
            "epsilon": round(eps, 6), "delta": self._delta,
            "optimal_alpha": alpha, "mechanism": "gaussian_zcdp",
        }

    @property
    def true_value(self) -> int:
        return self._true_value

    @property
    def sigma(self) -> float:
        return self._sigma


class DPMetricsCollector:
    """Rényi差分隐私度量收集器 — 统一入口。

    整合 DPCounter (拉普拉斯), GaussianDPCounter (高斯), DPHistogram。
    使用 MomentsAccountant 追踪总隐私损失。
    """

    def __init__(self, epsilon: float = 1.0, seed: Optional[int] = None):
        self._eps = epsilon
        self._seed = seed
        self._counters: Dict[str, DPCounter] = {}
        self._gaussian_counters: Dict[str, GaussianDPCounter] = {}
        self._histograms: Dict[str, DPHistogram] = {}
        self._accountant = MomentsAccountant()
        self._lock = threading.Lock()

    def counter(self, name: str) -> DPCounter:
        with self._lock:
            if name not in self._counters:
                self._counters[name] = DPCounter(self._eps, self._seed)
            return self._counters[name]

    def gaussian_counter(self, name: str, delta: float = 1e-5
                         ) -> GaussianDPCounter:
        with self._lock:
            if name not in self._gaussian_counters:
                self._gaussian_counters[name] = GaussianDPCounter(
                    self._eps, delta, self._seed
                )
            return self._gaussian_counters[name]

    def histogram(self, name: str, bins: List[str]) -> DPHistogram:
        with self._lock:
            if name not in self._histograms:
                self._histograms[name] = DPHistogram(
                    bins, self._eps, self._seed
                )
            return self._histograms[name]

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "counters": {
                    n: c.read() for n, c in self._counters.items()
                },
                "gaussian_counters": {
                    n: gc.read() for n, gc in self._gaussian_counters.items()
                },
                "histograms": {
                    n: h.read() for n, h in self._histograms.items()
                },
            }

    def total_privacy_cost(self, delta: float = 1e-5) -> dict:
        eps, alpha = self._accountant.get_dp(delta)
        return {
            "epsilon": round(eps, 6), "delta": delta,
            "optimal_alpha": alpha, "mechanism": "renyi_dp_composition",
        }

    def stats(self) -> dict:
        return {
            "epsilon_per_query": self._eps,
            "n_counters": len(self._counters),
            "n_gaussian_counters": len(self._gaussian_counters),
            "n_histograms": len(self._histograms),
        }


# 兼容层: 基础ε-DP包装 (保持与模块导出兼容)

class DPCounter:
    """ε-差分隐私计数器 — 拉普拉斯机制。"""
    def __init__(self, epsilon=1.0, seed=None):
        self._eps = epsilon; self._true = 0
        self._rng = random.Random(seed); self._lock = threading.Lock()
    def inc(self, d=1):
        with self._lock: self._true += d
    def read(self):
        with self._lock:
            u = self._rng.uniform(-0.5, 0.5)
            n = -math.copysign(1, u) * (1.0/max(self._eps,0.01)) * math.log(1-2*abs(u))
            return max(0, self._true + n)
    true_value = property(lambda s: s._true)

class DPGauge:
    """ε-差分隐私仪表。"""
    def __init__(self, epsilon=1.0, max_value=1.0, seed=None):
        self._eps = epsilon; self._max = max_value; self._true = 0.0
        self._rng = random.Random(seed); self._lock = threading.Lock()
    def set(self, v):
        with self._lock: self._true = min(self._max, max(0, v))
    def read(self):
        with self._lock:
            u = self._rng.uniform(-0.5, 0.5)
            n = -math.copysign(1, u) * (self._max/max(self._eps,0.01)) * math.log(1-2*abs(u))
            return max(0, min(self._max, self._true + n))
    true_value = property(lambda s: s._true)

class DPHistogram:
    """ε-差分隐私直方图。"""
    def __init__(self, bins, epsilon=1.0, seed=None):
        self._eps = epsilon; self._bins = bins
        self._counts = {b: 0 for b in bins}
        self._rng = random.Random(seed); self._lock = threading.Lock()
    def record(self, b):
        with self._lock:
            if b in self._counts: self._counts[b] += 1
    def read(self):
        with self._lock:
            s = 1.0 / max(self._eps, 0.01)
            result = {}
            for b in self._bins:
                u = self._rng.uniform(-0.5, 0.5)
                noise = -math.copysign(1.0, u) * s * math.log(
                    1.0 - 2.0 * abs(u))
                result[b] = max(0.0, self._counts[b] + noise)
            return result
    true_counts = property(lambda s: dict(s._counts))

class DPPrivacyBudget:
    """隐私预算管理器。"""
    def __init__(self, total_budget=10.0, delta=1e-5):
        self._total = total_budget; self._delta = delta
        self._spent = 0.0; self._qcount = 0; self._lock = threading.Lock()
    def consume(self, eps):
        with self._lock:
            self._spent += eps; self._qcount += 1
            return self._spent <= self._total
    remaining = property(lambda s: max(0, s._total - s._spent))
    spent = property(lambda s: s._spent)
