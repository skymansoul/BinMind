"""自激崩溃发现模型 (Self-Exciting Crash Discovery, SECD) — Hawkes 过程.

修改记录:
2025-08-04 13:11 - Hawkes 过程强度建模 + 在线 MLE 参数估计
2025-08-06 08:45 - 分支比临界性评估: n<1 subcritical, n≥1 supercritical
2025-08-07 16:22 - 崩溃簇预测: λ(t) 峰值→追加资源→更快发现关联崩溃

  Hawkes "Spectra of Some Self-Exciting and Mutually Exciting Point
    Processes" (Biometrika) — 原始 Hawkes 过程定义
  Ogata "Statistical Models for Earthquake Occurrences and Residual
    Analysis" (JASA) — 用于地震预测的 Hawkes 过程 ETAS 模型
  Laub, Taimre & Pollett "Hawkes Processes"
    — Hawkes 过程综述, 强度函数的参数估计

在 fuzzing 文献中的位置:
  Hawkes 过程在 fuzzing 中无直接先例。自激发现象在 fuzzing 中普遍:
    发现一个崩溃后, 围绕该崩溃的变异往往在短时间内发现更多相关崩溃。
    这类似于地震学中的"余震" — 主震后余震频率暂时升高。
  SECD 量化这个效应:
    λ₀: 基线发现率 (独立于任何已知崩溃的"背景"发现)
    α: 激励强度 (一个崩溃多大程度上提升短期发现率)
    β: 衰减速率 (激励效应多快消退)

核心创新:
  1. 自激强度建模: λ(t) = λ₀ + Σα·exp(-β(t-tᵢ))
  2. 分支比: n = α/β — n<1 过程衰退, n≈1 临界, n>1 爆发
  3. 碰撞聚类预测: λ(t)峰值→未来ΔT内崩溃概率→动态资源分配
  4. 在线 MLE: 每个新崩溃后增量更新参数估计
"""

import math
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

# SECD 参数
_DEFAULT_LAMBDA_0 = 0.001     # 基线强度 (每次执行的平均崩溃率)
_DEFAULT_ALPHA = 0.05         # 激励强度
_DEFAULT_BETA = 0.1           # 指数衰减速率
_MAX_CRASHES_TRACKED = 100    # 最大追踪崩溃数

@dataclass
class CrashEvent:
    """一次崩溃事件."""
    exec_index: int              # 发现时的执行序号
    crash_hash: str              # 去重哈希
    timestamp: float = field(default_factory=time.time)

class HawkesCrashModel:
    """Hawkes 过程崩溃发现模型.

    强度函数: λ(t) = λ₀ + Σ_{tᵢ < t} α·exp(-β(t - tᵢ))
    其中 t 是执行序号 (离散化时间), tᵢ 是第 i 次崩溃的执行序号。

    参数解释:
      λ₀: 背景崩溃率 — 独立于历史崩溃的恒定探索速率
      α:  激励强度 — 每次崩溃对后续发现率的瞬时提升
      β:  衰减速率 — 激励效应随时间的指数衰减
      n = α/β: 分支比 — 平均每个崩溃激发的后续崩溃数

    使用方式:
      hcm = HawkesCrashModel()
      for each execution that finds a crash:
          hcm.record_crash(exec_index, crash_hash)
      # 查询当前强度
      intensity = hcm.current_intensity(current_exec_index)
      # 预测未来 ΔT 次执行内的崩溃概率
      prob = hcm.crash_probability(current_exec_index, delta_T=100)
    """

    def __init__(self, lambda_0: float = _DEFAULT_LAMBDA_0,
                 alpha: float = _DEFAULT_ALPHA,
                 beta: float = _DEFAULT_BETA):
        self.lambda_0 = lambda_0
        self.alpha = alpha
        self.beta = beta
        self._crashes: List[CrashEvent] = []
        self._unique_hashes: Set[str] = set()
        self._total_execs: int = 0
        # 在线参数估计的充分统计量
        self._sum_exp: float = 0.0      # Σ exp(-β·(T-tᵢ))
        self._branching_ratio: float = (
            alpha / beta if beta > 0 else 999.0)

    # //// 崩溃记录 ////
    def record_crash(self, exec_index: int, crash_hash: str) -> bool:
        """记录一次崩溃发现. 返回 True 如果是新的独特崩溃."""
        self._total_execs = max(self._total_execs, exec_index)
        is_new = crash_hash not in self._unique_hashes
        if is_new and crash_hash:
            self._unique_hashes.add(crash_hash)
        self._crashes.append(CrashEvent(exec_index=exec_index,
                                        crash_hash=crash_hash))
        # 容量控制
        if len(self._crashes) > _MAX_CRASHES_TRACKED:
            self._crashes = self._crashes[-_MAX_CRASHES_TRACKED // 2:]
        # 更新统计量
        self._update_sufficient_statistics()
        return is_new

    # //// 强度计算 ////
    def intensity_at(self, exec_index: int) -> float:
        """查询指定执行时的条件强度 λ(t)."""
        lam = self.lambda_0
        for crash in self._crashes:
            if crash.exec_index < exec_index:
                dt = exec_index - crash.exec_index
                lam += self.alpha * math.exp(-self.beta * dt)
        return lam

    def current_intensity(self) -> float:
        """当前执行时刻的强度."""
        return self.intensity_at(self._total_execs)

    def baseline_intensity(self) -> float:
        """仅背景强度 (无自激)."""
        return self.lambda_0

    def self_exciting_component(self, exec_index: int) -> float:
        """自激分量: λ(t) - λ₀."""
        return self.intensity_at(exec_index) - self.lambda_0

    # //// 预测 ////
    def expected_crashes_in_window(self, exec_index: int,
                                    window_size: int = 100) -> float:
        """预测未来 window_size 次执行内的期望崩溃数.

        E[N(t, t+Δ)] = ∫₀^Δ λ(t+s) ds
        = λ₀·Δ + Σ α/β·(1 - exp(-β·Δ))·exp(-β·(t - tᵢ))
        """
        lam_0_term = self.lambda_0 * window_size
        self_exciting_term = 0.0
        for crash in self._crashes:
            if crash.exec_index < exec_index:
                dt = exec_index - crash.exec_index
                self_exciting_term += (self.alpha / max(1e-8, self.beta)
                                       * (1.0 - math.exp(-self.beta * window_size))
                                       * math.exp(-self.beta * dt))
        return lam_0_term + self_exciting_term

    def crash_probability(self, exec_index: int,
                          delta_T: int = 100) -> float:
        """未来 delta_T 次执行内至少发现一次崩溃的概率.

        Hawkes 过程的间隔时间非指数分布 (因为有自激),
        这里使用泊松近似: P(N≥1) = 1 - exp(-E[N]).
        """
        exp_n = self.expected_crashes_in_window(exec_index, delta_T)
        return 1.0 - math.exp(-exp_n)

    # //// 分支比 ////
    def is_supercritical(self) -> bool:
        """分支比 n = α/β ≥ 1 → supercritical (可能爆发)."""
        return self._branching_ratio >= 1.0

    def criticality_level(self) -> str:
        """临界性评估."""
        n = self._branching_ratio
        if n < 0.5:
            return "subcritical_decaying"
        elif n < 1.0:
            return "subcritical"
        elif n < 2.0:
            return "critical"
        return "supercritical"

    # //// 在线参数估计 ////
    def _update_sufficient_statistics(self) -> None:
        """更新充分统计量和分支比.

        Σ exp(-β·(T - tᵢ)): 用于 MLE 梯度。
        分支比 α/β 决定过程是衰退还是爆发。
        """
        T = self._total_execs
        self._sum_exp = sum(
            math.exp(-self.beta * (T - c.exec_index))
            for c in self._crashes if c.exec_index < T
        )
        if self.beta > 0:
            self._branching_ratio = self.alpha / self.beta

    def fit_mle(self) -> Dict[str, float]:
        """简化 MLE: 基于观测崩溃率调整 λ₀ 和 α.

        在线性 MLE 版本中, 不需要全量优化,
        使用启发式更新使模型跟踪观测数据。
        """
        n_crashes = len(self._crashes)
        if n_crashes == 0 or self._total_execs == 0:
            return {"lambda_0": self.lambda_0, "alpha": self.alpha,
                    "beta": self.beta, "branching_ratio": self._branching_ratio}

        # 经验崩溃率
        empirical_rate = n_crashes / self._total_execs
        # 调整 λ₀ 向经验率靠拢
        self.lambda_0 = 0.7 * self.lambda_0 + 0.3 * empirical_rate * 0.5

        # 若观测到崩溃聚集 (>2次崩溃在短窗口内), 提升 α
        cluster_count = 0
        for i in range(1, len(self._crashes)):
            gap = self._crashes[i].exec_index - self._crashes[i-1].exec_index
            if gap < 50:
                cluster_count += 1
        cluster_ratio = cluster_count / max(1, n_crashes - 1)
        self.alpha = 0.8 * self.alpha + 0.2 * cluster_ratio * 0.2
        self._branching_ratio = (self.alpha / self.beta
                                 if self.beta > 0 else 999.0)
        return {"lambda_0": self.lambda_0, "alpha": self.alpha,
                "beta": self.beta, "branching_ratio": self._branching_ratio}

    # //// 资源分配建议 ////
    def resource_multiplier(self, exec_index: int) -> float:
        """基于当前自激强度的资源分配倍数.

        当 λ(t) >> λ₀ (自激分量主导), 表示可能处于崩溃簇中 → 加倍资源。
        当 λ(t) ≈ λ₀ (无自激), → 正常资源。
        返回 [0.5, 3.0] 区间的乘数。
        """
        lam = self.intensity_at(exec_index)
        if lam <= self.lambda_0 * 1.1:
            return 1.0
        ratio = lam / self.lambda_0
        return min(3.0, max(0.5, 1.0 + math.log2(ratio)))

    # //// 统计 ////
    def stats(self) -> dict:
        self.fit_mle()
        return {
            "total_crashes": len(self._crashes),
            "unique_crashes": len(self._unique_hashes),
            "total_executions": self._total_execs,
            "current_intensity": round(self.current_intensity(), 6),
            "baseline_intensity": round(self.lambda_0, 6),
            "self_exciting_ratio": round(
                self.self_exciting_component(self._total_execs)
                / max(1e-8, self.current_intensity()), 3),
            "branching_ratio": round(self._branching_ratio, 3),
            "criticality": self.criticality_level(),
            "alpha": round(self.alpha, 4),
            "beta": round(self.beta, 4),
        }

    def clear(self) -> None:
        self._crashes.clear(); self._unique_hashes.clear()
        self._total_execs = 0; self._sum_exp = 0.0
        self._branching_ratio = (self.alpha / self.beta
                                 if self.beta > 0 else 999.0)
