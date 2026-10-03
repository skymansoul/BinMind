# Sharpe/Calmar/Martin 量化金融指标->fuzzer 能量分配
"""
量化金融风险调整的模糊测试能量调度 - Sharpe/Calmar 替代均匀分配。

现有能量调度 (AFLFast, entropy_scheduler) 基于覆盖增益的简单指数移动平均-
将所有增益等同看待, 不考虑"增益的波动性"。例如:
  种子A: 每次执行稳定产出 +5 边 (低风险)
  种子B: 50%概率产出 +50 边, 50%概率产出 0 (高风险)
传统调度给 B 更高能量 (平均收益更高), 忽略其波动性。

本模块将量化金融的风险调整指标移植到 fuzzing:
  1. Sharpe 比率: (平均收益 - 无风险收益) / 收益标准差
     衡量单位风险的超额回报
   2. Calmar 比率: 平均收益 / 最大回撤
      衡量最坏情况下的回报-对模糊测试特别适用:
      因为 fuzzer 的时间预算有限, 大回撤意味着"浪费了时间"
   3. Martin 比率: (最终累积覆盖 - 初始) / sqrt(Σ squared drawdowns)
      惩罚回撤的平方-比 Calmar 更敏感

风险调整后的能量分配:
  energy(i) = base_energy × (1 + α × risk_adjusted_ratio(i))
  其中 α 为风险偏好参数 (0=完全风险厌恶, 1=中性)。
  低 Sharpe/Calmar 的种子获得较少能量-节省的算力分配给高比率种子。

为什么 Sharpe 在模糊测试中有效:
  模糊测试的覆盖增益是非平稳的-种子的"回报"随被测程序状态变化。
  Sharpe 比率同时考虑收益均值和波动性, 避免将能量浪费在
  "偶尔爆发但大部分时间无产出" 的种子上。

ref: Kummita & Bodden - risk-adjusted power schedules,
     本项目实现其 Sharpe/Calmar/Martin 三项指标并增加自适应 α
ref: Truzz - byte-level validation check protection,
     本项目的"回撤惩罚"概念与其"验证检查字节保护"互补
ref: Sharpe "Mutual Fund Performance" (Journal of Business) -
     Sharpe 比率的原始论文-(R_p - R_f) / σ_p
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from collections import defaultdict


@dataclass
class SeedPerformanceHistory:
    """种子的历史覆盖增益记录-用于计算风险指标。"""
    seed_id: str
    gains: list[float] = field(default_factory=list)   # 每次执行的覆盖增益
    cumulative_gain: float = 0.0
    max_cumulative: float = 0.0                         # 历史最高累积值
    max_drawdown: float = 0.0                           # 最大回撤
    squared_drawdowns: list[float] = field(default_factory=list)
    window_size: int = 50                               # 滑动窗口大小

    def record(self, gain: float) -> None:
        self.gains.append(gain)
        self.cumulative_gain += gain
        if self.cumulative_gain > self.max_cumulative:
            self.max_cumulative = self.cumulative_gain
        # 回撤计算
        drawdown = self.max_cumulative - self.cumulative_gain
        if drawdown > self.max_drawdown:
            self.max_drawdown = drawdown
        if drawdown > 0:
            self.squared_drawdowns.append(drawdown * drawdown)
        # 滑动窗口
        if len(self.gains) > self.window_size:
            removed = self.gains.pop(0)
            self.cumulative_gain -= removed

    def mean_gain(self) -> float:
        if not self.gains:
            return 0.0
        return sum(self.gains) / len(self.gains)

    def std_gain(self) -> float:
        if len(self.gains) < 2:
            return 0.01
        mean = self.mean_gain()
        var = sum((g - mean) ** 2 for g in self.gains) / (len(self.gains) - 1)
        return math.sqrt(max(0.0001, var))

    def sharpe_ratio(self, risk_free_rate: float = 0.01) -> float:
        """Sharpe = (mean - r_f) / std。r_f = 最低可接受收益。"""
        excess = self.mean_gain() - risk_free_rate
        return excess / self.std_gain()

    def calmar_ratio(self) -> float:
        """Calmar = mean / max_drawdown。越高-单位回撤的回报越高。"""
        if self.max_drawdown < 0.01:
            return self.mean_gain() / 0.01
        return self.mean_gain() / self.max_drawdown

    def martin_ratio(self, initial_cov: float = 0.0) -> float:
        """Martin = (final_cov - initial) / sqrt(avg_squared_drawdown)。"""
        if not self.squared_drawdowns:
            return self.mean_gain() / 0.01
        avg_sq_dd = sum(self.squared_drawdowns) / len(self.squared_drawdowns)
        if avg_sq_dd < 1e-9:
            return self.mean_gain() / 0.01
        return (self.cumulative_gain - initial_cov) / math.sqrt(avg_sq_dd)


# 风险调整调度器

class RiskAdjustedScheduler:
    """基于量化金融指标的能量调度器。

    每轮计算每个种子的 Sharpe/Calmar/Martin 比率,
    以此分配下一轮的能量预算。低风险调整比率的种子被降权。"""

    __slots__ = ('_histories', '_base_energy', '_risk_preference',
                 '_risk_free_rate', '_total_energy_spent')

    def __init__(self, base_energy: float = 100.0,
                 risk_preference: float = 0.6,
                 risk_free_rate: float = 0.01):
        self._histories: dict[str, SeedPerformanceHistory] = {}
        self._base_energy = base_energy
        self._risk_preference = risk_preference  # α: 0=风险厌恶, 1=中性
        self._risk_free_rate = risk_free_rate
        self._total_energy_spent = 0.0

    def register_seed(self, seed_id: str) -> None:
        if seed_id not in self._histories:
            self._histories[seed_id] = SeedPerformanceHistory(seed_id=seed_id)

    def report_gain(self, seed_id: str, edges_found: int,
                    execution_time_ms: float) -> None:
        """报告一次执行的覆盖增益。edges_found 为本次新发现的边数。"""
        if seed_id not in self._histories:
            self.register_seed(seed_id)
        # 归一化收益: 新边数 / 时间 (边/秒) × 1000
        gain = (edges_found / max(1.0, execution_time_ms)) * 1000.0
        self._histories[seed_id].record(gain)

    def allocate_energy(self, seeds: list[str]) -> dict[str, float]:
        """为种子队列分配下一轮能量。

        分配公式: energy_i = base × (1 + α × composite_ratio_i)
        composite_ratio = mean(Sharpe_norm, Calmar_norm, Martin_norm)
        归一化至 [0, 1] 以保证总能量可预测。"""
        if not seeds:
            return {}

        # 计算每个种子的复合风险调整比率
        ratios = {}
        for sid in seeds:
            h = self._histories.get(sid)
            if h is None or len(h.gains) < 3:
                ratios[sid] = 0.5  # 无历史: 中性
                continue
            sharpe = max(-1.0, h.sharpe_ratio(self._risk_free_rate))
            calmar = max(-1.0, h.calmar_ratio())
            martin = max(-1.0, h.martin_ratio())
            # 归一化 (tanh 压缩到 [-1, 1] - [0, 1])
            composite = (math.tanh(sharpe) + math.tanh(calmar * 0.1) + math.tanh(martin * 0.05)) / 3.0
            ratios[sid] = (composite + 1.0) / 2.0  # - [0, 1]

        # 分配能量
        allocation = {}
        for sid in seeds:
            r = ratios.get(sid, 0.5)
            energy = self._base_energy * (1.0 + self._risk_preference * (r - 0.5) * 2.0)
            allocation[sid] = max(self._base_energy * 0.1, energy)
            self._total_energy_spent += allocation[sid]

        return allocation

    def get_risk_report(self, seed_id: str) -> dict:
        """单种子风险报告-用于调试和可视化。"""
        h = self._histories.get(seed_id)
        if h is None:
            return {}
        return {
            'mean_gain': round(h.mean_gain(), 2),
            'std_gain': round(h.std_gain(), 2),
            'sharpe': round(h.sharpe_ratio(self._risk_free_rate), 3),
            'calmar': round(h.calmar_ratio(), 3),
            'martin': round(h.martin_ratio(), 3),
            'max_drawdown': round(h.max_drawdown, 2),
            'n_executions': len(h.gains),
        }

    def stats(self) -> dict:
        n_seeds = len(self._histories)
        sharpes = [h.sharpe_ratio(self._risk_free_rate)
                   for h in self._histories.values() if h.gains]
        return {
            'registered_seeds': n_seeds,
            'avg_sharpe': round(sum(sharpes) / max(1, len(sharpes)), 3),
            'total_energy_spent': round(self._total_energy_spent, 0),
            'risk_preference': self._risk_preference,
        }


__all__ = [
    'RiskAdjustedScheduler', 'SeedPerformanceHistory',
]
