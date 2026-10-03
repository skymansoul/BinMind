"""执行开销预测器 (Execution Cost Forecaster, ECF) — 在线分位数回归预估种子执行时间.

  Koenker & Bassett "Regression Quantiles" — 分位数回归理论基础
  Cramér "Mathematical Methods of Statistics"
    — 渐近理论: 分位数估计的 Bahadur 表示
  Entropic
    — 执行速度是能量调度的关键输入, 但使用原始测量值而非预测值
  Honeycomb 的 adaptive timeout 机制
    — 基于历史执行时间的动态超时调整, 本项目借鉴其分位数思想

核心假设:
  种子执行时间在模糊测试中呈现长尾分布 (多数 < 10ms, 少数 > 1s)。
  调度器需要区分 "快种子" (适合高吞吐探索) 和 "慢种子" (可能进入深层路径)。
  提前预判执行开销允许调度器做吞吐量感知的种子选择, 而非事后补救。

  使用在线分位数回归 (quantile regression) 而非简单的移动平均,
  因为分位数对长尾异常值鲁棒, 且同时提供 P50 (典型) 和 P95 (最坏情况)
  两个调度决策维度。

特征选择:
  使用 5 个低成本特征 — 无需执行即可计算:
    1. seed.data 长度 (字节)
    2. seed.generation (代数, 越低越接近原始输入)
    3. seed.coverage 大小 (已覆盖的边数)
    4. seed.metadata['num_children'] (已产生的子代数量)
    5. 上一次执行的实测时间 (若存在)
"""

import math
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

# 特征维度
_N_FEATURES = 5

# 学习率配置
_DEFAULT_LR_P50 = 0.05
_DEFAULT_LR_P95 = 0.02  # P95 更新更保守, 因为尾部样本稀疏

@dataclass
class CostEstimate:
    """一个种子的执行开销预估。"""
    seed_id: str
    p50_ms: float          # 中位数预估值
    p95_ms: float          # 95% 分位数预估值
    last_actual_ms: float  # 最近一次实测值
    num_observations: int  # 该种子的历史执行次数
    features: List[float] = field(default_factory=lambda: [0.0] * _N_FEATURES)
    updated_at: float = field(default_factory=time.time)

class ExecutionCostForecaster:
    """在线分位数回归器 — 预测种子执行时间的 P50 和 P95。

    使用随机梯度下降 (SGD) 拟合线性分位数回归模型:
      ŷ_τ = w_τ · x + b_τ
    其中 τ ∈ {0.50, 0.95} 是目标分位数。

    分位数回归的损失函数 (pinball loss):
      L_τ(y, ŷ) = max(τ·(y-ŷ), (τ-1)·(y-ŷ))
      → 梯度: ∇L = -τ 若 y>ŷ,  (1-τ) 若 y≤ŷ

    在线更新规则 (SGD):
      w ← w - lr · ∇L_τ
    对于特征 x_j: ∇_j L = -τ·x_j (若 y>ŷ) 或 (1-τ)·x_j (若 y≤ŷ)

    为什么用分位数而非均值:
      - 执行时间分布高度偏斜 (大部分快, 少量慢)
      - 均值被离群值严重拉高 → 不适合做调度决策
      - P50 给出"典型情况下多快", P95 给出"最坏情况下多慢"
      - 调度器可根据阶段目标在两者间切换

    内存占用: O(N·D) 其中 N=种子数, D=5 → 极轻量
    """

    def __init__(self, lr_p50: float = _DEFAULT_LR_P50,
                 lr_p95: float = _DEFAULT_LR_P95):
        self.lr_p50 = lr_p50
        self.lr_p95 = lr_p95

        # 模型参数: 线性回归权重和偏置
        # P50 模型
        self._w_p50: List[float] = [0.0] * _N_FEATURES
        self._b_p50: float = 5.0  # 初始偏置 = 5ms (典型种子执行时间)
        # P95 模型
        self._w_p95: List[float] = [0.0] * _N_FEATURES
        self._b_p95: float = 50.0  # 初始偏置 = 50ms

        # seed_id → CostEstimate
        self._estimates: Dict[str, CostEstimate] = {}

        # 全局统计
        self._global_p50_ema: float = 5.0
        self._global_p95_ema: float = 50.0
        self._total_observations: int = 0

        # 特征预计算缓存 (seed_id → features)
        self._feature_cache: Dict[str, List[float]] = {}

    # //// 特征提取 ////
    @staticmethod
    def extract_features(seed) -> List[float]:
        """从种子对象提取 5 维归一化特征向量。

        特征归一化到 [0, 1] 区间, 缺失值填充 0.5 (中性先验)。
        """
        data_len = len(getattr(seed, 'data', b''))
        generation = getattr(seed, 'generation', 0)
        cov_size = len(getattr(seed, 'coverage', set()))
        num_children = seed.metadata.get('num_children', 0) if hasattr(seed, 'metadata') else 0
        last_exec_ms = seed.metadata.get('exec_time_ms', 0.0) if hasattr(seed, 'metadata') else 0.0

        return [
            min(1.0, data_len / 4096.0),              # 种子大小 (4KB归一化)
            1.0 / (1.0 + generation),                 # 代数新鲜度
            min(1.0, math.log2(1 + cov_size) / 10.0), # 覆盖边数 (log2)
            min(1.0, num_children / 100.0),           # 子代数
            min(1.0, last_exec_ms / 100.0),           # 上次执行时间 (100ms归一化)
        ]

    # //// 主入口: 观测到新执行时间, 更新模型 ////
    def observe(self, seed_id: str, actual_ms: float,
                seed=None) -> CostEstimate:
        """记录一次实际执行时间, 并更新分位数模型。

        若 seed 对象提供, 自动提取特征; 否则复用缓存特征。
        返回更新后的 CostEstimate。
        """
        actual_ms = max(0.01, actual_ms)
        self._total_observations += 1

        # 获取或创建特征向量
        feats = self._feature_cache.get(seed_id)
        if feats is None and seed is not None:
            feats = self.extract_features(seed)
            self._feature_cache[seed_id] = feats
        if feats is None:
            feats = [0.5] * _N_FEATURES

        # 获取或创建估计
        est = self._estimates.get(seed_id)
        if est is None:
            # 冷启动: 使用全局 EMA 作为先验
            est = CostEstimate(
                seed_id=seed_id,
                p50_ms=self._global_p50_ema,
                p95_ms=self._global_p95_ema,
                last_actual_ms=actual_ms,
                num_observations=1,
                features=list(feats),
            )
            self._estimates[seed_id] = est

        est.last_actual_ms = actual_ms
        est.num_observations += 1
        est.features = list(feats)
        est.updated_at = time.time()

        # SGD 更新 P50 模型
        self._sgd_update_quantile(feats, actual_ms, tau=0.50)

        # SGD 更新 P95 模型
        self._sgd_update_quantile(feats, actual_ms, tau=0.95)

        # 更新种子级估计
        est.p50_ms = max(0.01, self._predict(feats, self._w_p50, self._b_p50))
        est.p95_ms = max(0.01, self._predict(feats, self._w_p95, self._b_p95))

        # 更新全局 EMA
        alpha = 0.05
        self._global_p50_ema = (1 - alpha) * self._global_p50_ema + alpha * actual_ms
        if actual_ms > self._global_p95_ema:
            self._global_p95_ema = (1 - alpha * 0.5) * self._global_p95_ema + alpha * 0.5 * actual_ms

        return est

    def _sgd_update_quantile(self, feats: List[float], y: float,
                             tau: float) -> None:
        """单步 SGD 更新指定分位数的回归参数。

        Pinball loss: L_τ(y, ŷ) = max(τ·(y-ŷ), (τ-1)·(y-ŷ))
        次梯度:      ∂L/∂ŷ = -τ (y>ŷ) 或 (1-τ) (y≤ŷ)
        """
        if tau == 0.50:
            w = self._w_p50
            y_hat = self._predict(feats, w, self._b_p50)
            lr = self.lr_p50
        else:
            w = self._w_p95
            y_hat = self._predict(feats, w, self._b_p95)
            lr = self.lr_p95

        grad_sign = -tau if y > y_hat else (1.0 - tau)
        effective_lr = lr / math.sqrt(1 + 0.001 * self._total_observations)

        for j in range(_N_FEATURES):
            w[j] -= effective_lr * grad_sign * feats[j]

        # 偏置更新
        delta_b = effective_lr * grad_sign
        if tau == 0.50:
            self._b_p50 -= delta_b
        else:
            self._b_p95 -= delta_b

    # //// 预测 ////
    def _predict(self, feats: List[float], w: List[float], b: float) -> float:
        """线性模型预测: ŷ = w·x + b。"""
        # 对执行时间取 log 建模, 因为时间分布是乘性的
        # 预测 log(ms), 返回时 exp 回去
        log_pred = b
        for j in range(_N_FEATURES):
            log_pred += w[j] * feats[j]
        # Sigmoid 截断: 避免极端预测值
        return max(0.01, math.exp(min(8.0, max(-4.6, log_pred))))

    def predict(self, seed_id: str) -> Tuple[float, float]:
        """查询种子的 P50 和 P95 执行时间预估 (毫秒)。

        若种子无历史, 返回全局 EMA 作为先验。
        """
        est = self._estimates.get(seed_id)
        if est is not None:
            return est.p50_ms, est.p95_ms

        feats = self._feature_cache.get(seed_id, [0.5] * _N_FEATURES)
        p50 = max(0.01, self._predict(feats, self._w_p50, self._b_p50))
        p95 = max(0.01, self._predict(feats, self._w_p95, self._b_p95))
        return p50, p95

    def predict_from_seed(self, seed) -> Tuple[float, float]:
        """直接从种子对象预测 (无需先调用 observe)。"""
        feats = self.extract_features(seed)
        p50 = max(0.01, self._predict(feats, self._w_p50, self._b_p50))
        p95 = max(0.01, self._predict(feats, self._w_p95, self._b_p95))
        return p50, p95

    # //// 调度辅助 ////
    def is_fast_seed(self, seed_id: str, threshold_ms: float = 10.0) -> bool:
        """判断种子是否为 "快种子" (P50 < threshold_ms)。"""
        p50, _ = self.predict(seed_id)
        return p50 < threshold_ms

    def throughput_score(self, seed_id: str) -> float:
        """计算吞吐量分数: 1 / P50 (ms), 归一化到 [0, 1]。

        快种子 → 高吞吐量分 → 适合高频变异。
        """
        p50, _ = self.predict(seed_id)
        return min(1.0, 10.0 / max(0.1, p50))

    def risk_adjusted_score(self, seed_id: str) -> float:
        """风险调整分数: P50 / P95。

        接近 1.0 → 执行时间稳定 (低风险); 接近 0 → 高度可变 (高风险)。
        稳定种子更适合自动化流水线; 高风险种子可能有意外路径。
        """
        p50, p95 = self.predict(seed_id)
        return p50 / max(0.01, p95)

    # //// 统计 ////
    def stats(self) -> dict:
        n = len(self._estimates)
        p50s = [e.p50_ms for e in self._estimates.values()]
        p95s = [e.p95_ms for e in self._estimates.values()]

        return {
            "tracked_seeds": n,
            "total_observations": self._total_observations,
            "global_p50_ema_ms": round(self._global_p50_ema, 2),
            "global_p95_ema_ms": round(self._global_p95_ema, 2),
            "model_weights_p50": [round(w, 4) for w in self._w_p50],
            "model_weights_p95": [round(w, 4) for w in self._w_p95],
            "model_bias_p50": round(self._b_p50, 4),
            "model_bias_p95": round(self._b_p95, 4),
            "avg_predicted_p50": sum(p50s) / max(1, n),
            "avg_predicted_p95": sum(p95s) / max(1, n),
            "feature_dim": _N_FEATURES,
        }

    def clear(self) -> None:
        self._w_p50 = [0.0] * _N_FEATURES
        self._b_p50 = 5.0
        self._w_p95 = [0.0] * _N_FEATURES
        self._b_p95 = 50.0
        self._estimates.clear()
        self._feature_cache.clear()
        self._global_p50_ema = 5.0
        self._global_p95_ema = 50.0
        self._total_observations = 0
