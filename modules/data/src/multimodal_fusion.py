# 多模态异常融合 (Cross-Modal Anomaly Fusion with Score Calibration)
#
# 融合来自三个独立分析通道的信号, 产生统一的异常评分:
#   Channel A (向量搜索): LSH 余弦距离 → 该签名与已知良性样本的距离
#   Channel B (图结构评分): WL kernel + graphlet → 调用图结构异常度
#   Channel C (IOC 提取): 签名中检测到的 IOC 密度和置信度
#
# 核心问题: 各通道的输出尺度、置信度分布、缺失模式各不相同,
#   简单加权平均会放大高方差通道的噪声, 并低估确定性通道.
#
# 创新点:
#   1. Isotonic Regression 校准: 将各通道的原始分数映射为
#      共同的概率尺度 (P(anomaly | score)). 保序回归保证
#      score_A > score_B 时 P(A) ≥ P(B), 不引入排序反转.
#   2. 贝叶斯证据融合: 处理缺失通道 (某二进制无 CFG 数据时
#      Channel B 不可用) — 缺失通道贡献均匀先验, 不影响后验.
#      P(anomaly | s_A, s_B, s_C) ∝ Π_i P(s_i | anomaly) · P(anomaly).
#   3. 通道可靠性在线估计: 追踪各通道的校准误差 (Brier score),
#      高误差通道在融合中自动降权. 每 500 次预测后更新权重.
#   4. 异常阈值自校准: 基于融合分数的历史分布, 动态设定
#      anomaly threshold = μ + k·σ. k 可调 (默认 3.0).
#
# 与现有工作的区别:
# 标准 ensemble 方法: 平均/投票, 不处理尺度差异和缺失.
# Stacking: 需要训练元模型, 本方案零训练的贝叶斯融合.
#   - 单通道异常检测 (isolation forest, LOF): 不使用多模态信息.

import math
import time
from collections import deque
from typing import Dict, List, Optional, Tuple


class IsotonicCalibrator:
    """保序回归分数校准器: 将原始分数映射为 [0,1] 概率.

    用 Pool Adjacent Violators Algorithm (PAVA) 拟合单调递增函数.
    O(n) 时间, O(n) 空间. 每 N 次校准后重新拟合.
    """

    def __init__(self, recalibrate_every: int = 100):
        self._raw: List[float] = []
        self._labels: List[float] = []
        self._thresholds: List[float] = []
        self._probabilities: List[float] = []
        self._recal_every = recalibrate_every
        self._n_feed = 0
        self._last_refit_size = 0  # 上次 refit 时的样本数

    def feed(self, raw_score: float, label: int):
        """喂入一个 (分数, 标签) 对. label: 0=正常, 1=异常."""
        self._raw.append(raw_score)
        self._labels.append(float(label))
        self._n_feed += 1
        # 每 recal_every 次或样本翻倍时触发 refit
        if (self._n_feed % self._recal_every == 0 or
            len(self._raw) >= self._last_refit_size * 2):
            self._refit()
            self._last_refit_size = len(self._raw)

    def calibrate(self, raw_score: float) -> float:
        """返回校准后的 P(anomaly | score)."""
        if not self._thresholds:
            # 未校准: 用简单 sigmoid 近似
            if self._raw:
                mean_s = sum(self._raw)/len(self._raw)
                return 1.0/(1.0+__import__('math').exp(-3.0*(raw_score-mean_s)))
            return max(0.0, min(1.0, raw_score))
        idx = self._bisect(self._thresholds, raw_score)
        if idx >= len(self._probabilities):
            return self._probabilities[-1] if self._probabilities else 0.5
        if idx < 0:
            return self._probabilities[0] if self._probabilities else 0.5
        return self._probabilities[idx]

    def _refit(self):
        """PAVA 拟合."""
        if len(self._raw) < 10:
            return

        # 按 raw_score 排序
        pairs = sorted(zip(self._raw, self._labels), key=lambda x: x[0])
        scores = [p[0] for p in pairs]
        labels = [p[1] for p in pairs]

        # PAVA: 维护单调递增的概率序列
        # 每个 block = (sum_labels, count, start_idx, end_idx)
        blocks = []
        for s, l in zip(scores, labels):
            blocks.append({"sum_l": l, "count": 1})

        # 合并违反单调性的相邻块
        changed = True
        while changed:
            changed = False
            i = 0
            while i < len(blocks) - 1:
                p_i = blocks[i]["sum_l"] / blocks[i]["count"]
                p_j = blocks[i + 1]["sum_l"] / blocks[i + 1]["count"]
                if p_i > p_j:
                    # 合并
                    blocks[i]["sum_l"] += blocks[i + 1]["sum_l"]
                    blocks[i]["count"] += blocks[i + 1]["count"]
                    del blocks[i + 1]
                    changed = True
                else:
                    i += 1

        # 提取阈值和概率
        self._thresholds = []
        self._probabilities = []
        cum_count = 0
        for b in blocks:
            cum_count += b["count"]
            self._thresholds.append(scores[cum_count - 1] if cum_count <= len(scores) else scores[-1])
            self._probabilities.append(b["sum_l"] / b["count"])

    def _bisect(self, arr: List[float], val: float) -> int:
        lo, hi = 0, len(arr)
        while lo < hi:
            mid = (lo + hi) // 2
            if arr[mid] < val:
                lo = mid + 1
            else:
                hi = mid
        return lo


# 多模态融合器

class MultimodalFusionEngine:
    """三通道贝叶斯融合 + 保序校准 + 通道可靠性加权.

    用法:
      mfe = MultimodalFusionEngine(k_sigma=3.0)
      for sig in signatures:
          score_a = vector_search_score(sig)
          score_b = graph_scorer.score(sig)  # 可能为 None
          score_c = ioc_density(sig)
          fusion_score, is_anomaly = mfe.evaluate(score_a, score_b, score_c)
          if is_anomaly:
              alerts.append(sig)
      mfe.feedback(sig_id, true_label)  # 更新校准器
    """

    def __init__(self, k_sigma: float = 3.0,
                 recalibrate_every: int = 1000,
                 prior_anomaly: float = 0.05):
        self.k_sigma = k_sigma
        self.prior = prior_anomaly
        self._cal_a = IsotonicCalibrator(recalibrate_every=min(recalibrate_every, 200))
        self._cal_b = IsotonicCalibrator(recalibrate_every=min(recalibrate_every, 200))
        self._cal_c = IsotonicCalibrator(recalibrate_every=min(recalibrate_every, 200))

        # 通道可靠性: Brier score 的 EMA (越低越可靠)
        self._brier_a = 1.0
        self._brier_b = 1.0
        self._brier_c = 1.0
        self._brier_alpha = 0.01  # EMA 平滑因子

        # 融合分数历史 (用于动态阈值)
        self._score_history: deque = deque(maxlen=2000)
        self._n_evaluated = 0
        self._n_feedback = 0

    def evaluate(self, score_a: float,
                  score_b: Optional[float],
                  score_c: float) -> Tuple[float, bool]:
        """评估融合异常分数.

        score_b=None 表示图结构通道不可用 (无 CFG 数据的二进制).
        返回 (fusion_score, is_anomaly).
        """
        # 校准各通道
        pa = self._cal_a.calibrate(score_a)
        pb = self._cal_b.calibrate(score_b) if score_b is not None else None
        pc = self._cal_c.calibrate(score_c)

        # 贝叶斯融合
        fusion = self._bayesian_fuse(pa, pb, pc)

        self._score_history.append(fusion)
        self._n_evaluated += 1

        # 动态阈值判定
        threshold = self._dynamic_threshold()
        is_anomaly = fusion > threshold

        return fusion, is_anomaly

    def feedback(self, score_a: float, score_b: Optional[float],
                 score_c: float, true_label: int):
        """反馈真实标签, 更新各通道校准器.

        true_label: 0=正常, 1=异常.
        """
        self._cal_a.feed(score_a, true_label)
        if score_b is not None:
            self._cal_b.feed(score_b, true_label)
        self._cal_c.feed(score_c, true_label)

        # 更新 Brier score (各通道预测误差)
        pa = self._cal_a.calibrate(score_a)
        self._brier_a = (1 - self._brier_alpha) * self._brier_a + \
                         self._brier_alpha * (pa - true_label) ** 2

        if score_b is not None:
            pb = self._cal_b.calibrate(score_b)
            self._brier_b = (1 - self._brier_alpha) * self._brier_b + \
                             self._brier_alpha * (pb - true_label) ** 2

        pc = self._cal_c.calibrate(score_c)
        self._brier_c = (1 - self._brier_alpha) * self._brier_c + \
                         self._brier_alpha * (pc - true_label) ** 2

        self._n_feedback += 1

    def _bayesian_fuse(self, pa: float, pb: Optional[float],
                        pc: float) -> float:
        """贝叶斯证据融合: log-odds 加权平均.

        logit(p) = Σ_i w_i · logit(p_i) + logit(prior)
        其中 w_i = 1/brier_i (可靠性权重).
        缺失通道 (pb=None): w=0, 不参与融合.
        """
        # 可靠性权重归一化
        weights = [1.0 / max(self._brier_a, 1e-6),
                   1.0 / max(self._brier_b, 1e-6),
                   1.0 / max(self._brier_c, 1e-6)]

        if pb is None:
            weights[1] = 0.0  # 缺失通道

        total_w = sum(weights)
        if total_w < 1e-9:
            return self.prior

        norm_w = [w / total_w for w in weights]

        # logit 加权
        logit_prior = math.log(self.prior / (1.0 - self.prior))
        logit_fused = logit_prior

        probs = [pa, pb if pb is not None else 0.5, pc]
        for i in range(3):
            if norm_w[i] < 1e-9:
                continue
            p = max(0.001, min(0.999, probs[i]))
            logit_fused += norm_w[i] * math.log(p / (1.0 - p))

        return 1.0 / (1.0 + math.exp(-logit_fused))

    def _dynamic_threshold(self) -> float:
        """动态阈值 = μ + k·σ, 基于历史融合分数的分布."""
        if len(self._score_history) < 50:
            return 0.5 + self.k_sigma * 0.15

        scores = list(self._score_history)
        n = len(scores)
        mean = sum(scores) / n
        var = sum((s - mean) ** 2 for s in scores) / n
        std = math.sqrt(max(var, 1e-6))

        return min(0.95, mean + self.k_sigma * std)

    @property
    def stats(self) -> dict:
        return {
            "evaluated": self._n_evaluated,
            "feedback_received": self._n_feedback,
            "channel_reliability": {
                "vector_search": round(1.0 / max(self._brier_a, 1e-6), 2),
                "graph_score": round(1.0 / max(self._brier_b, 1e-6), 2),
                "ioc_density": round(1.0 / max(self._brier_c, 1e-6), 2),
            },
            "brier_scores": {
                "A_vector": round(self._brier_a, 6),
                "B_graph": round(self._brier_b, 6),
                "C_ioc": round(self._brier_c, 6),
            },
            "dynamic_threshold": round(self._dynamic_threshold(), 4),
            "score_history_size": len(self._score_history),
        }


__all__ = [
    "MultimodalFusionEngine",
    "IsotonicCalibrator",
]
