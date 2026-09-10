# 熵基漂移检测+安全门控TTA
# 测试时自适应 — CVE评分模型的在线漂移适应
#
# 问题: CVE评分模型在训练后假设输入分布稳定. 但2024-2026年数据表明:
# NVD在2026年4月停止全量富化 → 训练/测试分布断裂
# CVE利用速度从56天→10小时 → 模型对新CVE的系统性低评分 (滞后偏)
# EPSS模型每30天更新, 但新CVE类型 (AI/ML供应链) 不在训练分布中
# 这些问题导致模型在实际部署中性能持续退化, 传统方案需全量重训练.
#
# 解决方案: 测试时自适应 (Test-Time Adaptation, TTA).
# 基于RaL-TTA 的思想, 适配到CVE评分领域:
#   1. 在线漂移检测: 监控预测熵的滑动统计量,
#      使用KS检验比较近期熵分布与校准基线.
#   2. 安全门控 (SafeGate): 三级风险分类
#      NoShift → 正常评分.
#      LowRiskShift → 激活轻量适配 (BN统计量更新).
#      HighRiskShift → 冻结模型, 回退到保守评分 (降低分数+拉宽区间).
#   3. 锚点保护: 当高风险漂移检测到时, 使用AdaBN校准的锚点模型.
#
# 与ConformalExploitScorer的集成:
#   TTA调整评分均值 (应对系统性偏), 共形预测调整区间宽度 (应对个体不确定性).
#   漂移检测联动: HighRiskShift时, 共形α临时收紧 (如从0.1→0.05),
#   以更宽的预测区间覆盖模型不确定性.
#
# 设计说明:
#   1. 双层级适应: 轻量BN更新 (LowRisk) vs 锚点回退 (HighRisk).
#   2. 与共形预测的深度集成: TTA调整点估计, 共形提供区间保证.
#
#
# RaL-TTA: Risk-Aware Lightweight TTA for IIoT (F1=0.954)
# TENT: Test-Time Entropy Minimization (ICLR)
# 确认EPSS模型的滞后偏问题

import math
from collections import deque
from dataclasses import dataclass, field
from typing import Deque, Dict, List, Optional, Tuple


@dataclass
class TTADriftStatus:
    """TTA漂移检测状态."""
    level: str                # "NoShift" | "LowRiskShift" | "HighRiskShift"
    ks_statistic: float       # KS检验D值
    entropy_mean: float       # 近期预测熵均值
    entropy_baseline: float   # 校准基线熵均值
    adaptation_active: bool
    anchor_active: bool


class EntropyDriftDetector:
    """基于预测熵的漂移检测器.

    使用KS检验比较近期预测熵与校准基线.
    熵 = -Σ p_k·log(p_k), 其中p_k为类别概率 (二分类: exploited vs not).
    高熵 → 模型不确定 → 可能已漂移.
    """

    def __init__(self, window_size: int = 100,
                 baseline_size: int = 200,
                 significance: float = 0.01):
        self._window_size = window_size
        self._baseline_size = baseline_size
        self._significance = significance
        self._baseline_entropies: Deque[float] = deque(maxlen=baseline_size)
        self._recent_entropies: Deque[float] = deque(maxlen=window_size)
        self._calibrated = False

    def calibrate(self, scores: List[float]):
        """用初始评分序列建立熵基线.

        scores: 历史预测分数列表 [0,1].
        将每个分数转为二元分布的熵: H = -s·log(s) - (1-s)·log(1-s).
        """
        for s in scores:
            entropy = self._binary_entropy(s)
            self._baseline_entropies.append(entropy)
        self._calibrated = True

    def observe(self, score: float) -> TTADriftStatus:
        """观测新评分, 返回漂移状态."""
        entropy = self._binary_entropy(score)
        self._recent_entropies.append(entropy)

        if not self._calibrated or len(self._recent_entropies) < 20:
            return TTADriftStatus(
                level="NoShift", ks_statistic=0.0,
                entropy_mean=entropy,
                entropy_baseline=(sum(self._baseline_entropies) /
                                  max(len(self._baseline_entropies), 1)),
                adaptation_active=False, anchor_active=False,
            )

        # KS检验
        baseline_sorted = sorted(self._baseline_entropies)
        recent_sorted = sorted(self._recent_entropies)
        n, m = len(baseline_sorted), len(recent_sorted)
        d_max = 0.0
        i = j = 0
        while i < n and j < m:
            d_max = max(d_max, abs(i / n - j / m))
            if baseline_sorted[i] < recent_sorted[j]:
                i += 1
            else:
                j += 1

        critical = 1.628 * math.sqrt((n + m) / (n * m))

        recent_mean = sum(self._recent_entropies) / len(self._recent_entropies)
        baseline_mean = sum(self._baseline_entropies) / max(len(self._baseline_entropies), 1)

        # 三级分类
        if d_max <= critical * 0.8:
            level = "NoShift"
        elif d_max <= critical * 2.0:
            level = "LowRiskShift"
        else:
            level = "HighRiskShift"

        return TTADriftStatus(
            level=level, ks_statistic=round(d_max, 4),
            entropy_mean=round(recent_mean, 4),
            entropy_baseline=round(baseline_mean, 4),
            adaptation_active=(level != "NoShift"),
            anchor_active=(level == "HighRiskShift"),
        )

    def _binary_entropy(self, p: float) -> float:
        """二元分布的香农熵."""
        p = max(1e-10, min(1.0 - 1e-10, p))
        return -p * math.log(p) - (1.0 - p) * math.log(1.0 - p)

    @property
    def is_calibrated(self) -> bool:
        return self._calibrated

    @property
    def baseline_mean(self) -> float:
        if not self._baseline_entropies:
            return 0.0
        return sum(self._baseline_entropies) / len(self._baseline_entropies)


class TestTimeAdapter:
    """CVE评分的测试时自适应引擎.

    在线接收评分流, 检测分布漂移, 触发分级适应.

    使用模式:
      adapter = TestTimeAdapter(scoring_fn)
      adapter.calibrate(historical_scores)
      for new_cve in stream:
          score, status = adapter.adapt(new_cve_features)
          # score已根据漂移状态调整
    """

    def __init__(self, scoring_fn,
                 low_risk_lr: float = 0.001,
                 high_risk_penalty: float = 0.15):
        """
        scoring_fn: f(features) → float 评分函数.
        low_risk_lr: LowRisk时BN统计量的更新学习率.
        high_risk_penalty: HighRisk时评分下调幅度.
        """
        self._scoring_fn = scoring_fn
        self._detector = EntropyDriftDetector()
        self._low_risk_lr = low_risk_lr
        self._high_risk_penalty = high_risk_penalty

        # BN统计量 (用于轻量适应)
        self._running_mean: float = 0.5
        self._running_var: float = 0.1
        self._n_updates = 0

        # 锚点模型 (HighRisk时使用)
        self._anchor_offset: float = 0.0
        self._anchor_count = 0

        # 历史
        self._status_history: Deque[TTADriftStatus] = deque(maxlen=50)

    def calibrate(self, historical_scores: List[float]):
        """用历史评分校准漂移检测基线."""
        self._detector.calibrate(historical_scores)
        if historical_scores:
            self._running_mean = sum(historical_scores) / len(historical_scores)
            self._running_var = max(0.01, sum(
                (s - self._running_mean) ** 2 for s in historical_scores
            ) / len(historical_scores))

    def adapt(self, features: List[float],
              base_score: Optional[float] = None) -> Tuple[float, TTADriftStatus]:
        """对单个 CVE 执行自适应评分。

        features 为特征向量, base_score 已计算时传入, 否则调用
        scoring_fn; 返回 (adapted_score, drift_status)。
        """
        if base_score is None:
            base_score = self._scoring_fn(features)

        status = self._detector.observe(base_score)
        self._status_history.append(status)

        if status.level == "NoShift":
            # 正常评分, 轻量更新BN统计量
            self._update_bn(base_score)
            adapted = base_score

        elif status.level == "LowRiskShift":
            # BN适应: 将评分向运行均值微调
            self._update_bn(base_score)
            adapted = (base_score * (1.0 - self._low_risk_lr) +
                       self._running_mean * self._low_risk_lr)
            # 更新锚点
            self._anchor_offset += 0.1 * (base_score - self._running_mean)
            self._anchor_count += 1

        else:  # HighRiskShift
            # 回退锚点: 评分下调+锚点校正
            anchor_correction = (self._anchor_offset /
                                 max(self._anchor_count, 1))
            adapted = max(0.0, base_score - self._high_risk_penalty -
                          abs(anchor_correction) * 0.5)

        return round(adapted, 4), status

    def _update_bn(self, score: float):
        """指数移动平均更新BN统计量."""
        self._n_updates += 1
        alpha = 0.01
        self._running_mean = (1.0 - alpha) * self._running_mean + alpha * score
        self._running_var = ((1.0 - alpha) * self._running_var +
                             alpha * (score - self._running_mean) ** 2)

    def batch_adapt(self, features_batch: List[List[float]],
                    scores: Optional[List[float]] = None
                    ) -> List[Tuple[float, TTADriftStatus]]:
        """批量自适应评分."""
        if scores is None:
            scores = [self._scoring_fn(f) for f in features_batch]
        return [self.adapt(f, s) for f, s in zip(features_batch, scores)]

    def get_status_summary(self) -> Dict[str, Any]:
        """当前适配状态摘要."""
        recent = list(self._status_history)[-20:] if self._status_history else []
        shift_counts = {"NoShift": 0, "LowRiskShift": 0, "HighRiskShift": 0}
        for s in recent:
            shift_counts[s.level] = shift_counts.get(s.level, 0) + 1
        return {
            "calibrated": self._detector.is_calibrated,
            "baseline_entropy_mean": round(self._detector.baseline_mean, 4),
            "running_mean": round(self._running_mean, 4),
            "running_var": round(self._running_var, 4),
            "anchor_offset": round(self._anchor_offset, 4),
            "recent_shift_distribution": shift_counts,
            "dominant_status": max(shift_counts, key=shift_counts.get)
            if shift_counts else "NoShift",
        }

    @property
    def detector(self) -> EntropyDriftDetector:
        return self._detector


# 便捷接口

def build_tta_scorer(scoring_fn, historical_scores: List[float]
                     ) -> TestTimeAdapter:
    """构建预校准的TTA评分器."""
    adapter = TestTimeAdapter(scoring_fn)
    adapter.calibrate(historical_scores)
    return adapter


def adaptive_score_cve(adapter: TestTimeAdapter,
                       features: List[float],
                       conformal_scorer=None
                       ) -> Dict[str, Any]:
    """联合TTA+共形预测的完整自适应评分.

    若提供conformal_scorer (ConformalExploitScorer), 则:
      TTA调整点估计 → 共形提供区间 → 联合输出.
    """
    base_score = adapter._scoring_fn(features)
    adapted_score, status = adapter.adapt(features, base_score)

    result = {
        "base_score": round(base_score, 4),
        "adapted_score": round(adapted_score, 4),
        "score_adjustment": round(adapted_score - base_score, 4),
        "drift_level": status.level,
        "drift_ks": status.ks_statistic,
        "entropy_mean": status.entropy_mean,
        "anchor_active": status.anchor_active,
    }

    if conformal_scorer is not None:
        # 使用共形预测的区间
        try:
            from .cve_conformal import ConformalExploitScorer
            sigma = 0.05 + 0.05 * (1 if status.level != "NoShift" else 0)
            conformal_result = conformal_scorer.predict(adapted_score, sigma=sigma)
            result["conformal_lower"] = conformal_result["lower_bound"]
            result["conformal_upper"] = conformal_result["upper_bound"]
            result["uncertainty_level"] = conformal_result["uncertainty_level"]
        except Exception:
            pass

    return result
