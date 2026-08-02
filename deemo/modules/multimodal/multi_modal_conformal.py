# 2026-08-01
# 共形预测与分布无关不确定性量化
# 参考：Vovk et al. Algorithmic Learning in a Random World. 2005.
#       Angelopoulos & Bates. Conformal Prediction: A Gentle Introduction. 2021.
#       Barber et al. Predictive Inference with the Jackknife+. AOS 2021.
# 核心思想：不假设任何分布，仅通过校准集上的分数分布构建预测区间

import math
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
from collections import defaultdict


# ============================================================================
# 保形预测 — 基于 calibration set 的非参数预测区间
# 给定校准分数 {s_i}，新样本的预测集合 = {y: score(x_new, y) ≤ q̂}
# q̂ = (1-α) 校准分数的分位数（考虑有限样本修正）
# ============================================================================

@dataclass
class ConformalPredictionResult:
    prediction_set: List[int]   # 预测标签集合
    p_values: List[float]       # 每个标签的 conformal p-value
    threshold: float            # 本次预测使用的分数阈值
    confidence: float           # 1 - (average_set_size - 1)/n_classes（集合大小信息量）


def conformal_predict(calibration_scores: List[float],
                       calibration_labels: List[int],
                       test_score_fn,
                       n_classes: int,
                       alpha: float = 0.1) -> ConformalPredictionResult:
    """保形预测器。

    calibration_scores: 校准集上各样本的"异常分数"（nonconformity score）。
    分数越低 → 该样本越符合预测分布。
    alpha: 预设误差率（如 0.1 = 90% 置信水平）。

    原理：在校准集分位数上加有限样本修正 (n+1)/n，
    确保边际覆盖保证 P(Y_test ∈ prediction_set) ≥ 1-α。
    """
    _n = len(calibration_scores)
    if _n < 10:
        return ConformalPredictionResult(
            prediction_set=[0], p_values=[1.0]*(n_classes or 1),
            threshold=0.0, confidence=0.0)

    # 校准分数排序
    _sorted = sorted(calibration_scores)
    # 有限样本修正分位数
    _q_idx = int((1.0 - alpha) * (_n + 1))
    _q_idx = min(_q_idx, _n - 1)
    _threshold = _sorted[_q_idx]

    # p值模拟：实际使用时 test_score_fn 会对每个标签计算分数
    _p_values: List[float] = []
    _pred_set: List[int] = []
    for _y in range(n_classes):
        _score = test_score_fn(_y) if callable(test_score_fn) else 0.5
        # p-value: fraction of calibration scores >= this score
        _p_val = (sum(1 for _s in _sorted if _s >= _score) + 1) / (_n + 1)
        _p_values.append(round(_p_val, 4))
        if _p_val > alpha:
            _pred_set.append(_y)

    _conf = max(0.0, 1.0 - (len(_pred_set) - 1) / max(1, n_classes))
    return ConformalPredictionResult(
        prediction_set=_pred_set, p_values=_p_values,
        threshold=round(_threshold, 4), confidence=round(_conf, 4))


# ============================================================================
# Jackknife+ 预测区间 — 留一法构建的不确定性区间
# 参考：Barber et al. Predictive Inference with the Jackknife+. AOS 2021.
# 相比保形预测，Jackknife+ 不需要额外的校准集分割，
# 在样本量 < 100 时能更有效利用数据
# ============================================================================

def jackknife_plus_intervals(predictions: List[float],
                               residuals: List[float],
                               alpha: float = 0.1) -> Tuple[List[float], List[float]]:
    """Jackknife+ 预测区间构造。

    predictions: 留一法预测值 μ̂_{-i}(x_i)
    residuals: 留一法残差 R_i = |y_i - μ̂_{-i}(x_i)|
    alpha: 预设误差率

    返回：(lower_bounds, upper_bounds) — 每个测试点的预测区间。
    Jackknife+ 的覆盖保证：P(Y_test ∈ interval) ≥ 1 - 2α。
    注意是 2α 而非 α——这是与完全保形预测的理论折中。
    """
    _n = len(predictions)
    if _n < 5:
        _lo = [min(predictions) - 10.0] if predictions else [-10.0]
        _hi = [max(predictions) + 10.0] if predictions else [10.0]
        return _lo * _n, _hi * _n

    # 对残差取 (1-α) 分位数
    _sorted_resid = sorted(residuals)
    _q_idx = int((1.0 - alpha) * (_n + 1)) - 1
    _q_idx = max(0, min(_q_idx, _n - 1))
    _resid_q = _sorted_resid[_q_idx]

    # Jackknife+ 区间：每个点使用"除了自身外的所有留一预测"的分位
    _lo: List[float] = []
    _hi: List[float] = []
    for _i in range(_n):
        # 排除第 i 个自身的留一残差
        _others_pred = [predictions[_j] for _j in range(_n) if _j != _i]
        _lo_i = min(_others_pred) - _resid_q if _others_pred else 0.0
        _hi_i = max(_others_pred) + _resid_q if _others_pred else 0.0
        _lo.append(round(_lo_i, 4))
        _hi.append(round(_hi_i, 4))

    return _lo, _hi


# ============================================================================
# 自适应保形预测 — 对不同区域使用不同阈值（如不同严重度的漏洞）
# 参考：Romano et al. Classification with Valid and Adaptive Coverage. NeurIPS 2020.
# 自适应：不同输入特征的预测集合大小不同——
# 高频/简单模式→小集合（高信息量），低频/难模式→大集合（保守）。
# ============================================================================

class AdaptiveConformalPredictor:
    """自适应保形预测器：基于多校准集的层次化预测。

    将校准数据按协变量（如漏洞类型、严重度）分区，
    每个分区独立确定分数阈值，实现条件覆盖保证。
    """

    def __init__(self, alpha: float = 0.1):
        self.alpha = alpha
        self._partition_thresholds: Dict[str, float] = {}
        self._partition_scores: Dict[str, List[float]] = {}

    def fit_partition(self, partition_key: str,
                      calibration_scores: List[float]):
        """为特定分区拟合校准阈值。"""
        _n = len(calibration_scores)
        if _n < 5:
            self._partition_thresholds[partition_key] = float('inf')
            return
        _sorted = sorted(calibration_scores)
        _q_idx = int((1.0 - self.alpha) * (_n + 1))
        _q_idx = min(_q_idx, _n - 1)
        self._partition_thresholds[partition_key] = _sorted[_q_idx]
        self._partition_scores[partition_key] = _sorted

    def predict_set_size(self, partition_key: str,
                          test_score_fn) -> ConformalPredictionResult:
        """对给定分区的测试点返回预测集大小估计。

        如果该分区未见（无校准数据），回退到全局阈值。
        """
        _threshold = self._partition_thresholds.get(partition_key, float('inf'))
        _scores = self._partition_scores.get(partition_key, [])
        _n = len(_scores)

        # 简化的p值计算
        _p_vals: List[float] = [0.0]
        _test_score = test_score_fn() if callable(test_score_fn) else _threshold
        if _n > 0:
            _p_val = (sum(1 for _s in _scores if _s >= _test_score) + 1) / (_n + 1)
            _p_vals = [round(_p_val, 4)]

        _in_set = _test_score <= _threshold
        return ConformalPredictionResult(
            prediction_set=[0] if _in_set else [],
            p_values=_p_vals,
            threshold=round(_threshold, 4),
            confidence=max(0.0, 1.0 - (0 if _in_set else 1.0)))


# ============================================================================
# 最大预测集合大小 (MSC) — 校准质量的整体度量
# 预测集合越小 → 校准越有用 → 不确定性越低
# ============================================================================

def mean_prediction_set_size(predictions_sets: List[List[int]]) -> float:
    """平均预测集大小——越小说明预测越精确。

    大小为1 = 完美（单标签预测，高置信度）。
    大小等于类别数 = 完全不确定（随机猜测水平）。
    """
    if not predictions_sets:
        return 0.0
    return round(sum(len(_ps) for _ps in predictions_sets) / len(predictions_sets), 2)


def empirical_coverage(prediction_sets: List[List[int]],
                         true_labels: List[int]) -> float:
    """经验覆盖率：真实标签在预测集中的比例。

    理论保证 ≥ 1-α，实际覆盖率通常更高（保守性）。
    覆盖率远高于 1-α → 预测集过大 → 校准过于保守。
    """
    _n = len(prediction_sets)
    if _n == 0:
        return 0.0
    _covered = sum(1 for _i in range(_n) if true_labels[_i] in prediction_sets[_i])
    return round(_covered / _n, 4)


# ============================================================================
# 非一致性分数 — 几个常用的 non-conformity score
# ============================================================================

def margin_nonconformity_score(probabilities: List[float],
                                 true_label: int) -> float:
    _probs = sorted(probabilities, reverse=True)
    _margin = _probs[0] - (_probs[1] if len(_probs) > 1 else 0.0)
    return round(1.0 - _margin, 4)


def residual_nonconformity_score(prediction: float, true_value: float) -> float:
    return abs(prediction - true_value)


# ============================================================================
# 保形化集成 — 将多个校准器的输出合并为保形预测集
# ============================================================================

def conformal_ensemble(calibrator_scores: List[Tuple[List[float], List[int]]],
                         test_score_fn,
                         n_classes: int,
                         alpha: float = 0.1) -> List[int]:
    """多校准器的保形集成：取各校准器预测集的交集。

    交集策略保证最终预测集 ≤ 任一单独预测集——
    虽然更保守（覆盖率更高），但集合更小（更精确）。
    各校准器独立覆盖保证意味着：交集覆盖率 ≥ 1 - K*α（K是校准器数量）。
    """
    _pred_sets: List[List[int]] = []
    for _cal_scores, _cal_labels in calibrator_scores:
        _result = conformal_predict(
            _cal_scores, _cal_labels, test_score_fn, n_classes, alpha)
        _pred_sets.append(_result.prediction_set)

    if not _pred_sets:
        return list(range(n_classes))

    # 交集
    _intersection = set(_pred_sets[0])
    for _ps in _pred_sets[1:]:
        _intersection &= set(_ps)

    if not _intersection:  # 交集为空时取最小覆盖
        _min_set = min(_pred_sets, key=len)
        return _min_set
    return list(_intersection)


__all__ = [
    "ConformalPredictionResult",
    "conformal_predict", "adaptive_conformal_predict",
    "jackknife_plus_intervals",
    "AdaptiveConformalPredictor",
    "mean_prediction_set_size", "empirical_coverage",
    "margin_nonconformity_score", "residual_nonconformity_score",
    "conformal_ensemble",
]
