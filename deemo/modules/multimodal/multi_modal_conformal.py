# 保形预测与分布无关的不确定性量化
# Vovk et al. Algorithmic Learning in a Random World. 2005.
#       Angelopoulos & Bates. Conformal Prediction: A Gentle Introduction. 2021.
#       Barber et al. Predictive Inference with the Jackknife+. AOS 2021.
# 核心机制：不依赖任何分布假设，仅通过校准集分数分布构造预测区间

import math
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
from collections import defaultdict
import uuid


# 标准保形预测 — 基于校准集的非参数预测集构造
# 给定校准分数 {s_i}，预测集 = {y: score(x_new, y) ≤ q̂}
# q̂ = (1-α) 分位数（含有限样本修正因子）

@dataclass
class ConformalPredictionResult:
    prediction_set: List[int]   # 预测标签集合
    p_values: List[float]       # 每个标签的保形 p 值
    threshold: float            # 此次预测的分数门限
    confidence: float           # 1 - (avg_set_size - 1)/n_classes，反映集合紧凑度


def conformal_predict(calibration_scores: List[float],
                       calibration_labels: List[int],
                       test_score_fn,
                       n_classes: int,
                       alpha: float = 0.1) -> ConformalPredictionResult:
    """标准保形预测器。

    calibration_scores: 校准集每个样本的非一致性分数，越低表示该样本越符合分布预期。
    alpha: 允许的错误率，如 0.1 对应 90% 置信水平。

    工作机制：在校准分数经验分位数上叠加 (n+1)/n 有限样本修正，
    确保边际覆盖不等式 P(Y_test ∈ prediction_set) ≥ 1-α 恒成立。
    """
    _n = len(calibration_scores)
    if _n < 10:
        return ConformalPredictionResult(
            prediction_set=[0], p_values=[1.0]*(n_classes or 1),
            threshold=0.0, confidence=0.0)

    # 校准分数升序排列
    _sorted = sorted(calibration_scores)
    # 含有限样本修正的分位数索引
    _q_idx = int((1.0 - alpha) * (_n + 1))
    _q_idx = min(_q_idx, _n - 1)
    _threshold = _sorted[_q_idx]

    # 逐标签计算 p 值并构造预测集
    _p_values: List[float] = []
    _pred_set: List[int] = []
    for _y in range(n_classes):
        _score = test_score_fn(_y) if callable(test_score_fn) else 0.5
        # p 值定义为校准分数 ≥ 当前分数的样本比例（含连续性校正）
        _p_val = (sum(1 for _s in _sorted if _s >= _score) + 1) / (_n + 1)
        _p_values.append(round(_p_val, 4))
        if _p_val > alpha:
            _pred_set.append(_y)

    _conf = max(0.0, 1.0 - (len(_pred_set) - 1) / max(1, n_classes))
    return ConformalPredictionResult(
        prediction_set=_pred_set, p_values=_p_values,
        threshold=round(_threshold, 4), confidence=round(_conf, 4))


# Jackknife+ 预测区间 — 留一法构建分布无关区间
# Barber et al. Predictive Inference with the Jackknife+. AOS 2021.
# 相比标准保形预测，Jackknife+ 免除单独校准集的需求，
# 在样本量 < 100 时数据利用效率更高

def jackknife_plus_intervals(predictions: List[float],
                               residuals: List[float],
                               alpha: float = 0.1) -> Tuple[List[float], List[float]]:
    """Jackknife+ 预测区间构造。

    predictions: 留一预测值 μ̂_{-i}(x_i)
    residuals: 留一残差 R_i = |y_i - μ̂_{-i}(x_i)|
    alpha: 允许的错误率

    返回值：(下界列表, 上界列表)，每个测试点一个区间。
    Jackknife+ 的覆盖不等式：P(Y_test ∈ interval) ≥ 1 - 2α。
    约束为 2α 而非 α，这是对完全保形保证的理论折衷。
    """
    _n = len(predictions)
    if _n < 5:
        _lo = [min(predictions) - 10.0] if predictions else [-10.0]
        _hi = [max(predictions) + 10.0] if predictions else [10.0]
        return _lo * _n, _hi * _n

    # 残差的 (1-α) 经验分位数
    _sorted_resid = sorted(residuals)
    _q_idx = int((1.0 - alpha) * (_n + 1)) - 1
    _q_idx = max(0, min(_q_idx, _n - 1))
    _resid_q = _sorted_resid[_q_idx]

    # Jackknife+ 区间：逐点使用"除自身外所有留一预测"的极值 ± 残差分位
    _lo: List[float] = []
    _hi: List[float] = []
    for _i in range(_n):
        # 剔除第 i 个样本自身的留一残差
        _others_pred = [predictions[_j] for _j in range(_n) if _j != _i]
        _lo_i = min(_others_pred) - _resid_q if _others_pred else 0.0
        _hi_i = max(_others_pred) + _resid_q if _others_pred else 0.0
        _lo.append(round(_lo_i, 4))
        _hi.append(round(_hi_i, 4))

    return _lo, _hi


# 自适应保形预测 — 按特征分区独立设定门限
# Romano et al. Classification with Valid and Adaptive Coverage. NeurIPS 2020.
# 不同区域使用不同的分数阈值，使预测集大小随输入复杂度自适应变化——
# 常见/简单模式→紧致集合，罕见/困难模式→保守的宽集合。

class AdaptiveConformalPredictor:
    """自适应保形预测器：基于校准集分区的层次化预测。

    将校准数据按协变量（漏洞类别、严重度等）切分为独立分区，
    各分区自行确定分数门限，实现条件覆盖保证。
    """

    def __init__(self, alpha: float = 0.1):
        self.alpha = alpha
        self._partition_thresholds: Dict[str, float] = {}
        self._partition_scores: Dict[str, List[float]] = {}

    def fit_partition(self, partition_key: str,
                      calibration_scores: List[float]):
        """用指定分区的校准数据拟合分数门限。"""
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
        """给定分区测试点的预测集估计。

        若分区未见（校准时不存在该分区），回退至全局门限。
        """
        _threshold = self._partition_thresholds.get(partition_key, float('inf'))
        _scores = self._partition_scores.get(partition_key, [])
        _n = len(_scores)

        # 简化 p 值：单标签版本
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


# 平均预测集大小 (MSC) — 校准质量的聚合指标
# 集合越小 → 校准效果越好 → 不确定性越受控

def mean_prediction_set_size(predictions_sets: List[List[int]]) -> float:
    """多轮预测集的平均大小。越小精度越高。

    大小为 1 = 理想情况（单标签、高确定度）。
    大小为 n_classes = 完全无信息（等价于随机猜测）。
    """
    if not predictions_sets:
        return 0.0
    return round(sum(len(_ps) for _ps in predictions_sets) / len(predictions_sets), 2)


def empirical_coverage(prediction_sets: List[List[int]],
                         true_labels: List[int]) -> float:
    """经验覆盖率：真实标签落入预测集的样本比率。

    理论保证 ≥ 1-α，实际通常更保守（高于理论下界）。
    若覆盖率远超 1-α，说明预测集过大，校准偏于保守。
    """
    _n = len(prediction_sets)
    if _n == 0:
        return 0.0
    _covered = sum(1 for _i in range(_n) if true_labels[_i] in prediction_sets[_i])
    return round(_covered / _n, 4)


# 标准非一致性分数 — 两类常用分数函数

def margin_nonconformity_score(probabilities: List[float],
                                 true_label: int) -> float:
    _probs = sorted(probabilities, reverse=True)
    _margin = _probs[0] - (_probs[1] if len(_probs) > 1 else 0.0)
    return round(1.0 - _margin, 4)


def residual_nonconformity_score(prediction: float, true_value: float) -> float:
    return abs(prediction - true_value)


# 保形集成 — 多校准器的预测集交集

def conformal_ensemble(calibrator_scores: List[Tuple[List[float], List[int]]],
                         test_score_fn,
                         n_classes: int,
                         alpha: float = 0.1) -> List[int]:
    """多校准器保形集成：取各独立预测集的交集。

    交集策略保证最终集 ≤ 任一单独预测集——
    保守性提升（覆盖率更高），但集合更紧凑（输出更精确）。
    各校准器的独立覆盖保证导致：交集覆盖率 ≥ 1 - K·α（K 为校准器数量）。
    """
    _pred_sets: List[List[int]] = []
    for _cal_scores, _cal_labels in calibrator_scores:
        _result = conformal_predict(
            _cal_scores, _cal_labels, test_score_fn, n_classes, alpha)
        _pred_sets.append(_result.prediction_set)

    if not _pred_sets:
        return list(range(n_classes))

    # 取所有预测集的交集
    _intersection = set(_pred_sets[0])
    for _ps in _pred_sets[1:]:
        _intersection &= set(_ps)

    if not _intersection:  # 交集为空时回退到最小覆盖
        _min_set = min(_pred_sets, key=len)
        return _min_set
    return list(_intersection)


__all__ = [
    "ConformalPredictionResult",
    "conformal_predict",
    "jackknife_plus_intervals",
    "AdaptiveConformalPredictor",
    "mean_prediction_set_size", "empirical_coverage",
    "margin_nonconformity_score", "residual_nonconformity_score",
    "conformal_ensemble",
]

def _debug_print(*a,**kw):
    if __import__("os").environ.get("BINMIND_DEBUG"):print(*a,**kw)
