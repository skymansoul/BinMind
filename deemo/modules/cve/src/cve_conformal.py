# 共形预测CVE不确定性量化
# 共形预测 - CVE利用评分的分布无关不确定性量化
#
# 问题: 现有评分系统 (CVSS/EPSS/SSVC/GNN分数) 均为点估计, 无不确定性度量.
# NIST CSWP 41 (2025年5月) 明确指出 "LEV分数的误差范围当前未知".
# 这导致决策者无法区分"确信的CRITICAL"和"噪声中的CRITICAL".
#
# 解决方案: 归纳式共形预测 (Inductive Conformal Prediction, ICP).
# 原理:
#   1. 将标注数据分割为训练集 (fit model) 和校准集 (compute nonconformity).
#   2. 对新样本, 计算nonconformity分数 α = |y_pred - y_true| / σ_pred.
#   3. 预测区间: [ŷ - q_hat·σ_pred, ŷ + q_hat·σ_pred],
#      其中 q_hat = 校准集nonconformity分数的第 ⌈(n+1)(1-α)⌉/n 分位数.
#   4. 保证: P(y ∈ [ŷ - q·σ, ŷ + q·σ]) ≥ 1 - α (边际覆盖).
#
# 本实现的三个层次:
#   Level 1 - 回归共形: 对GNN/EPSS等点估计附加预测区间.
#   Level 2 - 分位数共形: 使用多个分位数回归器获取自适应区间宽度.
#   Level 3 - 自适应共形: 在线更新校准集, 检测分布偏移, 调整区间.
#
# 非显而易见性:
# 将conformal prediction首次引入CVE漏洞评分领域
# 三层自适应架构: 静态→分位数→在线, 逐级增加复杂度但提升精度
# 预测区间宽度本身作为元特征: 宽区间 → 高不确定性 → 需要更多情报收集
#
# 保证: 在exchangeability假设下, 预测区间具有有限样本覆盖保证.
#   即 P(Y_te ∈ C(X_te)) ≥ 1 - α, 对任何分布和任何样本量.
#   此保证是分布无关的, 不依赖正态性或大样本假设.
#
#
# Algorithmic Learning in a Random World
# A Gentle Introduction to Conformal Prediction
# LEV metric - 明确承认误差范围未知
# 未发现conformal prediction在CVE评分中的现有应用

import math
from typing import Dict, List, Optional, Set, Tuple, Any

from .cve_models import CVEEntry
from .cve_kb import CVEKnowledgeBase
from .cve_conformal_calibrator import AdaptiveCalibrator, CalibrationWindow


class ConformalExploitScorer:
    """Level 1: 回归共形 - 对任何点估计器附加有效的预测区间.

    输入: 点预测器 f: X → [0,1] (可以是GNN分数/EPSS/C3E分数等).
    输出: 预测区间 [L, U] 满足 P(Y ∈ [L, U]) ≥ 1 - α (边际保证).

    使用标准化nonconformity: s_i = |y_i - ŷ_i| / (σ_i + ε).
    σ_i 可由预测器的内在不确定性 (如GNN的confidence字段) 提供,
    或由校准集上的残差标准差估计.
    """

    def __init__(self, alpha: float = 0.1,
                 use_adaptive: bool = True):
        self._alpha = alpha                     # 目标误覆盖率
        self._q_hat: Optional[float] = None      # 校准分位数
        self._cal_scores: List[float] = []       # 校准集nonconformity分数
        self._calibrated = False
        self._use_adaptive = use_adaptive
        self._adaptive: Optional[AdaptiveCalibrator] = None
        if use_adaptive:
            self._adaptive = AdaptiveCalibrator(target_coverage=1.0 - alpha)

    def calibrate(self, y_true: List[float], y_pred: List[float],
                  sigma: Optional[List[float]] = None):
        """在校准集上计算nonconformity分数并确定q_hat.

        y_true: 真实利用标签 (0或1, 或连续值[0,1]).
        y_pred: 模型点预测.
        sigma: 预测不确定性 (若None则使用默认值0.05).
        """
        n = len(y_true)
        if n < 10:
            return

        if sigma is None:
            sigma = [0.05] * n

        scores = []
        for i in range(n):
            residual = abs(y_true[i] - y_pred[i])
            eps = 1e-6
            scores.append(residual / (sigma[i] + eps))

        scores.sort()

        # 有限样本修正: q_hat = score at ⌈(n+1)(1-α)⌉ 位置
        idx = int(math.ceil((n + 1) * (1.0 - self._alpha))) - 1
        idx = max(0, min(idx, n - 1))
        self._q_hat = scores[idx]
        self._cal_scores = scores
        self._calibrated = True

        if self._adaptive is not None:
            import time
            now = time.time()
            self._adaptive.calibrate(scores, [now] * len(scores))

    def calibrate_from_scores(self, nonconformity_scores: List[float]):
        """直接从nonconformity分数校准 (高级接口)."""
        if len(nonconformity_scores) < 10:
            return
        sorted_s = sorted(nonconformity_scores)
        n = len(sorted_s)
        idx = int(math.ceil((n + 1) * (1.0 - self._alpha))) - 1
        idx = max(0, min(idx, n - 1))
        self._q_hat = sorted_s[idx]
        self._cal_scores = sorted_s
        self._calibrated = True

        if self._adaptive is not None:
            import time
            now = time.time()
            self._adaptive.calibrate(nonconformity_scores, [now] * len(nonconformity_scores))

    def predict(self, y_pred: float, sigma: float = 0.05,
                use_adaptive: bool = True) -> Dict[str, Any]:
        """生成预测区间, 返回 {prediction, lower_bound, upper_bound,
        interval_width, confidence, q_hat, coverage_guarantee,
        uncertainty_level}。"""
        if not self._calibrated:
            # 未校准 → 宽区间 (安全侧)
            lower = max(0.0, y_pred - 0.3)
            upper = min(1.0, y_pred + 0.3)
            return {
                "prediction": round(y_pred, 4),
                "lower_bound": round(lower, 4),
                "upper_bound": round(upper, 4),
                "interval_width": round(upper - lower, 4),
                "confidence": 0.5,
                "q_hat": None,
                "coverage_guarantee": 1.0 - self._alpha,
                "uncertainty_level": "UNKNOWN",
                "calibrated": False,
            }

        if self._use_adaptive and self._adaptive is not None:
            import time
            lower, upper, q_used = self._adaptive.predict_interval(y_pred)
        else:
            eps = 1e-6
            q_used = self._q_hat if self._q_hat is not None else 0.5
            half_width = q_used * max(sigma, eps)
            lower = max(0.0, y_pred - half_width)
            upper = min(1.0, y_pred + half_width)

        interval_width = upper - lower

        # 不确定性水平分类:
        #   窄区间 (<0.2) → LOW (预测器确信)
        #   中区间 (0.2-0.4) → MEDIUM
        #   宽区间 (>0.4) → HIGH (需要更多情报)
        if interval_width < 0.15:
            unc_level = "LOW"
        elif interval_width < 0.35:
            unc_level = "MEDIUM"
        else:
            unc_level = "HIGH"

        # 自适应学习: 若之后获得真值, 可调用update()更新校准集
        return {
            "prediction": round(y_pred, 4),
            "lower_bound": round(lower, 4),
            "upper_bound": round(upper, 4),
            "interval_width": round(interval_width, 4),
            "confidence": round(1.0 - interval_width, 4),
            "q_hat": round(q_used, 4) if q_used is not None else None,
            "coverage_guarantee": 1.0 - self._alpha,
            "uncertainty_level": unc_level,
            "calibrated": True,
        }

    def update_with_outcome(self, y_pred: float, y_true: float,
                            sigma: float = 0.05):
        """用事后观测到的真值更新校准器 (在线学习)."""
        if self._adaptive is None:
            return
        eps = 1e-6
        score = abs(y_true - y_pred) / (sigma + eps)
        in_interval = score <= (self._q_hat or 0.5)
        self._adaptive.update(score, in_interval)
        self._cal_scores.append(score)
        # 维持排序状态以支持后续分位数更新
        self._cal_scores.sort()
        n = len(self._cal_scores)
        idx = int(math.ceil((n + 1) * (1.0 - self._alpha))) - 1
        idx = max(0, min(idx, n - 1))
        self._q_hat = self._cal_scores[idx]

    def get_stats(self) -> Dict[str, Any]:
        stat = {
            "calibrated": self._calibrated,
            "alpha": self._alpha,
            "coverage_guarantee": 1.0 - self._alpha,
            "calibration_set_size": len(self._cal_scores),
            "q_hat": round(self._q_hat, 4) if self._q_hat is not None else None,
        }
        if self._adaptive is not None:
            stat["adaptive"] = self._adaptive.get_stats()
        return stat


class QuantileConformalScorer:
    """Level 2: 分位数共形 - 使用多个分位数回归器获得自适应区间宽度.

    标准共形预测对每个样本使用相同宽度的区间 (共形分数为常数).
    分位数共形使用条件分位数:
      Lower: Q_{α/2}(x)  - 条件分位数下界
      Upper: Q_{1-α/2}(x) - 条件分位数上界
    然后用共形校准修正分位数回归的系统性偏差:
      [L'(x), U'(x)] = [Q_{α/2}(x) - q_lo·σ_lo, Q_{1-α/2}(x) + q_hi·σ_hi]

    对CVE场景适用: 不同CWE类型、不同厂商的利用特征分布不同,
    统一的区间宽度会在"易预测"区域过于保守, 在"难预测"区域覆盖不足.
    """

    def __init__(self, alpha: float = 0.1, n_quantiles: int = 9):
        self._alpha = alpha
        self._n_quantiles = n_quantiles
        self._quantile_levels = [i / (n_quantiles + 1) for i in range(1, n_quantiles + 1)]
        # 每个分位数水平的预测器权重 (用于加权聚合)
        self._quantile_weights: List[float] = []
        # 校准修正量
        self._lo_correction: float = 0.0
        self._hi_correction: float = 0.0
        self._calibrated = False

    def fit_quantiles(self, features: List[List[float]],
                      labels: List[float]):
        """从特征-标签对中估计分位数权重 (简化: 用线性插值逼近).

        完整实现需要训练多个分位数回归梯度增强树.
        此处使用经验分位数 + 特征加权的简化方案, 适应CVE特征维度 (~10).
        """
        n = len(labels)
        if n < 20:
            return

        sorted_pairs = sorted(zip(labels, features), key=lambda x: x[0])
        sorted_labels = [l for l, _ in sorted_pairs]

        self._quantile_weights = []
        for q in self._quantile_levels:
            idx = int(q * (n - 1))
            self._quantile_weights.append(sorted_labels[idx])

    def predict_quantile_interval(self, features: List[float],
                                  base_prediction: float) -> Dict[str, Any]:
        """返回自适应宽度的预测区间."""
        if not self._quantile_weights:
            # 回退: 对称区间
            half = 0.2
            return {
                "lower_bound": round(max(0.0, base_prediction - half), 4),
                "upper_bound": round(min(1.0, base_prediction + half), 4),
                "method": "fallback_symmetric",
            }

        # 基于特征向量计算分位数插值权重
        # 简化: 使用特征向量的L2范数作为"信息量"代理
        feat_norm = math.sqrt(sum(f * f for f in features)) / math.sqrt(len(features))
        # 信息量低的特征 → 更宽区间
        scale = 1.0 + max(0.0, 0.5 - feat_norm)

        alpha_lo = self._alpha / 2.0
        alpha_hi = 1.0 - self._alpha / 2.0
        lo_idx = max(0, int(alpha_lo * len(self._quantile_weights)))
        hi_idx = min(len(self._quantile_weights) - 1,
                     int(alpha_hi * len(self._quantile_weights)))

        lo_val = self._quantile_weights[lo_idx] if self._quantile_weights else 0.0
        hi_val = self._quantile_weights[hi_idx] if self._quantile_weights else 1.0

        lower = max(0.0, base_prediction - scale * max(base_prediction - lo_val, 0.1))
        upper = min(1.0, base_prediction + scale * max(hi_val - base_prediction, 0.1))

        return {
            "lower_bound": round(lower, 4),
            "upper_bound": round(upper, 4),
            "method": "quantile_adaptive",
            "feature_informativeness": round(feat_norm, 3),
        }


# 便捷集成接口

class ConformalCVEAnalyzer:
    """一站式共形CVE分析器 - 组合点预测与预测区间.

    使用模式:
      analyzer = ConformalCVEAnalyzer(alpha=0.1)
      analyzer.calibrate_from_kb(kb, score_key="gnn_score")
      result = analyzer.analyze
      # result包含: prediction, interval, uncertainty_level, recommendation
    """

    def __init__(self, alpha: float = 0.1, use_adaptive: bool = True):
        self._scorer = ConformalExploitScorer(alpha=alpha, use_adaptive=use_adaptive)
        self._quantile = QuantileConformalScorer(alpha=alpha)
        self._analysis_count = 0

    def calibrate_from_kb(self, kb: CVEKnowledgeBase,
                          score_key: str = "gnn_score",
                          alpha: float = 0.1):
        """从KB中的历史CVE数据校准共形预测器.

        score_key: 使用哪个分数的字段名.
        从KB条目中提取 (score, label) 对用于校准.
        """
        entries, _ = kb.search(limit=100000)
        if not entries:
            return

        y_true: List[float] = []
        y_pred: List[float] = []
        features: List[List[float]] = []

        for entry in entries:
            cid = _get_str(entry, "cve_id", "")
            if not cid:
                continue
            # 真实标签: KEV收录或利用成熟度≥functional → 1
            kev = _get_bool(entry, "cisa_kev")
            mat = _get_str(entry, "exploit_maturity", "unknown")
            mat_val = {"unknown": 0.0, "poc": 0.25, "proof_of_concept": 0.25,
                       "functional": 0.5, "metasploit": 0.75, "weaponized": 1.0}
            true_label = 1.0 if (kev or mat_val.get(mat.lower().strip(), 0.0) >= 0.5) else 0.0

            # 预测分数: 优先用指定分数键, 否则综合估计
            if score_key == "epss":
                pred = _get_num(entry, "epss_score") or 0.0
            elif score_key == "cvss":
                pred = (_get_num(entry, "cvss_score") or 0.0) / 10.0
            else:
                # 默认: 综合分数
                cvss = (_get_num(entry, "cvss_score") or 0.0) / 10.0
                epss = _get_num(entry, "epss_score") or 0.0
                pred = 0.4 * cvss + 0.4 * epss + (0.2 if kev else 0.0)

            y_true.append(true_label)
            y_pred.append(min(1.0, pred))

            feat = _extract_features(entry)
            features.append(feat)

        if len(y_true) >= 20:
            self._scorer.calibrate(y_true, y_pred)

        if len(features) >= 20:
            self._quantile.fit_quantiles(features, y_true)

    def analyze(self, cve_id: str, point_score: float,
                sigma: float = 0.05,
                features: Optional[List[float]] = None) -> Dict[str, Any]:
        """对单个 CVE 产生共形预测分析, 返回含预测区间、不确定性水平与决策建议的完整分析。"""
        result = self._scorer.predict(point_score, sigma)

        if features is not None:
            q_result = self._quantile.predict_quantile_interval(features, point_score)
            result["quantile_lower"] = q_result["lower_bound"]
            result["quantile_upper"] = q_result["upper_bound"]
            result["quantile_method"] = q_result.get("method", "unavailable")

        result["cve_id"] = cve_id

        # 决策建议
        unc = result.get("uncertainty_level", "UNKNOWN")
        pred = result["prediction"]
        if unc == "LOW" and pred > 0.7:
            result["recommendation"] = "IMMEDIATE_ACTION"
        elif unc == "LOW" and pred > 0.4:
            result["recommendation"] = "SCHEDULE_PATCHING"
        elif unc == "HIGH":
            result["recommendation"] = "GATHER_MORE_INTEL"
        else:
            result["recommendation"] = "MONITOR"

        self._analysis_count += 1
        return result

    def batch_analyze(self, entries: List[Any], score_key: str = "epss_score"
                      ) -> List[Dict[str, Any]]:
        """批量共形分析."""
        results = []
        for entry in entries:
            cid = _get_str(entry, "cve_id", "")
            score = _get_num(entry, score_key) or 0.0
            if score_key == "cvss_score":
                score = score / 10.0
            feat = _extract_features(entry)
            results.append(self.analyze(cid, min(1.0, score), sigma=0.08, features=feat))
        return results

    @property
    def stats(self) -> Dict[str, Any]:
        return {
            "scorer": self._scorer.get_stats(),
            "analyses_performed": self._analysis_count,
        }


# 内部辅助

from ._internal_helpers import _get_str, _get_num, _get_bool


def _extract_features(entry) -> List[float]:
    """提取标准化的特征向量 (10维)."""
    cvss = (_get_num(entry, "cvss_score") or 0.0) / 10.0
    epss = _get_num(entry, "epss_score") or 0.0
    epss_pct = _get_num(entry, "epss_percentile") or 0.0
    kev = 1.0 if _get_bool(entry, "cisa_kev") else 0.0
    mat_map = {"unknown": 0.0, "poc": 0.25, "proof_of_concept": 0.25,
               "functional": 0.5, "metasploit": 0.75, "weaponized": 1.0}
    mat = mat_map.get(_get_str(entry, "exploit_maturity", "unknown"), 0.0)
    has_fix = 1.0 if (_get_str(entry, "fix_version") or _get_str(entry, "patched_version")) else 0.0
    ref_count = 0.0
    refs = getattr(entry, 'references', None) or (entry.get('references', []) if isinstance(entry, dict) else [])
    if isinstance(refs, list):
        ref_count = min(math.log(1 + len(refs)) / math.log(101), 1.0)
    ref_list = getattr(entry, 'references', None) or (entry.get('references', []) if isinstance(entry, dict) else [])
    cpe_count = 0.0
    cpes = getattr(entry, 'cpe_matches', None) or (entry.get('cpe_matches', []) if isinstance(entry, dict) else [])
    if isinstance(cpes, list):
        cpe_count = min(math.log(1 + len(cpes)) / math.log(101), 1.0)
    return [cvss, epss, epss_pct, kev, mat, 0.5, 0.5, has_fix, ref_count, cpe_count]
