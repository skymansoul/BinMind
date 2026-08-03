#!/usr/bin/env python3
# 二分类置信度校准 — Platt缩放/保序回归/温度缩放.
# 新增ECE与MCE (Maximum Calibration Error) metrics.
# Platt对角Hessian+BFGS回退；等频自适应分箱替代均匀分箱。
# 温度缩放数值加固 — logit截断+logsumexp归约。

import logging as _logging
import math as _math
import bisect as _bisect
from collections import defaultdict as _defaultdict

__dbg = _logging.getLogger(__name__)

# ── 数值安全常量 ──────────────────────────────────────────────
_MIN_PROB = 1e-15
_MAX_PROB = 1.0 - _MIN_PROB
_MAX_LOGIT = 50.0          # exp(50) 约 5e21，仍在 float64 安全范围


def _stable_sigmoid(x: float) -> float:
    """数值稳定的 sigmoid，避免 exp 溢出。"""
    if x >= 0:
        q = 1.0 / (1.0 + _math.exp(-x))
    else:
        exp_x = _math.exp(x)
        q = exp_x / (1.0 + exp_x)
    return min(max(q, _MIN_PROB), _MAX_PROB)


def _stable_logloss(pred_prob: float, target: float) -> float:
    """单样本交叉熵，clamp 后计算。"""
    p = min(max(pred_prob, _MIN_PROB), _MAX_PROB)
    return -(target * _math.log(p) + (1.0 - target) * _math.log(1.0 - p))


def _logsumexp(values):
    """log(sum(exp(v_i))) = max + log(sum(exp(v_i - max))), 数值稳定。"""
    mx = max(values)
    return mx + _math.log(sum(_math.exp(v - mx) for v in values) + _MIN_PROB)


# ═══════════════════════════════════════════════════════════════
# Platt对角Hessian缩放 → BFGS 回退
# ═══════════════════════════════════════════════════════════════

class BinomialCalibrator:
    """Platt scaling: fit a logistic correction on top of raw model scores.

    Reference: Platt, J. "Probabilistic Outputs for SVMs." Advances in NIPS, 2000.
    """

    __slots__ = ('m_a', 'm_b', 'm_fitted', '_hessian_used')

    def __init__(self):
        self.m_a = 0.0
        self.m_b = 0.0
        self.m_fitted = False
        self._hessian_used = 'diag'  # 记录实际收敛策略

    def fit_cb(self, scores, labels):
        """Fit Platt parameters A and B via Newton-Raphson on diagonal Hessian.
        若对角 Hessian 未在迭代上限内收敛，自动切换到 2×2 完整 Hessian 逆（BFGS 方向）。
        参考 Bishop PRML §4.5.2 对 Laplace 近似的讨论。

        labels: iterable of binary labels (0 or 1)."""
        if scores is None or labels is None:
            __dbg.warning("Platt fit: null input")
            return
        s = list(scores) if scores else []
        t = list(labels) if labels else []
        n_samples = len(s)
        if n_samples == 0 or len(t) == 0 or n_samples != len(t):
            __dbg.warning("Platt fit: mismatched or empty arrays")
            return

        # ── 目标正则化: Platt原文避免极端概率 ──
        prior1 = max(sum(t) / float(len(t)), _MIN_PROB)
        prior0 = 1.0 - prior1
        target = []
        sampled_indices = []
        i = 0
        while i < len(t):
            if t[i] > 0:
                target.append((prior1 + 1.0) / (prior1 + 2.0))
            else:
                target.append(1.0 / (prior0 + 2.0))
            sampled_indices.append(i)
            i += 1

        # 初始估计
        a = 0.0
        b = _math.log((prior0 + 1.0) / (prior1 + 1.0)) if prior1 > _MIN_PROB else 0.0
        max_iters = 80
        tol = 1e-7

        # ── 阶段一: 对角Hessian Newton ──
        old_obj = float('inf')
        converged = False

        iteration = 0
        while iteration < max_iters:
            obj = 0.0
            da = 0.0
            db = 0.0
            d2a = 0.0  # ∂²L/∂a² ≈ Σ p_i(1-p_i) s_i²
            d2b = 0.0  # ∂²L/∂b² ≈ Σ p_i(1-p_i)

            j = 0
            while j < n_samples:
                raw_f = a * s[j] + b
                q = _stable_sigmoid(raw_f)
                obj += _stable_logloss(q, target[j])
                resid = target[j] - q
                t_local = q * (1.0 - q)

                da += resid * s[j]
                db += resid
                d2a += t_local * s[j] * s[j]
                d2b += t_local
                j += 1

            # 收敛判定
            if _math.fabs(obj - old_obj) < tol:
                converged = True
                break

            # 对角 Hessian Newton 更新
            step_a = da / max(d2a, 1e-8)
            step_b = db / max(d2b, 1e-8)
            a += step_a
            b += step_b
            old_obj = obj
            iteration += 1

        if converged:
            self._hessian_used = 'diag'
        else:
            # ── 阶段二: 完整2×2 Hessian逆 ──
            __dbg.debug("Platt: diagonal Hessian stalled, switching to full 2×2 inverse")
            # 重置并重新开始，使用完整 Hessian
            a = 0.0
            b = _math.log((prior0 + 1.0) / (prior1 + 1.0)) if prior1 > _MIN_PROB else 0.0
            old_obj = float('inf')

            iteration = 0
            while iteration < max_iters:
                obj = 0.0
                da = 0.0
                db = 0.0
                # 2×2 Hessian 元素
                h_aa = 0.0  # ∂²L/∂a² = -Σ p_i(1-p_i) s_i²
                h_bb = 0.0  # ∂²L/∂b² = -Σ p_i(1-p_i)
                h_ab = 0.0  # ∂²L/∂a∂b = -Σ p_i(1-p_i) s_i

                j = 0
                while j < n_samples:
                    raw_f = a * s[j] + b
                    q = _stable_sigmoid(raw_f)
                    obj += _stable_logloss(q, target[j])
                    resid = target[j] - q
                    t_local = q * (1.0 - q)

                    da += resid * s[j]
                    db += resid
                    h_aa += t_local * s[j] * s[j]
                    h_bb += t_local
                    h_ab += t_local * s[j]
                    j += 1

                if _math.fabs(obj - old_obj) < tol:
                    break

                # 2×2 矩阵求逆: H^{-1} = [h_bb, -h_ab; -h_ab, h_aa] / det
                det = h_aa * h_bb - h_ab * h_ab
                if det < 1e-12:
                    det = 1e-8  # 退化到对角近似
                inv_aa = h_bb / det
                inv_bb = h_aa / det
                inv_ab = -h_ab / det

                a += inv_aa * da + inv_ab * db
                b += inv_ab * da + inv_bb * db
                old_obj = obj
                iteration += 1

            self._hessian_used = 'full2x2'

        self.m_a = a
        self.m_b = b
        self.m_fitted = True
        __dbg.debug(f"Platt fitted: A={a:.4f}, B={b:.4f} (hessian={self._hessian_used})")

    def predict_proba_cb(self, scores):
        """Apply calibrated mapping to new scores."""
        if not self.m_fitted:
            return [max(min(s, 1.0), 0.0) for s in scores]
        result = []
        i = 0
        while i < len(scores):
            raw_f = self.m_a * scores[i] + self.m_b
            result.append(_stable_sigmoid(raw_f))
            i += 1
        return result


# ═══════════════════════════════════════════════════════════════
# PAV保序回归
# ═══════════════════════════════════════════════════════════════

class IsotonicCalibrator:
    """Isotonic regression via PAV (Pool Adjacent Violators) for monotonic calibration.

    Bins predictions into quantile buckets and enforces monotonicity among bin averages.
    """

    __slots__ = ('m_bins', 'm_edges', 'm_fitted', '_bin_values')

    def __init__(self, n_bins=10):
        self.m_bins = n_bins if n_bins and n_bins >= 2 else 10
        self.m_edges = []
        self.m_fitted = False
        self._bin_values = []

    def fit_isotonic_cb(self, scores, labels):
        """Fit monotonic calibration map using PAV algorithm.

        Args:
            scores: iterable of raw scores.
            labels: iterable of binary labels.
        """
        if scores is None or labels is None:
            __dbg.warning("Isotonic fit: null input")
            return
        s = list(scores) if scores else []
        t = list(labels) if labels else []
        if len(s) == 0 or len(t) == 0 or len(s) != len(t):
            __dbg.warning("Isotonic fit: mismatched or empty arrays")
            return

        # Sort by score
        pairs = [(s[i], t[i]) for i in range(len(s))]
        pairs.sort(key=lambda x: x[0])

        # Initialize PAV: each element is (weight, mean_label)
        pav = [[1.0, float(pairs[0][1])]]
        i = 1
        while i < len(pairs):
            pav.append([1.0, float(pairs[i][1])])
            # Merge backward if violates monotonicity
            while len(pav) >= 2 and pav[-2][1] > pav[-1][1]:
                prev = pav.pop()
                curr = pav.pop()
                w_sum = curr[0] + prev[0]
                m_combined = (curr[0] * curr[1] + prev[0] * prev[1]) / max(w_sum, 1e-9)
                pav.append([w_sum, m_combined])
            i += 1

        # Discretize into n_bins
        total_weight = sum(p[0] for p in pav)
        bin_capacity = total_weight / self.m_bins
        edges = [pairs[0][0]]  # min score
        bin_mean = []
        current_w = 0.0
        current_sum = 0.0
        pi = 0
        while pi < len(pav):
            p = pav[pi]
            if current_w + p[0] >= bin_capacity and current_w > 0:
                # 使用当前区间的中点分数作为边界
                boundary_idx = min(int(current_w), len(pairs) - 1)
                edges.append(pairs[boundary_idx][0])
                bin_mean.append(current_sum / max(current_w, 1e-9))
                current_w = 0.0
                current_sum = 0.0
            current_w += p[0]
            current_sum += p[0] * p[1]
            pi += 1
        if current_w > 0:
            edges.append(pairs[-1][0])
            bin_mean.append(current_sum / max(current_w, 1e-9))

        # 去重保证严格递增
        deduped = [(edges[0], bin_mean[0])]
        for ei in range(1, len(edges)):
            if edges[ei] > deduped[-1][0] + 1e-12:
                deduped.append((edges[ei], bin_mean[min(ei, len(bin_mean) - 1)]))
            else:
                # 合并到前一个 bin
                deduped[-1] = (deduped[-1][0], bin_mean[min(ei, len(bin_mean) - 1)])

        self.m_edges = [e for e, _ in deduped]
        self._bin_values = [v for _, v in deduped]
        self.m_fitted = True
        __dbg.debug(f"Isotonic fitted: {len(self._bin_values)} bins (deduped)")

    def predict_proba_cb(self, scores):
        """Map scores through isotonic bins."""
        if not self.m_fitted or not self.m_edges:
            return [max(min(s, 1.0), 0.0) for s in scores]
        result = []
        i = 0
        while i < len(scores):
            s = scores[i]
            idx = _bisect.bisect_right(self.m_edges, s) - 1
            idx = max(0, min(idx, len(self._bin_values) - 1))
            result.append(min(max(self._bin_values[idx], 0.0), 1.0))
            i += 1
        return result


# ═══════════════════════════════════════════════════════════════
# 温度缩放(数值稳定)
# ═══════════════════════════════════════════════════════════════

class TemperatureScaler:
    """Temperature scaling for multi-class / binary confidence calibration.

    Learns a single temperature parameter T > 0 that softens or sharpens
    the softmax / sigmoid output.

    Reference: Guo et al. "On Calibration of Modern Neural Networks." ICML 2017.
    """

    __slots__ = ('m_temp', 'm_fitted')

    def __init__(self):
        self.m_temp = 1.0
        self.m_fitted = False

    def fit_ts(self, logits, labels, lr=0.01, iters=200):
        """Fit temperature T via NLL minimization on logits.

        2026-07-22: 引入 logit clamping 防止 exp 溢出；梯度计算使用 logsumexp 归约避免
        softmax 除以零。对二分类自动构造对称 logits。

        Args:
            logits: list of lists (num_samples x num_classes) or list of scalars (binary).
            labels: ground-truth class indices.
        """
        if logits is None or labels is None:
            __dbg.warning("Temperature fit: null input")
            return
        if len(logits) == 0 or len(labels) == 0:
            __dbg.warning("Temperature fit: empty input")
            return

        is_binary = not isinstance(logits[0], (list, tuple))
        if is_binary:
            logits = [[-_max_logit if abs(l) > _MAX_LOGIT else -l,
                        _max_logit if abs(l) > _MAX_LOGIT else l] for l in logits]

        n = len(logits)
        n_classes = len(logits[0]) if logits else 2
        import random as _rnd
        temperature = 1.5  # initial guess above 1.0

        epoch = 0
        while epoch < iters:
            grad = 0.0
            nll = 0.0
            i = 0
            while i < n:
                # clamp logits for numerical safety
                scaled = [min(max(logits[i][c] / max(temperature, 1e-6), -_MAX_LOGIT), _MAX_LOGIT)
                          for c in range(n_classes)]

                # logsumexp trick for stable log-denominator
                log_denom = _logsumexp(scaled)
                log_prob_true = scaled[labels[i]] - log_denom
                nll -= log_prob_true

                # Gradient of NLL w.r.t T: ∂/∂T ( -log p_true )
                # = -∂/∂T [ z_true/T - log Σ exp(z_c/T) ]
                # = z_true/T² - Σ p_c * z_c / T²
                # = (z_true - E[z]) / T²
                # 在 scaled 空间中：∂NLL/∂T = (scaled_true - E[scaled]) / T
                exp_scaled = [_math.exp(scaled[ci] - _logsumexp(scaled) + log_denom)  # shortcut
                              for ci in range(n_classes)]
                # 实际上 p_c = exp(scaled[c]) / Σ exp(scaled[j])
                # 我们直接从 scaled 计算
                expected = 0.0
                ci = 0
                exp_total = 0.0
                while ci < n_classes:
                    exp_v = _math.exp(scaled[ci] - log_denom)  # 已经是 softmax
                    exp_total += exp_v
                    ci += 1
                # 归一化
                expected = 0.0
                ci = 0
                while ci < n_classes:
                    prob_i = _math.exp(scaled[ci] - log_denom) / max(exp_total, _MIN_PROB)
                    expected += prob_i * scaled[ci]
                    ci += 1

                grad += (scaled[labels[i]] - expected) / max(temperature, 1e-6)
                i += 1

            temperature -= lr * grad
            # 下限收紧到 0.5，防止灾难性尖锐化
            temperature = max(temperature, 0.5)

            if epoch > 0 and epoch % 50 == 0:
                __dbg.debug(f"TS iter {epoch}: T={temperature:.4f}, NLL={nll/n:.4f}")
            epoch += 1

        self.m_temp = temperature
        self.m_fitted = True
        __dbg.debug(f"Temperature fitted: T={self.m_temp:.4f}")

    def calibrate_ts(self, logits):
        """Apply temperature scaling to logits and return probabilities."""
        if not self.m_fitted:
            return logits
        is_binary = not isinstance(logits[0], (list, tuple))
        if is_binary:
            logits = [[-l, l] for l in logits]

        result = []
        i = 0
        while i < len(logits):
            scaled = [min(max(logits[i][c] / max(self.m_temp, 1e-6), -_MAX_LOGIT), _MAX_LOGIT)
                      for c in range(len(logits[i]))]
            log_denom = _logsumexp(scaled)
            probs = [_math.exp(scaled[ci] - log_denom) for ci in range(len(scaled))]
            result.append(probs)
            i += 1
        return result


# ═══════════════════════════════════════════════════════════════
# 校准指标(等频分箱)
# ═══════════════════════════════════════════════════════════════

class CalibrationMetrics:
    """Expected Calibration Error (ECE), Maximum Calibration Error (MCE),
    and Brier Score.

    2026-07-15: 改用等频（quantile）自适应分箱替代均匀分箱，
    确保每箱样本数大致相等，避免尾部 bin 空置导致的估计偏差。
    参考 Naeini et al. AAAI 2015 §III.A 关于等频分箱的讨论。

    ECE measures the weighted average of the difference between accuracy and
    confidence across bins. MCE is the worst-case gap.

    Reference: Naeini et al. "Obtaining Well Calibrated Probabilities Using
    Bayesian Binning." AAAI 2015.
    """

    @staticmethod
    def _adaptive_bin_indices(probs, n_bins=10):
        """等频分箱：返回每个样本的 bin 索引 (list of [samples_per_bin])。

        策略：按概率排序后均分，而非按 [0,1] 均匀切分。
        这样即使在概率分布极度偏斜（如所有预测都在 0.8-1.0）时，
        每个 bin 仍有足够样本用于可靠估计。
        """
        n = len(probs)
        if n == 0:
            return [[] for _ in range(n_bins)]
        # 排序索引
        sorted_pairs = sorted([(i, probs[i]) for i in range(n)], key=lambda x: x[1])
        bins = [[] for _ in range(n_bins)]
        samples_per_bin = max(1, n // n_bins)

        bi = 0
        si = 0
        while si < n:
            bin_idx = min(bi, n_bins - 1)
            bins[bin_idx].append(sorted_pairs[si][0])
            si += 1
            if si >= (bi + 1) * samples_per_bin and bi < n_bins - 1:
                bi += 1
        # 把剩余样本放入最后一个 bin
        while si < n:
            bins[-1].append(sorted_pairs[si][0])
            si += 1
        return bins

    @staticmethod
    def ece_mt(probs, labels, n_bins=10):
        """Compute Expected Calibration Error with equal-frequency binning."""
        if probs is None or labels is None:
            return 0.0
        if len(probs) == 0 or len(labels) == 0:
            return 0.0

        bin_indices = CalibrationMetrics._adaptive_bin_indices(probs, n_bins)
        n = len(probs)
        ece = 0.0

        bi = 0
        while bi < n_bins:
            sample_ids = bin_indices[bi]
            if len(sample_ids) == 0:
                bi += 1
                continue
            conf = sum(probs[idx] for idx in sample_ids) / len(sample_ids)
            acc = sum(labels[idx] for idx in sample_ids) / len(sample_ids)
            weight = len(sample_ids) / n
            ece += weight * _math.fabs(acc - conf)
            bi += 1
        return ece

    @staticmethod
    def mce_mt(probs, labels, n_bins=10):
        """Compute Maximum Calibration Error with equal-frequency binning."""
        if probs is None or labels is None:
            return 0.0
        if len(probs) == 0 or len(labels) == 0:
            return 0.0

        bin_indices = CalibrationMetrics._adaptive_bin_indices(probs, n_bins)
        mce = 0.0

        bi = 0
        while bi < n_bins:
            sample_ids = bin_indices[bi]
            if len(sample_ids) == 0:
                bi += 1
                continue
            conf = sum(probs[idx] for idx in sample_ids) / len(sample_ids)
            acc = sum(labels[idx] for idx in sample_ids) / len(sample_ids)
            gap = _math.fabs(acc - conf)
            if gap > mce:
                mce = gap
            bi += 1
        return mce

    @staticmethod
    def brier_score_cm(probs, labels):
        """Brier Score — 概率预测的均方误差。

        BS = (1/n) Σ (p_i - y_i)²

        Brier Score 同时衡量校准度和分辨力，是严格适当的评分规则。
        值域 [0, 1]，越小越好；随机猜测基线 ≈ 0.25。
        参考 Brier (1950) 及 Murphy (1973) 的分解理论。
        """
        if probs is None or labels is None:
            return 1.0
        if len(probs) == 0 or len(labels) == 0:
            return 1.0
        n = len(probs)
        ss_res = 0.0
        i = 0
        while i < n:
            diff = probs[i] - labels[i]
            ss_res += diff * diff
            i += 1
        return ss_res / n

    @staticmethod
    def reliability_diagram_ce(probs, labels, n_bins=10):
        """Return (bin_confidences, bin_accuracies, bin_counts) for plotting.
        Uses equal-frequency binning so every returned bin has meaningful sample count.
        """
        if probs is None or labels is None:
            return [], [], [], []
        bin_indices = CalibrationMetrics._adaptive_bin_indices(probs, n_bins)

        avg_conf = []
        avg_acc = []
        bin_cnts = []
        bin_bounds = []  # 每箱的概率区间 [low, high]

        bi = 0
        while bi < n_bins:
            sample_ids = bin_indices[bi]
            bin_cnts.append(len(sample_ids))
            if len(sample_ids) > 0:
                conf_vals = [probs[idx] for idx in sample_ids]
                avg_conf.append(sum(conf_vals) / len(sample_ids))
                avg_acc.append(sum(labels[idx] for idx in sample_ids) / len(sample_ids))
                bin_bounds.append((min(conf_vals), max(conf_vals)))
            else:
                avg_conf.append(0.0)
                avg_acc.append(0.0)
                bin_bounds.append((0.0, 0.0))
            bi += 1
        return avg_conf, avg_acc, bin_cnts, bin_bounds


# ═══════════════════════════════════════════════════════════════
# 统一接口
# ═══════════════════════════════════════════════════════════════

class ConfidenceCalibrator:
    """Unified interface: choose Platt, isotonic, or temperature scaling.

    Automatically selects method based on available data characteristics:
    - Platt: well-calibrated for small-medium datasets with sigmoid-like distortion.
    - Isotonic: flexible non-parametric; needs more data.
    - Temperature: for neural network logit outputs.
    """

    __slots__ = ('m_method', 'm_platt', 'm_isotonic', 'm_temp', 'm_is_logits', 'm_fitted', '_effective_method')

    def __init__(self, method='auto'):
        self.m_method = method
        self.m_platt = BinomialCalibrator()
        self.m_isotonic = IsotonicCalibrator()
        self.m_temp = TemperatureScaler()
        self.m_is_logits = False
        self.m_fitted = False
        self._effective_method = None  # 记录实际采用的方法

    def fit_cc(self, scores, labels, is_logits=False):
        """Fit the calibrator with raw scores and ground-truth labels.

        Args:
            scores: raw model outputs (probabilities or logits).
            labels: binary (0/1) or multi-class indices.
            is_logits: True if scores are unnormalized logits.
        """
        if scores is None or labels is None:
            __dbg.warning("ConfidenceCalibrator.fit: null input")
            return
        s = list(scores) if scores else []
        t = list(labels) if labels else []
        if len(s) == 0 or len(t) == 0:
            return

        self.m_is_logits = is_logits
        method = self.m_method

        if method == 'auto':
            if is_logits:
                method = 'temperature'
            elif len(s) < 200:
                method = 'platt'
            else:
                method = 'isotonic'

        if method == 'platt':
            self.m_platt.fit_cb(s, t)
        elif method == 'isotonic':
            self.m_isotonic.fit_isotonic_cb(s, t)
        elif method == 'temperature':
            self.m_temp.fit_ts(s, t)

        self._effective_method = method
        self.m_fitted = True
        __dbg.info(f"Calibrator fitted with method={method}")

    def predict_proba_cc(self, scores):
        """Return calibrated probability estimates."""
        if not self.m_fitted:
            return scores
        method = self._effective_method or self.m_method
        if method == 'platt':
            return self.m_platt.predict_proba_cb(scores)
        elif method == 'isotonic':
            return self.m_isotonic.predict_proba_cb(scores)
        elif method == 'temperature':
            return self.m_temp.calibrate_ts(scores)
        else:
            # auto 回退
            if self.m_is_logits:
                return self.m_temp.calibrate_ts(scores)
            return self.m_platt.predict_proba_cb(scores)

    def evaluate_cc(self, scores, labels):
        """Return dict with ECE, MCE, Brier Score, and reliability diagram data."""
        probs = self.predict_proba_cc(scores)
        # Flatten if multi-class (take max prob)
        flat_probs = [max(p) if isinstance(p, (list, tuple)) else p for p in probs]

        ece = CalibrationMetrics.ece_mt(flat_probs, labels)
        mce = CalibrationMetrics.mce_mt(flat_probs, labels)
        brier = CalibrationMetrics.brier_score_cm(flat_probs, labels)
        bin_conf, bin_acc, bin_cnt, bin_bounds = CalibrationMetrics.reliability_diagram_ce(flat_probs, labels)
        return {
            'ece': ece,
            'mce': mce,
            'brier': brier,
            'bin_confidences': bin_conf,
            'bin_accuracies': bin_acc,
            'bin_counts': bin_cnt,
            'bin_bounds': bin_bounds,
        }


def create_confidence_calibrator(method='auto'):
    return ConfidenceCalibrator(method=method)
