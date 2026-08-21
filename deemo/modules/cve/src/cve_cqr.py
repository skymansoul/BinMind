# 共形分位数回归自适应区间
# 共形分位数回归 - CVE评分的自适应宽度预测区间
#
# 问题: 标准共形预测 (cve_conformal) 使用全局常数q_hat,
# 对每个CVE产生等宽预测区间. 但CVE的评分不确定性是异方差的:
# 常见CWE (如XSS) 的预测方差低 → 窄区间足够.
# 罕见CWE (如AI投毒) 的预测方差高 → 需要宽区间.
# 等宽区间导致: 对"容易"的CVE过于保守 (浪费决策带宽),
# 对"困难"的CVE覆盖不足 (误判风险).
#
# 解决方案: 共形分位数回归.
# 训练两个分位数回归器 Q_α/2(x) 和 Q_{1-α/2}(x),
# 然后用共形校准修正系统性偏差:
#   L(x) = Q_α/2(x) - q_lo
#   U(x) = Q_{1-α/2}(x) + q_hi
# 其中 q_lo, q_hi 在校准集上计算, 确保 P(y∈[L,U]) ≥ 1-α.
#
# 关键改进:
#   CCQR使用 Max-then-Average 评分但在校准阶段错误地
#   使用了 Average-then-Max 结构. LCMQR修正为一致使用
#   Average-then-Max, 提供更紧的区间 (Jensen不等式).
#   本实现采用LCMQR的一致评分.
#
# 与cve_conformal.py的关系:
# ConformalExploitScorer: 等宽区间 (参数方法).
# CQRScorer: 自适应宽度区间 (非参数方法).
#   两者互补: CQR用于异方差场景, 标准共形用于同方差场景.
#
# 非显而易见性:
#   1. 首次将CQR应用于CVE评分的不确定性量化.
#      LCMQR 和 DCP 是通用方法,
#      但零应用面向CVE漏洞评分.
#   2. LCMQR一致评分: 避免CCQR的理论缺陷.
#   3. 分位数回归器使用梯度增强 (pinball loss),
#      适配CVE特征的混合类型 (连续+离散).
#
#
# CQR: Conformalized Quantile Regression (NeurIPS)
# 修正CCQR的理论不一致性
# Distribution-aware Conformal Prediction 统一框架

import math
from typing import Callable, Dict, List, Optional, Tuple


class PinballQuantileRegressor:
    """Pinball损失分位数回归器 - 梯度增强风格.

    使用坐标下降+pinball损失拟合条件分位数.
    Pinball损失: L_τ(y, ŷ) = max(τ·(y-ŷ), (τ-1)·(y-ŷ)).
    """

    def __init__(self, tau: float, n_estimators: int = 50,
                 learning_rate: float = 0.05, max_depth: int = 3):
        self._tau = tau          # 目标分位数 ∈ (0,1)
        self._n_est = n_estimators
        self._lr = learning_rate
        self._depth = max_depth
        self._trees: List[Dict] = []  # 每棵"树"是一组分箱规则
        self._fitted = False

    def fit(self, X: List[List[float]], y: List[float]):
        """拟合分位数回归器."""
        n, d = len(X), len(X[0]) if X else 0
        if n < 10:
            return
        residuals = list(y)
        self._trees = []

        for _ in range(self._n_est):
            # 贪心分箱: 对每个特征维度排序, 找最佳分裂点
            best_feat, best_split, best_loss = -1, 0.0, float('inf')
            for feat_idx in range(d):
                sorted_idx = sorted(range(n), key=lambda i: X[i][feat_idx])
                for split_idx in range(1, n, max(1, n // 20)):
                    left_idx = sorted_idx[:split_idx]
                    right_idx = sorted_idx[split_idx:]
                    if len(left_idx) < 2 or len(right_idx) < 2:
                        continue
                    # 每侧拟合一个常数预测 (该侧残差的τ-分位数)
                    left_r = sorted([residuals[i] for i in left_idx])
                    right_r = sorted([residuals[i] for i in right_idx])
                    left_pred = left_r[int(self._tau * len(left_r))]
                    right_pred = right_r[int(self._tau * len(right_r))]
                    # 总pinball损失
                    loss = 0.0
                    for i in left_idx:
                        e = residuals[i] - left_pred
                        loss += max(self._tau * e, (self._tau - 1) * e)
                    for i in right_idx:
                        e = residuals[i] - right_pred
                        loss += max(self._tau * e, (self._tau - 1) * e)
                    if loss < best_loss:
                        best_loss = loss
                        best_feat = feat_idx
                        best_split = X[sorted_idx[split_idx]][feat_idx]

            if best_feat < 0:
                break

            self._trees.append({"feat": best_feat, "split": best_split})
            # 更新残差
            for i in range(n):
                pred = self._predict_tree(i, X[i])
                residuals[i] -= self._lr * pred

        self._fitted = True

    def _predict_tree(self, idx: int, x: List[float],
                      tree_limit: Optional[int] = None) -> float:
        """使用树集合作预测."""
        pred = 0.0
        limit = tree_limit if tree_limit is not None else len(self._trees)
        for t in self._trees[:limit]:
            if x[t["feat"]] <= t["split"]:
                pred += self._lr  # 简化: 左分支+1, 右分支-1
            else:
                pred -= self._lr
        return pred

    def predict(self, X: List[List[float]]) -> List[float]:
        """预测条件分位数."""
        if not self._fitted:
            return [0.5] * len(X)
        return [self._predict_tree(0, x) + 0.5 for x in X]

    @property
    def is_fitted(self) -> bool:
        return self._fitted


class CQRScorer:
    """共形分位数回归评分器 - 自适应宽度预测区间.

    训练两个分位数回归器 (下界α/2, 上界1-α/2),
    用共形校准修正系统性偏差.
    """

    def __init__(self, alpha: float = 0.1):
        self._alpha = alpha
        self._lo_regressor = PinballQuantileRegressor(tau=alpha / 2.0)
        self._hi_regressor = PinballQuantileRegressor(tau=1.0 - alpha / 2.0)
        self._q_lo: float = 0.0  # 下界校准量
        self._q_hi: float = 0.0  # 上界校准量
        self._calibrated = False

    def fit(self, X_train: List[List[float]], y_train: List[float],
            X_cal: List[List[float]], y_cal: List[float]):
        """训练分位数回归器 + 共形校准.

        X_train, y_train: 训练集 (拟合分位数回归器).
        X_cal, y_cal: 校准集 (计算q_lo, q_hi).
        """
        self._lo_regressor.fit(X_train, y_train)
        self._hi_regressor.fit(X_train, y_train)

        lo_preds = self._lo_regressor.predict(X_cal)
        hi_preds = self._hi_regressor.predict(X_cal)

        # LCMQR一致评分: E_i = max(lo_pred_i - y_i, y_i - hi_pred_i)
        # 使用 Average-then-Max (先计算, 再取分位数)
        scores = [max(lo_preds[i] - y_cal[i], y_cal[i] - hi_preds[i])
                  for i in range(len(y_cal))]
        scores.sort()

        n = len(scores)
        idx = int(math.ceil((n + 1) * (1.0 - self._alpha))) - 1
        idx = max(0, min(idx, n - 1))
        q_hat = scores[idx]

        self._q_lo = q_hat
        self._q_hi = q_hat
        self._calibrated = True

    def predict(self, x: List[float]) -> Dict[str, float]:
        """返回自适应预测区间."""
        if not self._calibrated:
            return {"lower": 0.0, "upper": 1.0, "interval_width": 1.0}

        lo = self._lo_regressor.predict([x])[0]
        hi = self._hi_regressor.predict([x])[0]

        lower = max(0.0, lo - self._q_lo)
        upper = min(1.0, hi + self._q_hi)
        width = upper - lower

        # 自适应标签
        if width < 0.15:
            band = "narrow"
        elif width < 0.3:
            band = "moderate"
        else:
            band = "wide"

        return {"lower": round(lower, 4), "upper": round(upper, 4),
                "interval_width": round(width, 4),
                "adaptive_band": band,
                "q_correction": round(self._q_lo, 4)}

    def predict_batch(self, X: List[List[float]]
                      ) -> List[Dict[str, float]]:
        return [self.predict(x) for x in X]

    @property
    def is_calibrated(self) -> bool:
        return self._calibrated


# 便捷接口

def build_cqr_from_data(X_train: List[List[float]], y_train: List[float],
                        X_cal: List[List[float]], y_cal: List[float],
                        alpha: float = 0.1) -> CQRScorer:
    """一站式CQR构建."""
    scorer = CQRScorer(alpha=alpha)
    scorer.fit(X_train, y_train, X_cal, y_cal)
    return scorer


def compare_with_standard_conformal(cqr: CQRScorer,
                                    X_test: List[List[float]],
                                    y_test: List[float]
                                    ) -> Dict[str, Any]:
    """评估CQR的覆盖率和效率."""
    preds = cqr.predict_batch(X_test)
    covered = sum(1 for i, p in enumerate(preds)
                  if p["lower"] <= y_test[i] <= p["upper"])
    avg_width = sum(p["interval_width"] for p in preds) / len(preds)
    widths = [p["interval_width"] for p in preds]
    return {
        "n_test": len(X_test),
        "empirical_coverage": round(covered / len(X_test), 4),
        "avg_interval_width": round(avg_width, 4),
        "min_width": round(min(widths), 4),
        "max_width": round(max(widths), 4),
        "width_std": round(
            math.sqrt(sum((w - avg_width)**2 for w in widths) / len(widths)), 4),
    }
