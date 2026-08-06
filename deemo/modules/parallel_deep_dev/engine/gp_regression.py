"""
创建: 2025-07-28
零依赖高斯过程回归 — RBF核 + Cholesky分解 + EI采集函数。

从 hyper_optimizer.py 分离，纯数学实现，不依赖 numpy/scipy。
适用于小规模观测点（N<100）的超参优化场景。
"""

from __future__ import annotations

import math


def rbf_kernel(x1: list[float], x2: list[float], length_scale: float) -> float:
    sq_dist = sum((a - b) ** 2 for a, b in zip(x1, x2))
    return math.exp(-0.5 * sq_dist / (length_scale ** 2))


def gp_predict(
    x_star: list[float], X: list[list[float]], y: list[float],
    length_scale: float, noise: float,
) -> tuple[float, float]:
    """GP回归预测——返回 (mean, variance)。使用Cholesky分解。"""
    n = len(X)
    if n == 0:
        return 0.5, 1.0
    K = [[0.0] * n for _ in range(n)]
    for i in range(n):
        for j in range(n):
            K[i][j] = rbf_kernel(X[i], X[j], length_scale)
        K[i][i] += noise
    L = cholesky(K)
    if L is None:
        return 0.5, 1.0
    alpha = cholesky_solve(L, y)
    k_star = [rbf_kernel(x_star, X[i], length_scale) for i in range(n)]
    mean = sum(k_star[i] * alpha[i] for i in range(n))
    k_self = rbf_kernel(x_star, x_star, length_scale) + noise
    v = forward_substitution(L, k_star)
    var = k_self - sum(v[i] * v[i] for i in range(n))
    return mean, max(var, 1e-12)


def expected_improvement(
    pred_mean: float, pred_std: float, y_best: float,
) -> float:
    """期望改进 = σ·(z·Φ(z) + φ(z)), z = (μ - y_best)/σ。"""
    if pred_std < 1e-10:
        return 0.0
    z = (pred_mean - y_best) / pred_std
    return pred_std * (z * normal_cdf(z) + normal_pdf(z))


# ---------------------------------------------------------------------------
# Cholesky 分解 + 三角求解
# ---------------------------------------------------------------------------

def cholesky(A: list[list[float]]) -> list[list[float]] | None:
    n = len(A)
    L = [[0.0] * n for _ in range(n)]
    for i in range(n):
        for j in range(i + 1):
            s = sum(L[i][k] * L[j][k] for k in range(j))
            if i == j:
                diag = A[i][i] - s
                if diag <= 1e-12:
                    return None
                L[i][j] = math.sqrt(diag)
            else:
                L[i][j] = (A[i][j] - s) / L[j][j]
    return L


def forward_substitution(L: list[list[float]], b: list[float]) -> list[float]:
    n = len(L)
    y = [0.0] * n
    for i in range(n):
        y[i] = (b[i] - sum(L[i][j] * y[j] for j in range(i))) / L[i][i]
    return y


def cholesky_solve(L: list[list[float]], b: list[float]) -> list[float]:
    y = forward_substitution(L, b)
    n = len(L)
    x = [0.0] * n
    for i in range(n - 1, -1, -1):
        x[i] = (y[i] - sum(L[j][i] * x[j] for j in range(i + 1, n))) / L[i][i]
    return x


# ---------------------------------------------------------------------------
# 标准正态分布函数
# ---------------------------------------------------------------------------

def normal_cdf(x: float) -> float:
    if x < -6.0:
        return 0.0
    if x > 6.0:
        return 1.0
    return 0.5 * (1.0 + math.erf(x / math.sqrt(2.0)))


def normal_pdf(x: float) -> float:
    return math.exp(-0.5 * x * x) / math.sqrt(2.0 * math.pi)
