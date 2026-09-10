"""GLASSO 覆盖依赖网络 — 稀疏逆协方差 + 条件独立图.
参考: Friedman, Hastie & Tibshirani Biostatistics.
在 fuzzing 中零先例。学习覆盖维度间的稀疏条件依赖图,
Σ_{ij}^{-1}=0 ⟺ 维度 i 和 j 在给定其他维度时条件独立。"""

import math
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple


_DEFAULT_LAMBDA = 0.1
_MAX_GLASSO_ITER = 60


@dataclass
class GLASSOResult:
    n_variables: int
    n_edges: int             # 非零条件依赖边数
    sparsity: float          # 边数 / 全连接边数
    precision_matrix: List[List[float]]
    edges: List[Tuple[int, int, float]]  # (i, j, partial_corr)


class GLASSOCoverageNetwork:
    """GLASSO 覆盖依赖网络.

    Graphical Lasso: max log det Θ - tr(SΘ) - λ||Θ||₁
    Θ = Σ^{-1} (precision matrix), S = 经验协方差.
    Θ_{ij}=0 → 维度 i 和 j 条件独立 (给定其他所有维度).

    坐标下降: 逐行更新, 使用 lasso 回归子问题。
    """

    def __init__(self, lambda_reg: float = _DEFAULT_LAMBDA):
        self.lam = lambda_reg
        self._data: List[List[float]] = []
        self._n_vars: int = 0

    def add_observation(self, coverage_vector: List[float]) -> None:
        """添加一行覆盖观测 (各维度值)."""
        self._data.append(list(coverage_vector))
        self._n_vars = len(coverage_vector)
        if len(self._data) > 150:
            self._data = self._data[-100:]

    def fit(self) -> Optional[GLASSOResult]:
        n, p = len(self._data), self._n_vars
        if n < p + 2 or p < 3:
            return None

        # 经验协方差矩阵
        S = [[0.0] * p for _ in range(p)]
        means = [sum(row[j] for row in self._data) / n for j in range(p)]
        for i in range(p):
            for j in range(p):
                S[i][j] = sum((self._data[k][i] - means[i])
                             * (self._data[k][j] - means[j])
                             for k in range(n)) / (n - 1)
                S[i][j] += 1e-4 if i == j else 0.0  # Tikhonov

        # 初始化 W = S + λI, Θ = W^{-1}
        W = [[S[i][j] + (self.lam if i == j else 0.0) for j in range(p)]
             for i in range(p)]
        Theta = self._matrix_inverse(W)

        # 坐标下降
        for _ in range(_MAX_GLASSO_ITER):
            max_change = 0.0
            for j in range(p):
                # lasso 更新: 使用对角近似
                indices = [k for k in range(p) if k != j]
                beta_hat = self._lasso_step(W, S, j, p)
                for bi, idx in enumerate(indices):
                    w_new = S[idx][j]
                    for bk in range(len(indices)):
                        if bk != bi:
                            w_new -= W[idx][indices[bk]] * beta_hat[bk]
                    if abs(W[idx][j] - w_new) > max_change:
                        max_change = abs(W[idx][j] - w_new)
                    W[idx][j] = w_new; W[j][idx] = w_new
            if max_change < 1e-4:
                break

        # 从 W 恢复 Θ
        Theta = self._glasso_recover_theta(W, S, p)

        # 提取非零边
        edges = []
        for i in range(p):
            for j in range(i + 1, p):
                theta_ij = Theta[i][j]
                if abs(theta_ij) > 1e-6:
                    # 偏相关系数 = -Θ_{ij}/√(Θ_{ii}·Θ_{jj})
                    pcorr = -theta_ij / math.sqrt(max(1e-12,
                        abs(Theta[i][i] * Theta[j][j])))
                    edges.append((i, j, pcorr))
        edges.sort(key=lambda x: abs(x[2]), reverse=True)

        return GLASSOResult(
            n_variables=p, n_edges=len(edges),
            sparsity=len(edges) / max(1, p * (p - 1) / 2),
            precision_matrix=Theta, edges=edges)

    def _lasso_step(self, W: List[List[float]], S: List[List[float]],
                     j: int, p: int) -> List[float]:
        """软阈值 lasso 单步 (对角近似)."""
        beta = []
        indices = [k for k in range(p) if k != j]
        for idx in indices:
            # 简化: 单变量软阈值
            b_j = S[idx][j]
            w_jj = max(1e-8, W[idx][idx])
            # 软阈值: sign(b)*(|b|-λ)₊
            beta_val = (abs(b_j) - self.lam) / w_jj if abs(b_j) > self.lam else 0.0
            beta.append(math.copysign(beta_val, b_j) if beta_val > 0 else 0.0)
        return beta

    def _glasso_recover_theta(self, W: List[List[float]],
                               S: List[List[float]], p: int) -> List[List[float]]:
        """从 W 恢复 Θ."""
        W_inv = self._matrix_inverse(W)
        return W_inv

    @staticmethod
    def _matrix_inverse(A: List[List[float]]) -> List[List[float]]:
        """Cholesky 逆 (对称正定)."""
        n = len(A)
        L = [[0.0] * n for _ in range(n)]
        for i in range(n):
            for j in range(i + 1):
                s = sum(L[i][k] * L[j][k] for k in range(j))
                L[i][j] = (math.sqrt(max(1e-12, A[i][i] - s)) if i == j
                          else (A[i][j] - s) / max(1e-12, L[j][j]))
        inv = [[0.0] * n for _ in range(n)]
        for col in range(n):
            z = [0.0] * n
            for i in range(n):
                z[i] = ((1.0 if i == col else 0.0)
                       - sum(L[i][k] * z[k] for k in range(i))) / max(1e-12, L[i][i])
            for i in range(n - 1, -1, -1):
                inv[i][col] = (z[i] - sum(L[k][i] * inv[k][col]
                               for k in range(i + 1, n))) / max(1e-12, L[i][i])
        return inv

    def stats(self) -> dict:
        r = self.fit()
        if r is None:
            return {"n_obs": len(self._data), "n_vars": self._n_vars,
                    "status": "insufficient_data"}
        return {"n_vars": r.n_variables, "n_edges": r.n_edges,
                "sparsity": round(r.sparsity, 4),
                "lambda": self.lam, "top_edges":
                [(i, j, round(w, 3)) for i, j, w in r.edges[:5]]}

    def clear(self) -> None:
        self._data.clear()
