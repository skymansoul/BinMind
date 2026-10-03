"""Score Matching KSD — Hyvarinen score matching eliminates score-equiv-0 degeneracy. Estimates s(x)=Wx+b via linear score matching, substitutes into full Stein kernel. Ref: Hyvarinen (2005) JMLR."""

import math, random
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, FrozenSet, List, Optional, Set, Tuple

_N_NYSTROM = 25; _MIN_SAMPLES = 12; _LAMBDA_REG = 0.1

@dataclass
class ScoreMatchingKSDResult:
    ksd_squared: float; ksd: float; score_model_norm: float
    effective_dim: int; n_samples: int; converged: bool

class ScoreMatchingKSD:

    def __init__(self, n_features: int = 64):
        self.n_feat = n_features
        self._samples: List[FrozenSet[int]] = []
        self._feature_index: Dict[int, int] = {}
        # 得分模型参数
        self._W: List[List[float]] = []   # d×d 得分矩阵
        self._b: List[float] = []          # 偏置
        self._score_trained: bool = False

    def add_sample(self, coverage: Set[int]) -> None:
        fp = frozenset(coverage)
        self._samples.append(fp)
        for eid in coverage:
            if eid not in self._feature_index:
                self._feature_index[eid] = len(self._feature_index)
        if len(self._samples) > 200:
            self._samples = self._samples[-150:]
        self._score_trained = False

    # //// 得分匹配训练 ////
    def _train_score_model(self) -> None:
        """线性得分匹配: W = -(Σ_cov + λI)⁻¹, b = 0.

        推导: J(W,b)=E[½||Wx+b||²+tr(W)], 期望对 p(x)。
        对中心化数据的闭式解为 W = -Cov(x)⁻¹ (无正则化)。
        加入 Tikhonov: W = -(Cov + λI)⁻¹。
        """
        n = len(self._samples)
        d = min(self.n_feat, len(self._feature_index), 64)
        if n < _MIN_SAMPLES or d < 2:
            self._score_trained = False
            return

        # 特征向量化 (dense representation)
        vecs = self._to_vectors(d)
        n_actual = len(vecs)

        # 中心化
        mean = [0.0] * d
        for v in vecs:
            for j in range(d):
                mean[j] += v[j] / n_actual

        # 协方差矩阵
        cov = [[0.0] * d for _ in range(d)]
        for v in vecs:
            vc = [v[j] - mean[j] for j in range(d)]
            for i in range(d):
                for j in range(d):
                    cov[i][j] += vc[i] * vc[j] / (n_actual - 1) if n_actual > 1 else 0.0

        # 正则化协方差求逆 → W = -Cov_reg⁻¹
        for i in range(d):
            cov[i][i] += _LAMBDA_REG

        cov_inv = self._invert_matrix(cov)

        self._W = [[-cov_inv[i][j] for j in range(d)] for i in range(d)]
        self._b = [0.0] * d
        self._score_trained = True

        # 有效维度: 协方差矩阵的 rank(λ>0.01)
        evals = self._power_eigenvalues(cov, k=min(d, 8))
        self._effective_dim = sum(1 for ev in evals if ev > 0.01 * max(evals))

    # //// KSD 计算 (使用估计的得分) ////
    def evaluate(self) -> Optional[ScoreMatchingKSDResult]:
        if not self._score_trained:
            self._train_score_model()
        if not self._score_trained:
            return None

        n = len(self._samples)
        d = len(self._W)
        if n < _MIN_SAMPLES:
            return None

        vecs = self._to_vectors(d)
        n = len(vecs)

        # Nyström: 选择诱导点
        m = min(_N_NYSTROM, n)
        rng = random.Random(42)
        idx = rng.sample(range(n), m)

        # IMQ 核参数
        c = 1.0; beta = 0.5
        bandwidth = self._median_dist(vecs)

        # KSD² 估计 (简化: 用 Nyström 近似)
        ksd_sq = self._compute_ksd_nystrom(vecs, idx, bandwidth, c, beta, d)
        ksd = math.sqrt(max(0.0, ksd_sq))

        # 得分模型范数
        score_norm = math.sqrt(sum(
            sum(wij * wij for wij in row) for row in self._W))

        return ScoreMatchingKSDResult(
            ksd_squared=ksd_sq, ksd=ksd,
            score_model_norm=score_norm,
            effective_dim=getattr(self, '_effective_dim', d),
            n_samples=n,
            converged=ksd < 0.005)

    def _compute_ksd_nystrom(self, vecs: List[List[float]],
                              inducing_idx: List[int],
                              sigma: float, c: float,
                              beta: float, d: int) -> float:
        """用估计的 score function 计算 Stein 核 + Nyström."""
        n = len(vecs); m = len(inducing_idx)
        # 构建诱导点间的 Stein 核矩阵 K_mm
        K_mm = [[0.0] * m for _ in range(m)]
        for a in range(m):
            for b in range(m):
                K_mm[a][b] = self._stein_kernel(
                    vecs[inducing_idx[a]], vecs[inducing_idx[b]],
                    sigma, d)
                if a == b:
                    K_mm[a][b] += 1e-4  # 正则化

        # 构建 K_nm: 所有点 vs 诱导点
        K_nm = [[0.0] * m for _ in range(n)]
        for i in range(n):
            for j in range(m):
                K_nm[i][j] = self._stein_kernel(
                    vecs[i], vecs[inducing_idx[j]], sigma, d)

        # KSD² ≈ (1/n²) Σ_{i,j} k₀(x_i, x_j)
        # 用 Nyström: ≈ trace(K_nm @ K_mm^{-1} @ K_nm^T) / n²
        K_mm_inv = self._invert_matrix(K_mm)
        trace_est = 0.0
        for i in range(n):
            # (K_nm @ K_mm_inv)[i] row
            row = [sum(K_nm[i][k] * K_mm_inv[k][j] for k in range(m))
                  for j in range(m)]
            trace_est += sum(row[j] * K_nm[i][j] for j in range(m))
        return trace_est / max(1, n * n)

    def _stein_kernel(self, x: List[float], y: List[float],
                       sigma: float, d: int) -> float:
        """完整 Stein 核: score×score×kernel + score×grad + trace(hessian).

        k₀(x,y) = ŝ(x)ᵀŝ(y)k(x,y) + ŝ(x)ᵀ∇_y k + ŝ(y)ᵀ∇_x k + tr(∇_x∇_y k)

        其中 ŝ(x)=Wx+b (得分估计), k 是 IMQ 核。
        """
        # 得分向量
        sx = [sum(self._W[i][j] * x[j] for j in range(d)) + self._b[i]
             for i in range(d)]
        sy = [sum(self._W[i][j] * y[j] for j in range(d)) + self._b[i]
             for i in range(d)]

        # IMQ 核: k(x,y) = (c² + ||x-y||²)^(-β)
        r_sq = sum((xi - yi) ** 2 for xi, yi in zip(x, y))
        denom = (sigma * sigma + r_sq) ** (-0.5)  # β=0.5
        k_val = denom

        # 梯度: ∇_y k(x,y) = -k·(x-y)/(σ²+r²)  (对于 IMQ β=0.5)
        grad_factor = -0.5 * k_val / max(1e-12, sigma * sigma + r_sq)
        grad_y = [grad_factor * (y[i] - x[i]) for i in range(d)]
        grad_x = [grad_factor * (x[i] - y[i]) for i in range(d)]

        # 项1: ŝ(x)ᵀŝ(y)·k(x,y)
        term1 = sum(sx[i] * sy[i] for i in range(d)) * k_val

        # 项2: ŝ(x)ᵀ∇_y k + ŝ(y)ᵀ∇_x k
        term2 = (sum(sx[i] * grad_y[i] for i in range(d))
                + sum(sy[i] * grad_x[i] for i in range(d)))

        # 项3: tr(∇_x∇_y k) — IMQ 核的混合 Hessian 迹 (简化)
        # ∂²k/∂x_i∂y_i = k·(1/(σ²+r²))(1 - (x_i-y_i)²/(σ²+r²))
        hess_trace = 0.0
        for i in range(d):
            diff_sq = (x[i] - y[i]) ** 2
            hess_trace += (k_val / max(1e-12, sigma * sigma + r_sq)
                          * (1.0 - diff_sq / max(1e-12, sigma * sigma + r_sq)))
        term3 = hess_trace

        return term1 + term2 + term3

    # //// 辅助 ////
    def _to_vectors(self, d: int) -> List[List[float]]:
        feat_keys = list(self._feature_index.keys())[:d]
        col_map = {eid: i for i, eid in enumerate(feat_keys)}
        vecs = []
        for fp in self._samples:
            v = [0.0] * d
            for eid in fp:
                col = col_map.get(eid)
                if col is not None:
                    v[col] = 1.0
            norm = math.sqrt(sum(x*x for x in v))
            if norm > 1e-8:
                v = [x / norm for x in v]
            vecs.append(v)
        return vecs

    def _median_dist(self, vecs: List[List[float]]) -> float:
        n = min(len(vecs), 30); dists = []
        for i in range(n):
            for j in range(i+1, n):
                d2 = sum((vecs[i][k]-vecs[j][k])**2 for k in range(len(vecs[i])))
                dists.append(math.sqrt(d2))
        dists.sort()
        return dists[len(dists)//2] if dists else 1.0

    @staticmethod
    def _invert_matrix(A: List[List[float]]) -> List[List[float]]:
        n = len(A)
        L = [[0.0]*n for _ in range(n)]
        for i in range(n):
            for j in range(i+1):
                s = sum(L[i][k]*L[j][k] for k in range(j))
                L[i][j] = (math.sqrt(max(1e-12, A[i][i]-s)) if i==j
                          else (A[i][j]-s)/max(1e-12, L[j][j]))
        inv = [[0.0]*n for _ in range(n)]
        for col in range(n):
            z = [0.0]*n
            for i in range(n):
                z[i] = ((1.0 if i==col else 0.0)
                       -sum(L[i][k]*z[k] for k in range(i)))/max(1e-12, L[i][i])
            for i in range(n-1,-1,-1):
                inv[i][col] = (z[i]-sum(L[j][i]*inv[j][col]
                               for j in range(i+1,n)))/max(1e-12, L[i][i])
        return inv

    @staticmethod
    def _power_eigenvalues(A: List[List[float]], k: int) -> List[float]:
        n = len(A); evals = []
        rng = random.Random(42)
        for _ in range(k):
            v = [rng.random() for _ in range(n)]
            for __ in range(30):
                Av = [sum(A[i][j]*v[j] for j in range(n)) for i in range(n)]
                norm = math.sqrt(sum(x*x for x in Av))
                if norm < 1e-10: break
                v = [x/norm for x in Av]
            rq = sum(v[i]*sum(A[i][j]*v[j] for j in range(n)) for i in range(n))
            evals.append(max(0.0, rq))
        return evals

    def stats(self) -> dict:
        r = self.evaluate()
        if r is None:
            return {"n": len(self._samples), "status": "insufficient_data"}
        return {"n": r.n_samples, "ksd": round(r.ksd, 6),
                "converged": r.converged, "score_norm": round(r.score_model_norm, 3),
                "effective_dim": r.effective_dim}

    def clear(self) -> None:
        self._samples.clear(); self._feature_index.clear()
        self._W.clear(); self._b.clear(); self._score_trained = False
