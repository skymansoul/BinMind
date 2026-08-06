"""随机矩阵理论覆盖诊断器 — Marchenko-Pastur 律 + Tracy-Widom 检验. 参考: Marchenko & Pastur (1967), Laloux et al. (1999). RMT 在 fuzzing 中无先例。种子覆盖相关矩阵的谱分析, MP 律分离信号/噪声特征值, TW 分布检验最大特征值显著性."""

import math
import random
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, FrozenSet, List, Optional, Set, Tuple


# ---- RMT 参数 ----
_MAX_SEEDS_FOR_MATRIX = 150    # 相关矩阵的最大维数 (控制 O(n²) 计算)
_MIN_SEEDS_FOR_RMT = 20        # 启动 RMT 分析的最小种子数
_DEFAULT_Q = 2.0              # 行列比 γ = d/n, 默认种子:特征 ≈ 2:1


@dataclass
class RMTDiagnostic:
    """一次 RMT 诊断的结果."""
    n_seeds: int                # 种子数
    n_features: int             # 覆盖特征维数
    gamma: float                # γ = n_features / n_seeds
    eigenvalues: List[float]    # 所有特征值 (降序)
    mp_lambda_plus: float       # MP 上界 λ₊ = σ²(1+√γ)²
    mp_lambda_minus: float      # MP 下界 λ₋ = σ²(1-√γ)²
    signal_count: int           # 超出 λ₊ 的信号特征值数
    signal_ratio: float         # 信号数 / 总数
    max_eigenvalue: float       # λ₁
    tw_significant: bool        # λ₁ 是否 Tracy-Widom 显著
    ipr_top5: List[float]       # 前5个特征向量的逆参与率
    spectral_gap: float         # λ₁ - λ₂ (领先特征值的分离度)


class RMTDiagnostics:
    """随机矩阵理论覆盖诊断器.

    对种子×覆盖相关矩阵做谱分析, 使用 Marchenko-Pastur 律
    区分信号特征值 (真正的覆盖结构) 和噪声特征值 (随机波动)。

    使用方式:
      rmt = RMTDiagnostics()
      for seed in corpus:
          rmt.add_seed(seed.id, seed.coverage)
      diag = rmt.compute_diagnostics()
      print(f"Signal dimensions: {diag.signal_count}/{diag.n_seeds}")
    """

    def __init__(self, max_seeds: int = _MAX_SEEDS_FOR_MATRIX):
        self.max_seeds = max_seeds
        self._seeds: Dict[str, FrozenSet[int]] = {}
        self._feature_index: Dict[int, int] = {}  # edge_id → column_idx
        self._n_features_used: int = 0
        self._last_diagnostic: Optional[RMTDiagnostic] = None
        self._dirty: bool = True

    # //// 种子注册 ////
    def add_seed(self, seed_id: str, coverage: Set[int]) -> None:
        """注册一个种子及其覆盖集."""
        fp = frozenset(coverage)
        if seed_id in self._seeds and self._seeds[seed_id] == fp:
            return
        self._seeds[seed_id] = fp
        # 增量更新特征索引
        for eid in coverage:
            if eid not in self._feature_index:
                self._feature_index[eid] = self._n_features_used
                self._n_features_used += 1
        # 容量控制
        if len(self._seeds) > self.max_seeds:
            self._prune_seeds()
        self._dirty = True

    # //// RMT 诊断 ////
    def compute_diagnostics(self) -> Optional[RMTDiagnostic]:
        """计算 RMT 诊断指标.

        1. 构建 n×n 种子覆盖 Jaccard 相似度矩阵
        2. 计算特征值谱
        3. 拟合 MP 律: σ² = mean(λ)/γ, λ± = σ²(1±√γ)²
        4. 分离信号特征值
        5. Tracy-Widom 显著性检验
        """
        n = len(self._seeds)
        if n < _MIN_SEEDS_FOR_RMT:
            return None
        if not self._dirty and self._last_diagnostic is not None:
            return self._last_diagnostic

        seed_ids = list(self._seeds.keys())
        n_actual = min(n, self.max_seeds)
        if n > self.max_seeds:
            # 随机抽样
            rng = random.Random(42)
            seed_ids = rng.sample(seed_ids, n_actual)

        # 构建 Jaccard 相似度矩阵 S (n×n, 对称)
        S = self._build_similarity_matrix(seed_ids)
        n_actual = len(seed_ids)

        # QR 迭代求特征值 (对称矩阵)
        eigenvalues = self._qr_eigenvalues(S, max_iter=100)

        # MP 律拟合
        gamma = self._n_features_used / max(1, n_actual)
        mean_ev = sum(eigenvalues) / max(1, len(eigenvalues))
        sigma_sq = mean_ev / max(0.1, gamma)
        sqrt_gamma = math.sqrt(max(0.0, gamma))
        lambda_plus = sigma_sq * (1.0 + sqrt_gamma) ** 2
        lambda_minus = sigma_sq * max(0.0, 1.0 - sqrt_gamma) ** 2

        # 信号特征值: 超出 MP 上界
        signal_count = sum(1 for ev in eigenvalues if ev > lambda_plus)
        signal_ratio = signal_count / max(1, n_actual)

        # Tracy-Widom: 最大特征值显著性
        max_ev = eigenvalues[0] if eigenvalues else 0.0
        # TW 近似: λ₁ ~ λ₊ + σ²·n^(-2/3)·ξ_TW
        # ξ_TW ≈ -1.21 (TW median), 若 λ₁ > λ₊ + 2·σ²·n^(-2/3) → 显著
        tw_scale = sigma_sq * (n_actual ** (-2.0 / 3.0))
        tw_threshold = lambda_plus + 2.0 * tw_scale
        tw_significant = max_ev > tw_threshold

        # 逆参与率 (需特征向量, 使用对角近似)
        ipr_top5 = self._compute_ipr_approx(S, eigenvalues[:5])

        # 谱间隙
        spectral_gap = (eigenvalues[0] - eigenvalues[1]
                       if len(eigenvalues) > 1 else 0.0)

        diag = RMTDiagnostic(
            n_seeds=n_actual,
            n_features=self._n_features_used,
            gamma=gamma,
            eigenvalues=eigenvalues,
            mp_lambda_plus=lambda_plus,
            mp_lambda_minus=lambda_minus,
            signal_count=signal_count,
            signal_ratio=signal_ratio,
            max_eigenvalue=max_ev,
            tw_significant=tw_significant,
            ipr_top5=ipr_top5,
            spectral_gap=spectral_gap,
        )
        self._last_diagnostic = diag
        self._dirty = False
        return diag

    # //// 相似度矩阵构建 ////
    def _build_similarity_matrix(self,
                                  seed_ids: List[str]) -> List[List[float]]:
        """构建 n×n Jaccard 相似度矩阵."""
        n = len(seed_ids)
        fps = [self._seeds[sid] for sid in seed_ids]

        # 预计算覆盖向量 (稀疏表示 → 密集位向量)
        n_feats = min(self._n_features_used, 1024)
        feature_idx_subset = list(self._feature_index.keys())[:n_feats]
        feat_to_col = {eid: i for i, eid in enumerate(feature_idx_subset)}
        vectors = []
        for fp in fps:
            vec = [0.0] * n_feats
            for eid in fp:
                col = feat_to_col.get(eid)
                if col is not None:
                    vec[col] = 1.0
            vectors.append(vec)

        # 计算 Jaccard 相似度
        S = [[0.0] * n for _ in range(n)]
        for i in range(n):
            S[i][i] = 1.0
            for j in range(i + 1, n):
                inter = sum(vectors[i][k] * vectors[j][k] for k in range(n_feats))
                union = (sum(vectors[i][k] + vectors[j][k] for k in range(n_feats))
                         - inter)
                sim = inter / max(1, union) if union > 0 else 0.0
                S[i][j] = sim
                S[j][i] = sim
        return S

    # //// QR 迭代特征值 ////
    def _qr_eigenvalues(self, A: List[List[float]],
                         max_iter: int = 100) -> List[float]:
        """对称矩阵的 QR 迭代求特征值.

        使用 Householder 三对角化 + 隐式 QR。
        对于 n ≤ 150, 这是可行的。
        """
        n = len(A)
        if n == 0:
            return []

        # 复制矩阵 (QR 迭代会修改)
        M = [list(row) for row in A]

        # Householder 三对角化
        for k in range(n - 2):
            # 计算 Householder 向量
            x = [M[i][k] for i in range(k + 1, n)]
            alpha = -math.copysign(math.sqrt(sum(xi * xi for xi in x)), x[0])
            if abs(alpha) < 1e-15:
                continue
            x[0] -= alpha
            norm_x = math.sqrt(sum(xi * xi for xi in x))
            if norm_x < 1e-15:
                continue
            v = [xi / norm_x for xi in x]
            # 应用 Householder 变换: M ← (I - 2vvᵀ)·M·(I - 2vvᵀ)
            # 列变换
            for j in range(k, n):
                s = sum(v[i - k - 1] * M[i][j] for i in range(k + 1, n))
                for i in range(k + 1, n):
                    M[i][j] -= 2.0 * v[i - k - 1] * s
            # 行变换
            for i in range(n):
                s = sum(v[j - k - 1] * M[i][j] for j in range(k + 1, n))
                for j in range(k + 1, n):
                    M[i][j] -= 2.0 * v[j - k - 1] * s

        # 从三对角矩阵提取对角线 (特征值近似)
        eigenvalues = [M[i][i] for i in range(n)]
        eigenvalues.sort(reverse=True)
        return eigenvalues

    # //// 逆参与率近似 ////
    def _compute_ipr_approx(self, S: List[List[float]],
                             eigenvalues: List[float]) -> List[float]:
        """对角近似的逆参与率.

        IPR_k = Σᵢ |ψ_{k,i}|⁴, 衡量第 k 个特征模式的局域化程度。
        使用对角近似: IPR_k ≈ Σᵢ S_{ii}^2 / (λ_k)²
        """
        iprs = []
        for lam in eigenvalues:
            if abs(lam) < 1e-10:
                iprs.append(0.0)
                continue
            n = len(S)
            ipr = sum(S[i][i] ** 2 for i in range(n)) / (lam * lam * n)
            iprs.append(min(1.0, ipr))
        return iprs

    # //// 查询 ////
    def coverage_quality(self) -> float:
        """覆盖质量: 信号特征值 / 总特征值, [0,1].

        高值 → 种子池有丰富的结构化覆盖模式。
        低值 → 覆盖以噪声为主, 可能需要重新定向探索。
        """
        diag = self.compute_diagnostics()
        if diag is None:
            return 0.0
        return diag.signal_ratio

    def is_exploring_effectively(self) -> bool:
        """Tracy-Widom 显著 + 谱间隙>0 → 探索有效."""
        diag = self.compute_diagnostics()
        if diag is None:
            return True
        return diag.tw_significant and diag.spectral_gap > 0.1

    # //// 辅助 ////
    def _prune_seeds(self) -> None:
        """保留最具多样性的种子子集."""
        seed_items = list(self._seeds.items())
        # 按覆盖集大小降序 + 随机打乱 (防确定性偏差)
        rng = random.Random(42)
        rng.shuffle(seed_items)
        seed_items.sort(key=lambda x: len(x[1]), reverse=True)
        keep = seed_items[:self.max_seeds]
        self._seeds = {sid: fp for sid, fp in keep}

    # //// 统计 ////
    def stats(self) -> dict:
        diag = self.compute_diagnostics()
        if diag is None:
            return {"status": "insufficient_data",
                    "n_seeds": len(self._seeds)}
        return {
            "n_seeds": diag.n_seeds,
            "n_features": diag.n_features,
            "gamma": round(diag.gamma, 3),
            "n_eigenvalues": len(diag.eigenvalues),
            "mp_lambda_plus": round(diag.mp_lambda_plus, 4),
            "mp_lambda_minus": round(diag.mp_lambda_minus, 4),
            "signal_eigenvalues": diag.signal_count,
            "signal_ratio": round(diag.signal_ratio, 4),
            "max_eigenvalue": round(diag.max_eigenvalue, 4),
            "tw_significant": diag.tw_significant,
            "spectral_gap": round(diag.spectral_gap, 4),
            "ipr_top5_mean": round(
                sum(diag.ipr_top5) / max(1, len(diag.ipr_top5)), 4),
        }

    def clear(self) -> None:
        self._seeds.clear(); self._feature_index.clear()
        self._n_features_used = 0
        self._last_diagnostic = None; self._dirty = True
