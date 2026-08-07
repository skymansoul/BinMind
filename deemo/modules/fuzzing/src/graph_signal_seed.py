"""图信号种子分析 (Graph Signal Processing on Seeds, GSPS).

修改记录:
2025-08-14 11:33 - Laplacian 图傅里叶变换 + 覆盖信号频谱分解
2025-08-15 09:17 - 平滑度评分: 信号与低频本征模的对齐程度
2025-08-16 14:08 - 高通滤波: 移除低频分量→残差信号→检测异常种子

  Shuman et al. "The Emerging Field of Signal Processing on Graphs"
    (IEEE SPM) — GSP 的综述: 图傅里叶变换、滤波、采样
  Ortega et al. "Graph Signal Processing: Overview, Challenges,
    and Applications" (Proc. IEEE) — GSP 在各领域的应用
  Hammond, Vandergheynst & Gribonval "Wavelets on Graphs via
    Spectral Graph Theory" (ACHA) — 图谱小波

在 fuzzing 中零先例。将覆盖值视为 ISRG 图上的信号:
  x_i = coverage_gain at seed i
  L = D - A (组合 Laplacian)
  图傅里叶变换: x̂ = Uᵀ·x, 其中 U 是 L 的特征向量
  平滑度: xᵀLx = Σ λ_k·|x̂_k|² — 信号在低频分量上的能量

核心创新:
  1. 覆盖信号频谱: 分解为低频 (平滑区域) + 高频 (突变区域)
  2. 平滑度诊断: 信号与最低频本征模对齐 → 覆盖结构良好
  3. 高通滤波残差: 去除低频 → 残差 → 检测覆盖异常的种子
"""

import math
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

# GSPS 参数
_N_EIGENVECTORS = 8          # 保留的本征向量数

@dataclass
class GraphSignalResult:
    """一次图信号分析的结果."""
    n_nodes: int
    n_edges: int
    eigenvalues: List[float]     # 前 k 个特征值
    signal_energy: float         # xᵀx
    smoothness: float            # xᵀLx — 越小越平滑
    lowpass_energy_ratio: float  # 低频能量 / 总能量
    # 异常种子 (高通残差大)
    anomaly_seeds: List[Tuple[str, float]]  # (seed_id, residual_norm)

class GraphSignalProcessor:
    """图信号处理器 — 覆盖信号在 ISRG 图上的频谱分析.

    Graph Fourier Transform: x̂_k = <x, u_k> = Σ x_i·u_k(i)
    频率 = λ_k (特征值), λ₁=0 是直流分量, λ₂<λ₃<...是递增频率。
    低频 = 图上的平滑变化, 高频 = 快速振荡 (局部异常)。

    使用方式:
      gsp = GraphSignalProcessor()
      gsp.set_graph(adjacency_dict)
      gsp.set_signal({seed_id: coverage_value, ...})
      result = gsp.analyze()
      print(f"Smoothness: {result.smoothness:.2f}")
    """

    def __init__(self):
        self._adjacency: Dict[str, Set[str]] = defaultdict(set)
        self._signal: Dict[str, float] = {}
        self._node_ids: Dict[str, int] = {}
        self._idx_to_id: Dict[int, str] = {}
        self._n_nodes: int = 0
        # 缓存谱分解
        self._eigenvalues: List[float] = []
        self._eigenvectors: List[List[float]] = []

    def set_graph(self, adjacency: Dict[str, Set[str]]) -> None:
        """设置种子图邻接关系."""
        self._adjacency.clear()
        idx = 0
        for sid in adjacency:
            self._node_ids[sid] = idx
            self._idx_to_id[idx] = sid
            idx += 1
        self._n_nodes = idx
        for sid, neighbors in adjacency.items():
            if sid in self._node_ids:
                i = self._node_ids[sid]
                for nb in neighbors:
                    if nb in self._node_ids:
                        self._adjacency[i].add(self._node_ids[nb])

    def set_signal(self, signal: Dict[str, float]) -> None:
        """设置节点上的覆盖信号."""
        self._signal = {sid: signal.get(sid, 0.0)
                       for sid in self._node_ids}

    # //// 图傅里叶变换 ////
    def analyze(self) -> Optional[GraphSignalResult]:
        """执行图信号频谱分析."""
        n = self._n_nodes
        if n < 3:
            return None

        # 构建 Laplacian L = D - A (组合 Laplacian)
        L = self._build_laplacian()
        # 特征分解
        self._eigendecompose(L)

        # 信号向量
        x = [self._signal.get(self._idx_to_id.get(i, ""), 0.0)
             for i in range(n)]
        # 去均值 (直流分量)
        x_mean = sum(x) / n
        x_centered = [xi - x_mean for xi in x]

        # 图傅里叶变换: x̂ = Uᵀ·x (U 的列是特征向量)
        k = min(_N_EIGENVECTORS, len(self._eigenvectors))
        x_hat = []
        for j in range(k):
            uj = self._eigenvectors[j]
            x_hat_j = sum(x_centered[i] * uj[i] for i in range(n))
            x_hat.append(x_hat_j)

        # 信号能量
        signal_energy = sum(xi * xi for xi in x_centered)

        # 平滑度: xᵀLx = Σ λ_k·|x̂_k|²
        smoothness = 0.0
        for j in range(k):
            lam = (self._eigenvalues[j] if j < len(self._eigenvalues)
                   else 0.0)
            smoothness += lam * (x_hat[j] * x_hat[j])

        # 低频能量比例 (前 k/2 个分量)
        half_k = max(1, k // 2)
        low_energy = sum(x_hat[j] * x_hat[j] for j in range(half_k))
        total_hat_energy = sum(x_hat[j] * x_hat[j] for j in range(k))
        lowpass_ratio = (low_energy / max(1e-12, total_hat_energy)
                        if total_hat_energy > 1e-12 else 0.0)

        # 高通残差: x - lowpass(x) → 异常节点
        anomaly_scores = self._highpass_residual(x_centered, half_k, n)

        return GraphSignalResult(
            n_nodes=n, n_edges=sum(len(v) for v in self._adjacency.values()) // 2,
            eigenvalues=self._eigenvalues[:k],
            signal_energy=signal_energy,
            smoothness=smoothness,
            lowpass_energy_ratio=lowpass_ratio,
            anomaly_seeds=anomaly_scores[:10],
        )

    def _build_laplacian(self) -> List[List[float]]:
        """构建组合 Laplacian L = D - A."""
        n = self._n_nodes
        degrees = [len(self._adjacency.get(i, set())) for i in range(n)]
        L = [[0.0] * n for _ in range(n)]
        for i in range(n):
            L[i][i] = float(degrees[i])
            for j in self._adjacency.get(i, set()):
                L[i][j] = -1.0
        return L

    def _eigendecompose(self, L: List[List[float]]) -> None:
        """幂迭代求前 k 个最小特征值和特征向量."""
        import random
        n = self._n_nodes
        k = min(_N_EIGENVECTORS, n)
        self._eigenvalues = []
        self._eigenvectors = []
        rng = random.Random(42)

        # 对 L 做谱移位: L_shift = max_degree·I - L → 最大特征值对应 L 的最小
        max_deg = max(L[i][i] for i in range(n)) if n > 0 else 1
        A = [[0.0] * n for _ in range(n)]
        for i in range(n):
            for j in range(n):
                if i == j:
                    A[i][j] = max_deg - L[i][j]
                else:
                    A[i][j] = -L[i][j]

        for _ in range(k):
            v = [rng.random() for _ in range(n)]
            norm = math.sqrt(sum(x*x for x in v))
            v = [x/max(1e-15, norm) for x in v]
            for __ in range(60):
                Av = [sum(A[i][j]*v[j] for j in range(n)) for i in range(n)]
                for pv in self._eigenvectors:
                    dot = sum(Av[i]*pv[i] for i in range(n))
                    Av = [Av[i]-dot*pv[i] for i in range(n)]
                norm = math.sqrt(sum(x*x for x in Av))
                if norm < 1e-10: break
                v_new = [x/norm for x in Av]
                diff = math.sqrt(sum((v_new[i]-v[i])**2 for i in range(n)))
                v = v_new
                if diff < 1e-8: break
            # Rayleigh quotient for L
            Lv = [sum(L[i][j]*v[j] for j in range(n)) for i in range(n)]
            rayleigh = sum(v[i]*Lv[i] for i in range(n))
            self._eigenvalues.append(max(0.0, rayleigh))
            self._eigenvectors.append(v)

    def _highpass_residual(self, x: List[float], cutoff: int,
                            n: int) -> List[Tuple[str, float]]:
        """高通滤波: 移除低通分量后的残差."""
        # 重构低通信号: x_low = Σ_{k<cutoff} x̂_k·u_k
        x_low = [0.0] * n
        for j in range(min(cutoff, len(self._eigenvectors))):
            uj = self._eigenvectors[j]
            x_hat_j = sum(x[i] * uj[i] for i in range(n))
            for i in range(n):
                x_low[i] += x_hat_j * uj[i]
        # 残差 = x - x_low
        residuals = [abs(x[i] - x_low[i]) for i in range(n)]
        scored = [(self._idx_to_id.get(i, f"n{i}"), residuals[i])
                  for i in range(n)]
        scored.sort(key=lambda t: t[1], reverse=True)
        return scored

    # //// 统计 ////
    def stats(self) -> dict:
        result = self.analyze()
        if result is None:
            return {"n_nodes": self._n_nodes, "status": "insufficient_data"}
        return {
            "n_nodes": result.n_nodes, "n_edges": result.n_edges,
            "signal_energy": round(result.signal_energy, 2),
            "smoothness": round(result.smoothness, 3),
            "lowpass_ratio": round(result.lowpass_energy_ratio, 3),
            "n_anomalies": len(result.anomaly_seeds),
            "top_anomaly": (result.anomaly_seeds[0]
                           if result.anomaly_seeds else None),
        }

    def clear(self) -> None:
        self._adjacency.clear(); self._signal.clear()
        self._node_ids.clear(); self._idx_to_id.clear()
        self._n_nodes = 0
        self._eigenvalues.clear(); self._eigenvectors.clear()
