"""谱种子图分解器 — Laplacian 谱分析 + Fiedler 聚类 + Cheeger 瓶颈检测. 参考: Chung (1997), Shi & Malik (2000). 谱图论在 fuzzing 中无先例。通过 Laplacian 谱分解获取代数连通性, Fiedler 向量最优二分, 谱嵌入全局多样性度量."""

import math
from collections import defaultdict
from dataclasses import dataclass
from typing import Dict, FrozenSet, List, Optional, Set, Tuple


# ---- 谱分解参数 ----
_MAX_POWER_ITERS = 200        # 幂迭代最大次数
_CONVERGENCE_TOL = 1e-8       # 收敛容差
_N_SPECTRAL_DIMS = 6          # 谱嵌入维数 (前 k 个特征向量)


@dataclass
class SpectralDecomposition:
    """一次谱分解的结果."""
    eigenvalues: List[float]             # 前 k 个特征值 (升序, λ₁=0)
    eigenvectors: List[List[float]]      # 对应的特征向量
    fiedler_vector: List[float]          # λ₂ 对应的特征向量
    algebraic_connectivity: float        # λ₂
    spectral_gap: float                  # λ₂ - λ₁ (= λ₂ since λ₁=0)
    cheeger_lower_bound: float           # h(G) ≥ λ₂/2
    partition: Tuple[List[int], List[int]]  # 谱二分结果 (索引列表)
    embedding: Dict[int, List[float]]    # node_idx → k 维谱坐标


class SpectralSeedGraphDecomposer:
    """谱种子图分解器 — Laplacian 谱分析用于种子图结构发现.

    在 ISRG 的邻接矩阵上构建归一化 Laplacian,
    使用幂迭代 (Lanczos 变体) 计算前 k 个特征对,
    为种子调度和语料库管理提供大尺度结构信息。

    工作原理:
      1. 从 ISRG 获取种子间邻接关系
      2. 构建归一化 Laplacian: L_norm = I - D^(-1/2)·A·D^(-1/2)
      3. 幂迭代计算 Fiedler 向量 (λ₂)
      4. 谱嵌入: 前 k 个特征向量作为种子在谱空间中的坐标
      5. 谱二分: 按 Fiedler 分量符号分簇
    """

    def __init__(self, n_spectral_dims: int = _N_SPECTRAL_DIMS):
        self.n_dims = n_spectral_dims
        self._adjacency: Dict[int, Set[int]] = defaultdict(set)
        self._node_ids: Dict[str, int] = {}      # seed_id → node_idx
        self._idx_to_id: Dict[int, str] = {}      # node_idx → seed_id
        self._n_nodes: int = 0
        self._last_decomposition: Optional[SpectralDecomposition] = None
        self._dirty: bool = True

    # //// 图构建 ////
    def set_graph(self, adjacency: Dict[str, Set[str]]) -> None:
        """从 ISRG 邻接表构建内部图结构.

        adjacency: {seed_id → {neighbor_seed_id, ...}, ...}
        将字符串 ID 映射为整数索引以加速矩阵运算。
        """
        self._adjacency.clear()
        self._node_ids.clear()
        self._idx_to_id.clear()

        idx = 0
        for sid in adjacency:
            self._node_ids[sid] = idx
            self._idx_to_id[idx] = sid
            idx += 1
        self._n_nodes = idx

        for sid, neighbors in adjacency.items():
            if sid not in self._node_ids:
                continue
            i = self._node_ids[sid]
            for nb in neighbors:
                if nb in self._node_ids:
                    j = self._node_ids[nb]
                    self._adjacency[i].add(j)
        self._dirty = True

    def add_edge(self, seed_a: str, seed_b: str) -> None:
        """增量添加一条边 (在线更新)."""
        for sid in (seed_a, seed_b):
            if sid not in self._node_ids:
                idx = self._n_nodes
                self._node_ids[sid] = idx
                self._idx_to_id[idx] = sid
                self._n_nodes += 1
        i, j = self._node_ids[seed_a], self._node_ids[seed_b]
        self._adjacency[i].add(j)
        self._adjacency[j].add(i)
        self._dirty = True

    # //// 谱分解 ////
    def decompose(self) -> Optional[SpectralDecomposition]:
        """执行谱分解 — 计算归一化 Laplacian 的前 k 个特征对.

        使用幂迭代 + deflation: 对每个特征值, 用幂迭代求主导特征向量,
        然后用 Hotelling deflation 移除已找到的分量。
        """
        n = self._n_nodes
        if n < 2:
            return None
        if not self._dirty and self._last_decomposition is not None:
            return self._last_decomposition

        # 构建度数矩阵
        degrees = [len(self._adjacency.get(i, set())) for i in range(n)]
        max_deg = max(degrees) if degrees else 1

        eigenvalues = []
        eigenvectors = []

        # 幂迭代 + deflation 求前 k 个特征向量
        working_matrix = None  # 隐式: L_norm·x = x - D^(-1/2)·A·D^(-1/2)·x
        for k_idx in range(min(self.n_dims, n)):
            vec = self._power_iteration(degrees, eigenvalues, eigenvectors,
                                        max_deg, n)
            if vec is None:
                break
            # Rayleigh 商: λ = vᵀ·L·v / vᵀ·v
            lv = self._laplacian_matvec(vec, degrees, n)
            rayleigh = sum(vec[i] * lv[i] for i in range(n))
            eigenvalues.append(rayleigh)
            eigenvectors.append(vec)

        if len(eigenvalues) < 2:
            return None

        # Fiedler 向量 = 第二个特征向量 (对应 λ₂)
        fiedler = eigenvectors[1] if len(eigenvectors) > 1 else eigenvectors[0]
        lambda_2 = eigenvalues[1] if len(eigenvalues) > 1 else eigenvalues[0]

        # 谱二分: 按 Fiedler 分量符号
        pos_cluster = [i for i in range(n) if fiedler[i] >= 0]
        neg_cluster = [i for i in range(n) if fiedler[i] < 0]

        # Cheeger 下界
        cheeger = lambda_2 / 2.0

        # 谱嵌入: node_idx → k-dim 坐标
        embedding = {}
        for i in range(n):
            embedding[i] = [evecs[i] for evecs in eigenvectors[:self.n_dims]]

        result = SpectralDecomposition(
            eigenvalues=eigenvalues,
            eigenvectors=eigenvectors,
            fiedler_vector=fiedler,
            algebraic_connectivity=lambda_2,
            spectral_gap=lambda_2,
            cheeger_lower_bound=cheeger,
            partition=(pos_cluster, neg_cluster),
            embedding=embedding,
        )
        self._last_decomposition = result
        self._dirty = False
        return result

    def _laplacian_matvec(self, vec: List[float],
                          degrees: List[int], n: int) -> List[float]:
        """归一化 Laplacian 的矩阵-向量乘法: L·v = v - D^(-1/2)·A·D^(-1/2)·v.

        不显式构造矩阵, 使用邻接表做 O(|E|) 稀疏计算。
        """
        result = list(vec)  # 先复制 (I 部分)
        # D^(-1/2)·A·D^(-1/2)·v
        for i in range(n):
            if degrees[i] == 0:
                continue
            inv_sqrt_di = 1.0 / math.sqrt(degrees[i])
            accum = 0.0
            for j in self._adjacency.get(i, set()):
                if degrees[j] == 0:
                    continue
                accum += (1.0 / math.sqrt(degrees[j])) * vec[j]
            result[i] -= inv_sqrt_di * accum
        return result

    def _power_iteration(self, degrees: List[int],
                         prev_eigenvalues: List[float],
                         prev_eigenvectors: List[List[float]],
                         max_deg: int, n: int) -> Optional[List[float]]:
        """幂迭代求主导特征向量 (已做 deflation).

        Deflation: 在每次 matvec 后, 从结果中减去已找到特征向量的投影。
        """
        import random
        # 随机初始化
        rng = random.Random(42 + len(prev_eigenvalues))
        v = [rng.random() for _ in range(n)]
        # 归一化
        norm = math.sqrt(sum(x * x for x in v))
        if norm < 1e-15:
            return None
        v = [x / norm for x in v]

        for _ in range(_MAX_POWER_ITERS):
            # L·v
            lv = self._laplacian_matvec(v, degrees, n)
            # Deflation: 减去已收敛特征向量的投影
            for pv in prev_eigenvectors:
                dot = sum(lv[i] * pv[i] for i in range(n))
                for i in range(n):
                    lv[i] -= dot * pv[i]
            # 归一化
            norm = math.sqrt(sum(x * x for x in lv))
            if norm < 1e-15:
                break
            v_new = [x / norm for x in lv]
            # 收敛检查
            diff = math.sqrt(sum((v_new[i] - v[i]) ** 2 for i in range(n)))
            v = v_new
            if diff < _CONVERGENCE_TOL:
                break
        return v

    # //// 谱多样性评分 ////
    def spectral_diversity_score(self, seed_id: str) -> float:
        """基于谱嵌入的种子多样性评分.

        种子在 k 维谱空间中到原点的欧氏距离。
        距离大 → 在谱空间中偏离中心 → 覆盖模式独特。
        与 ISRG 的 Jaccard 多样性互补: ISRG 看局部, SSGD 看全局谱结构。
        """
        decomp = self._last_decomposition
        if decomp is None or seed_id not in self._node_ids:
            return 0.5
        idx = self._node_ids[seed_id]
        coords = decomp.embedding.get(idx)
        if coords is None:
            return 0.5
        # 从第 2 维开始 (跳过 λ₁=0 的平凡特征向量)
        dist = math.sqrt(sum(c * c for c in coords[1:]))
        # Sigmoid 归一化到 [0, 1]
        return 1.0 / (1.0 + math.exp(-dist * 3.0))

    def bottleneck_seeds(self, top_k: int = 5) -> List[str]:
        """识别谱瓶颈种子.

        瓶颈种子 = Fiedler 向量分量接近零的种子 (位于谱二分边界)。
        这些种子连接两个覆盖分区, 是跨区域探索的关键枢纽。
        """
        decomp = self._last_decomposition
        if decomp is None:
            return []
        fv = decomp.fiedler_vector
        # 按 |fiedler_component| 升序排列 (接近零的在前面)
        indices = sorted(range(len(fv)), key=lambda i: abs(fv[i]))
        result = []
        for i in indices[:top_k]:
            sid = self._idx_to_id.get(i)
            if sid:
                result.append(sid)
        return result

    def cluster_seeds(self) -> Dict[int, List[str]]:
        """谱聚类: 将种子分配到谱分区.

        返回 {cluster_id: [seed_id, ...]}。
        Fiedler 二分 + 递归 (当前仅做一层)。
        """
        decomp = self._last_decomposition
        if decomp is None:
            return {}
        pos, neg = decomp.partition
        clusters = {0: [], 1: []}
        for i in pos:
            sid = self._idx_to_id.get(i)
            if sid:
                clusters[0].append(sid)
        for i in neg:
            sid = self._idx_to_id.get(i)
            if sid:
                clusters[1].append(sid)
        return clusters

    # //// 统计 ////
    def stats(self) -> dict:
        decomp = self._last_decomposition
        self.decompose()  # 确保已分解
        decomp = self._last_decomposition
        if decomp is None or len(decomp.eigenvalues) < 2:
            return {"nodes": self._n_nodes, "decomposed": False}
        ev = decomp.eigenvalues
        return {
            "nodes": self._n_nodes,
            "decomposed": True,
            "algebraic_connectivity (lambda_2)": round(ev[1], 4),
            "spectral_gap": round(decomp.spectral_gap, 4),
            "cheeger_bound": round(decomp.cheeger_lower_bound, 4),
            "n_eigenvalues_computed": len(ev),
            "cluster_0_size": len(decomp.partition[0]),
            "cluster_1_size": len(decomp.partition[1]),
            "top_eigenvalues": [round(e, 4) for e in ev[:5]],
        }

    def clear(self) -> None:
        self._adjacency.clear(); self._node_ids.clear()
        self._idx_to_id.clear(); self._n_nodes = 0
        self._last_decomposition = None; self._dirty = True
