# 修改记录:
# 2025-07-30 15:44 - 增加连通性保护检查：删除边后验证不产生孤立节点
# 2025-08-02 11:27 - 引入稀疏度自适应因子：图越稀疏，全局 drop 概率越低
#
# 度保持边丢弃 -- 基于节点度数的反比概率边丢弃，优先保护低度节点。
#
# 理论依据：
# 二进制程序的 CFG 具有天然的度偏斜--入口块和循环头拥有高度数，
# 而错误处理块和出口块度数很低。标准的 DropEdge
# 对所有边使用统一丢弃概率 p，导致低度节点的边以概率 p 被随机删除。
# 在稀疏 CFG 中（平均度数通常 < 2），一条低度节点只有 1-2 条边，
# 固定概率丢弃会以高概率使此类节点变为孤立节点。
#
# 本模块的改进：
# 丢弃概率 p_ij = p_global * min(1, beta / max(deg_i, deg_j))
#
# 其中:
# p_global: 全局基准丢弃概率（默认 0.15）
# beta: 保护阈值--度数 <= beta 的节点的边丢弃概率显著降低
# max(deg_i, deg_j): 取最大度数而非平均--任一端度数很低，
# 整条边都应受保护。avg 会掩盖不对称性
#
# 稀疏度自适应因子:
# 全局图稀疏度 = |E| / (|V| * (|V|-1))
# p_effective = p_global * min(1.0, avg_degree / beta)
# 极稀疏图（avg_degree < beta）-> p_effective < p_global
#
# 与 BEGA 引力模型的差异：
# BEGA 需要 O(|E| * iter) 的引力场迭代。本模块仅需 O(|V|) 度数计算，
# 适用于大规模图或实时推理场景。两者可组合--先 BEGA 粗筛，再度保持精调。
#
# 文献：
# DropEdge: 统一概率随机边丢弃
# BEGA: 见 bega_gravity.py

import math
from typing import Optional, Tuple

try:
    import numpy as np
except ImportError:
    np = None


# 核心函数

def degree_preserving_dropout(
    adj: "np.ndarray",
    drop_prob: float = 0.15,
    beta: float = 2.0,
    seed: Optional[int] = None,
) -> "np.ndarray":
    """对邻接矩阵应用度保持边丢弃。返回新的邻接矩阵（不修改原始矩阵）。

    参数:
      adj:       邻接矩阵，shape (N, N)，支持有向图。
      drop_prob: 全局基准丢弃概率 ∈ [0, 1]。
      beta:      度数保护阈值。度数 <= beta 的节点的边受到保护。
      seed:      随机种子。

    边界条件: N <= 2 不丢弃任何边；无边图原样返回。
    """
    if np is None:
        raise ImportError("degree_preserving_dropout requires NumPy")

    n_nodes = adj.shape[0]
    if n_nodes <= 2:
        return adj.copy()

    if seed is not None:
        np.random.seed(seed)

    augmented = adj.copy()
    edges = np.argwhere(augmented > 0)
    if len(edges) == 0:
        return augmented

# 度数计算
    in_deg = np.array(adj.sum(axis=0)).flatten()
    out_deg = np.array(adj.sum(axis=1)).flatten()
    total_deg = in_deg + out_deg

# 稀疏度自适应因子
    avg_degree = total_deg.mean()
    sparse_factor = min(1.0, avg_degree / max(beta, 1e-9))
    effective_prob = drop_prob * sparse_factor

# 逐边丢弃决策
    for i, j in edges:
        max_deg = max(total_deg[i], total_deg[j])
        if max_deg > 0:
            degree_factor = min(1.0, beta / max_deg)
        else:
            degree_factor = 0.0  # 孤立节点边不丢弃

        edge_prob = effective_prob * degree_factor

        if np.random.random() < edge_prob:
            # 连通性保护--删除前验证不产生孤立节点
            temp = augmented.copy()
            temp[i, j] = 0
            j_connected = temp.sum(axis=0)[j] > 0 or temp.sum(axis=1)[j] > 0
            i_connected = temp.sum(axis=0)[i] > 0 or temp.sum(axis=1)[i] > 0
            if j_connected and i_connected:
                augmented[i, j] = 0

    return augmented


def compute_effective_drop_rates(
    adj: "np.ndarray",
    drop_prob: float = 0.15,
    beta: float = 2.0,
) -> Tuple[float, "np.ndarray"]:
    """计算各边的有效丢弃概率——供外部可视化和消融实验使用。

    返回:
      (effective_global_prob, per_edge_probs_matrix)
      per_edge_probs_matrix[i,j] 为边 (i,j) 的实际丢弃概率。
    """
    n_nodes = adj.shape[0]
    in_deg = np.array(adj.sum(axis=0)).flatten()
    out_deg = np.array(adj.sum(axis=1)).flatten()
    total_deg = in_deg + out_deg

    avg_degree = total_deg.mean()
    sparse_factor = min(1.0, avg_degree / max(beta, 1e-9))
    effective_prob = drop_prob * sparse_factor

    probs = np.zeros_like(adj, dtype=np.float64)
    edges = np.argwhere(adj > 0)
    for i, j in edges:
        max_deg = max(total_deg[i], total_deg[j])
        if max_deg > 0:
            probs[i, j] = effective_prob * min(1.0, beta / max_deg)

    return effective_prob, probs


# 便捷封装

class DegreePreservingDropout:
    """度保持边丢弃的可调用封装——与 GraphAugmenter 接口兼容。"""

    def __init__(self, drop_prob: float = 0.15, beta: float = 2.0,
                 seed: Optional[int] = None):
        self._p = drop_prob
        self._beta = beta
        self._seed = seed

    def __call__(self, adj: "np.ndarray") -> "np.ndarray":
        return degree_preserving_dropout(adj, self._p, self._beta, self._seed)

    @property
    def effective_drop_prob(self):
        return self._p
