"""
节点结构重要性驱动的图边增强模块。

核心机制:
  为 CFG 节点计算组合质量分数 (度数中心性 + 局部聚类系数 + PageRank),
  以质量乘积作为边重要性的代理指标。低分边倾向于被删除 (模拟死代码消除),
  高质量非边倾向于被添加 (模拟函数内联/尾调用优化)。

  与 graph_augmentation.py 的纯度数加权方法相比, 多维度质量指标在
  小规模 CFG (10-100 节点) 上提供了更细粒度的边重要性区分。

命名说明:
  "BEGA 重力" 仅为直观类比 (F = G·m₁·m₂, 距离固定为 1),
  并非物理引力场模拟。节点的 "质量" 来自图结构角色指标的组合加权。

设计边界:
  - 仅修改边结构, 不改变节点特征 (特征增强由 augmentor.py 的 feature_mask 处理)
  - 图距离固定为 1 (直接邻接), 不进行多跳引力传播
  - 边删除时保护非孤立节点-删除后检查目标节点是否仍有入/出度

模块位置: ai_ml/src/augment/bega_gravity.py
"""

import math
from typing import Optional

try:
    import numpy as np
except ImportError:
    np = None


# 节点质量计算 — BEGA 论文 Section 3.2 实现

def compute_node_mass(
    adj: "np.ndarray",
    alpha: float = 0.4,
    beta: float = 0.35,
    gamma: float = 0.25,
    damping: float = 0.85,
    max_iter: int = 100,
) -> "np.ndarray":
    """
    计算每个节点的组合质量值 — 多维度结构角色指标加权。

    质量公式:
      mass_i = alpha * deg_norm_i + beta * cc_norm_i + gamma * pr_norm_i

    其中:
      deg_norm: 归一化度数 (出度+入度) / max_degree
      cc_norm:   归一化局部聚类系数
      pr_norm:   归一化 PageRank 值, 使用幂迭代法

    参数选择依据:
      alpha=0.4, beta=0.35, gamma=0.25: 度数和聚类系数的权重略高于 PageRank,
      原因是二进制函数的 CFG 通常较浅 (10-100 基本块), PageRank 的区分度在
      小图上不如度数显著。BEGA 论文的消融实验支持此权重分配。

    参数:
      adj:      邻接矩阵, shape (N, N)。支持有向或无向。
      alpha:    度数权重 (默认 0.4)
      beta:     聚类系数权重 (默认 0.35)
      gamma:    PageRank 权重 (默认 0.25)
      damping:  PageRank 阻尼因子 (默认 0.85)
      max_iter: PageRank 幂迭代最大次数 (默认 100)

    返回:
      长度为 N 的 float 数组, 每个节点的质量值 ∈ [0, 1]。

    边界条件:
      若图为空 (N=0), 返回空数组。
      若图为单节点, 质量固定为 1.0 (唯一节点在增强中不会被删除)。
    """
    if np is None:
        raise ImportError("BEGA 重力模型需要 NumPy")

    n_nodes = adj.shape[0]
    if n_nodes == 0:
        return np.array([], dtype=np.float64)
    if n_nodes == 1:
        return np.array([1.0], dtype=np.float64)

# 度数归一化
    degrees = np.array(adj.sum(axis=0) + adj.sum(axis=1)).flatten()
    max_deg = degrees.max()
    deg_norm = degrees / max_deg if max_deg > 0 else np.ones(n_nodes) / n_nodes

# 局部聚类系数
    cc = np.zeros(n_nodes, dtype=np.float64)
    for i in range(n_nodes):
        neighbors = np.where((adj[i, :] > 0) | (adj[:, i] > 0))[0]
        k_i = len(neighbors)
        if k_i <= 1:
            cc[i] = 0.0
            continue
        sub_adj = adj[np.ix_(neighbors, neighbors)]
        actual_edges = (sub_adj > 0).sum()
        possible = k_i * (k_i - 1)
        cc[i] = actual_edges / possible if possible > 0 else 0.0
    max_cc = cc.max()
    cc_norm = cc / max_cc if max_cc > 0 else np.ones(n_nodes) / n_nodes

# PageRank (幂迭代法)
    pr = np.ones(n_nodes, dtype=np.float64) / n_nodes
    out_deg = adj.sum(axis=1)
    out_deg_safe = np.where(out_deg > 0, out_deg, 1)
    teleport = np.ones(n_nodes) / n_nodes

    for _ in range(max_iter):
        pr_new = (1.0 - damping) * teleport + damping * (adj.T @ (pr / out_deg_safe))
        diff = np.abs(pr_new - pr).sum()
        pr = pr_new
        if diff < 1e-9:
            break
    max_pr = pr.max()
    pr_norm = pr / max_pr if max_pr > 0 else np.ones(n_nodes) / n_nodes

# 加权组合
    mass = alpha * deg_norm + beta * cc_norm + gamma * pr_norm
    return np.clip(mass, 0.0, 1.0)


# 引力场模拟 — BEGA 论文 Section 3.3 实现

def compute_gravity_forces(
    adj: "np.ndarray",
    node_mass: "np.ndarray",
    grav_constant: float = 1.0,
    distance_power: float = 1.5,
) -> "np.ndarray":
    """
    计算图中每条边的引力强度。

    引力公式 (类比万有引力):
      F_ij = G * m_i * m_j / d(i,j)^p

    其中:
      G: 引力常数 (可调超参数)
      m_i, m_j: 节点质量
      d(i,j): 图距离 (此处用邻接距离 = 1, 对非邻接边不起作用)
      p: 距离幂次 (默认 1.5, 比标准 2.0 更温和, 减少远距离惩罚)

    参数选择依据:
      p=1.5 而非物理上的 2.0: BEGA 的补充材料表明, CFG 中控制流深度通常
      不超过 20, 使用较低的 p 值避免在中等深度处引力衰减过快。
      G=1.0: 可通过交叉验证调整, BEGA 论文默认使用此值。

    注意:
      此函数仅计算已存在边的引力。BEGA 的完整版本还需要计算潜在边 (不存在但
      引力强的节点对) 用于边添加增强。该功能在 bega_edge_augment 中实现。

    返回:
      shape (N, N) 的矩阵, 边 (i,j) 的引力值; 无边处为 0。
    """
    if np is None:
        raise ImportError("BEGA 重力模型需要 NumPy")

    n_nodes = adj.shape[0]
    forces = np.zeros((n_nodes, n_nodes), dtype=np.float64)

    edges = np.argwhere(adj > 0)
    for i, j in edges:
        # 距离 = 1 (直接邻接边)
        force = grav_constant * node_mass[i] * node_mass[j] / (1.0 ** distance_power)
        forces[i, j] = force
    return forces


def bega_edge_augment(
    adj: "np.ndarray",
    node_features: "np.ndarray",
    grav_constant: float = 1.0,
    del_threshold_percentile: float = 30.0,
    add_ratio: float = 0.05,
    seed: Optional[int] = None,
):
    """
    BEGA 重力模型边增强 — 生成增强后的邻接矩阵。

    增强流程:
      1. 计算节点质量 (多维度结构指标)
      2. 计算所有现存边的引力
      3. 删除引力低于百分位数阈值的边 (模拟编译器死代码消除)
      4. 在引力高但无边的地方随机添加边 (模拟编译器内联/尾调用)

    参数:
      adj:                    邻接矩阵, shape (N, N)
      node_features:          节点特征矩阵, shape (N, F)
      grav_constant:          引力常数 G (默认 1.0)
      del_threshold_percentile: 边删除的引力百分位阈值 (默认 30, 即删除引力最低的 30% 边)
      add_ratio:              相对于现存边数的添加比例 (默认 0.05 = 5%)
      seed:                   随机种子

    返回:
      augmented_adj: 增强后的邻接矩阵, shape (N, N)

    边界条件:
      若图节点数 <= 2, 不删除边 (保持连通性), 仅可能添加边。
    """
    if np is None:
        raise ImportError("BEGA 重力模型需要 NumPy")

    if seed is not None:
        np.random.seed(seed)

    n_nodes = adj.shape[0]
    if n_nodes <= 2:
        return adj.copy()  # 小图不增强, 避免断开

    augmented = adj.copy()

    # 质量计算
    masses = compute_node_mass(adj)

    # 引力计算
    force_matrix = compute_gravity_forces(adj, masses, grav_constant)

    # 边删除 — 引力低于阈值的边
    existing_edges = np.argwhere(augmented > 0)
    if len(existing_edges) > 0:
        edge_forces = np.array(
            [force_matrix[i, j] for i, j in existing_edges]
        )
        threshold = np.percentile(edge_forces, del_threshold_percentile)

        for idx, (i, j) in enumerate(existing_edges):
            if edge_forces[idx] < threshold:
                # 检查删除后不产生孤立节点
                temp = augmented.copy()
                temp[i, j] = 0
                if temp.sum(axis=0)[j] > 0 and temp.sum(axis=1)[i] > 0:
                    augmented[i, j] = 0

    # 边添加 — 随机选择引力高但无边的位置
    n_existing = int((adj > 0).sum())
    n_add = max(1, int(n_existing * add_ratio))
    non_edges = np.argwhere(adj == 0)
    # 排除自环
    non_edges = non_edges[non_edges[:, 0] != non_edges[:, 1]]

    if len(non_edges) > 0:
        # 以节点质量乘积作为引力代理 (无边位置无法计算真实引力)
        candidate_mass_product = np.array(
            [masses[i] * masses[j] for i, j in non_edges]
        )
        # 选择质量乘积最高的候选 (引力最强)
        top_indices = np.argsort(candidate_mass_product)[-n_add:]
        for idx in top_indices:
            i, j = non_edges[idx]
            augmented[i, j] = 1.0

    return augmented


# 双视图生成 — 对比学习应用

class BEGAGravityAugmenter:
    """
    BEGA 重力模型增强器 — 为对比学习生成两个语义上有意义的增强视图。

    与现有 GraphAugmenter.augment_pair 的差异:
      - 视图 1: 使用低引力阈值 (删 20% 边) 模拟轻度优化 (-O1)
      - 视图 2: 使用高引力阈值 (删 40% 边) 模拟激进优化 (-O3)
      - 两个视图都经过 BEGA 引力边添加, 增强跨编译器泛化能力

    设计意图:
      GraphMoCo 对比学习需要正样本对 (同函数的两个增强视图), BEGA 的重力
      模型比随机 dropout 提供更真实的编译器模拟, 因为这些增强反映了实际
      编译器优化的语义影响: 死代码消除、函数内联、尾调用优化等。
    """

    def __init__(
        self,
        grav_constant: float = 1.0,
        view1_del_percentile: float = 20.0,
        view2_del_percentile: float = 40.0,
        add_ratio: float = 0.05,
        seed: Optional[int] = None,
    ):
        self._G = grav_constant
        self._del1 = view1_del_percentile
        self._del2 = view2_del_percentile
        self._add = add_ratio
        self._seed = seed

    def augment_pair(
        self, adj: "np.ndarray", node_features: "np.ndarray"
    ) -> tuple:
        """
        生成两个增强视图。

        返回:
          (view1_adj, view2_adj): 两个增强后的邻接矩阵。

        注意:
          节点特征在此模块中不修改 (仅边结构被增强), 特征增强由
          ai_ml/src/augment/augmentor.py 的 feature_mask 处理。
        """
        seed1 = self._seed
        seed2 = self._seed + 1 if self._seed is not None else None

        view1 = bega_edge_augment(
            adj, node_features,
            grav_constant=self._G,
            del_threshold_percentile=self._del1,
            add_ratio=self._add,
            seed=seed1,
        )
        view2 = bega_edge_augment(
            adj, node_features,
            grav_constant=self._G,
            del_threshold_percentile=self._del2,
            add_ratio=self._add,
            seed=seed2,
        )
        return view1, view2


__all__ = [
    "compute_node_mass",
    "compute_gravity_forces",
    "bega_edge_augment",
    "BEGAGravityAugmenter",
]
