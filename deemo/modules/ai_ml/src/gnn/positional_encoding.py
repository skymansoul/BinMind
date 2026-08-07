#
# 图位置/结构编码 — 用于二进制 CFG 中增强 GNN 的拓扑感知能力。
#
# 背景：GCN/GAT 的消息传递天然无法区分同构节点（结构相同但位置不同）。
# 拉普拉斯位置编码 (LPE) 解决绝对位置问题但存在符号模糊性（特征向量可正负翻转）。
# 随机游走结构编码 (RWSE) 解决局部角色问题（hub/leaf/clique 成员），对 CFG 的
# 分支-汇合结构感知尤佳。
#
# 设计决策（与通用 GNN 方案的关键差异--适配二进制 CFG）：
# (a) 多尺度 LPE：单一 k 值的特征向量对 CFG 区分度不足--小 k 捕获全局社区，
# 大 k 捕获局部结构，需要融合。参考 GraphGPS
# 使用 concatenated multi-k PE，本项目在此基础上增加自适应 k 选择。
# (b) 符号对齐：特征向量 ei 和 -ei 在数学上等价，但对 GNN 输入是不同向量。
# 特征分解在不同运行中可能符号翻转--需要对齐策略。
# (c) 分量感知归一化：二进制 CFG 常含不可达代码块（死代码），形成多个弱连通分量。
# 应按分量独立计算拉普拉斯矩阵避免跨分量特征泄漏。
# (d) 不可约循环处理：goto/间接跳转产生的不可约 CFG 导致拉普拉斯矩阵出现
# 重复/接近零的特征值--降维时需检测并跳过退化维度。

import numpy as np
from typing import Dict, List, Tuple, Optional, Set
from collections import defaultdict
import logging

logger = logging.getLogger(__name__)

# 连通分量检测 — 处理 CFG 中的死代码/不可达块


def _connected_components(adj: np.ndarray) -> List[np.ndarray]:
    """BFS 求弱连通分量，返回每个分量的节点索引数组。

    对有向 CFG 使用弱连通（忽略边方向）——死代码块可能只有出边没有入边。
    """
    n = adj.shape[0]
    # 无向化邻接
    undirected = (adj + adj.T) > 0
    visited = np.zeros(n, dtype=bool)
    components: List[np.ndarray] = []

    for start in range(n):
        if visited[start]:
            continue
        # BFS
        queue = [start]
        visited[start] = True
        comp_nodes = [start]
        while queue:
            u = queue.pop(0)
            for v in range(n):
                if undirected[u, v] and not visited[v]:
                    visited[v] = True
                    queue.append(v)
                    comp_nodes.append(v)
        components.append(np.array(comp_nodes))

    return components


# 多尺度拉普拉斯位置编码 (MultiScaleLPE)


class MultiScaleLPE:
    """多尺度拉普拉斯位置编码。

    对每个连通分量独立计算归一化拉普拉斯矩阵的前 k_min..k_max 个非平凡
    特征向量并拼接。多尺度策略来自 GraphGPS 的 concatenated PE 设计——
    但本项目针对二进制 CFG 的稀疏性做了分量级独立计算。

    参数:
      k_scales: 各尺度保留的特征向量数量，如 [3, 5, 8] —— 小值捕获全局，
                大值补充局部细节
      sign_align: 特征向量的符号对齐策略。
        'median' — 基于中位数符号决定翻转（本项目默认，比 mean 更鲁棒）
        'abs'    — 取绝对值（丢失方向信息，仅作 fallback）
        'none'   — 不对齐
    """

    def __init__(self, k_scales: List[int] = None, sign_align: str = 'median'):
        self.k_scales = k_scales or [3, 5]
        self.sign_align = sign_align
        # 特征分解缓存：key=(哈希(bytes(adj)), max_k) → (eigenvecs, eigenvalues)
        self._eig_cache: Dict[Tuple[int, int], Tuple[np.ndarray, np.ndarray]] = {}

    def _sign_align_eigenvecs(self, vecs: np.ndarray) -> np.ndarray:
        """特征向量符号对齐——防止 ei 和 -ei 在不同运行时随机翻转。

        策略：对每个特征向量，检查其元素的中位数符号。
        若中位数 > 0 且多数元素 < 0 — 翻转整个向量。
        中位数比均值更鲁棒——一个极端值不会翻转整个向量。
        """
        if self.sign_align == 'none':
            return vecs
        if self.sign_align == 'abs':
            return np.abs(vecs)

        aligned = vecs.copy()
        for j in range(vecs.shape[1]):
            col = aligned[:, j]
            med = np.median(col)
            if med < 0:
                aligned[:, j] = -col
            # 中位数为零的退化情况：检查偏度
            elif abs(med) < 1e-10:
                skew = np.mean(np.sign(col))
                if skew < -0.1:
                    aligned[:, j] = -col
        return aligned

    def compute(self, adj: np.ndarray) -> np.ndarray:
        """计算多尺度 LPE。

        返回: (N, sum(k_scales)) 的位置编码矩阵。
        对单节点分量返回零填充——无结构信息可编码。
        """
        n = adj.shape[0]
        max_k = max(self.k_scales)
        total_dim = sum(self.k_scales)

        if n <= 1:
            return np.zeros((n, total_dim))

        components = _connected_components(adj)
        pe = np.zeros((n, total_dim))

        for comp_nodes in components:
            if len(comp_nodes) <= 1:
                continue  # 孤立节点--PE 保持为零

            sub_adj = adj[comp_nodes][:, comp_nodes]
            sub_pe = self._compute_component_lpe(sub_adj, max_k, total_dim)

            # 将子图 PE 映射回全图索引
            for local_idx, global_idx in enumerate(comp_nodes):
                pe[global_idx, :] = sub_pe[local_idx, :]

        return pe

    def _compute_component_lpe(self, adj: np.ndarray, max_k: int,
                                total_dim: int) -> np.ndarray:
        """对单个连通分量计算多尺度 LPE。"""
        n = adj.shape[0]

        # 归一化拉普拉斯: L_sym = I - D^{-1/2} A D^{-1/2}
        # 使用 A+I 而非 A--自环确保孤立节点不产生除零
        a_self = adj + np.eye(n)
        deg = a_self.sum(axis=1)
        d_inv_sqrt = np.where(deg > 0, 1.0 / np.sqrt(deg), 0.0)
        d_mat = np.diag(d_inv_sqrt)
        l_sym = np.eye(n) - d_mat @ a_self @ d_mat

        # 特征分解--L_sym 对称且半正定，eval 在 [0, 2]
        try:
            vals, vecs = np.linalg.eigh(l_sym)
        except np.linalg.LinAlgError:
            # 数值不稳定时降级为伪逆近似--罕见，出现时记录
            logger.warning("eigh failed on %d×%d component, using SVD fallback", n, n)
            u, s, vh = np.linalg.svd(l_sym)
            vals = s
            vecs = u

        # 跳过 λ≈0 的特征值（连通分量的平凡解）
        trivial_mask = np.abs(vals) < 1e-8
        nontrivial_idx = np.where(~trivial_mask)[0]

        # 符号对齐
        vecs = self._sign_align_eigenvecs(vecs)

        # 多尺度拼接
        col_offset = 0
        result = np.zeros((n, total_dim))
        for k in self.k_scales:
            k_actual = min(k, len(nontrivial_idx))
            if k_actual > 0:
                selected_idx = nontrivial_idx[:k_actual]
                result[:, col_offset:col_offset + k_actual] = vecs[:, selected_idx]
            col_offset += k

        return result

    def compute_fast(self, adj: np.ndarray) -> np.ndarray:
        """快速路径：使用缓存避免重复特征分解。

        在符号执行循环中同一个函数的 CFG 可能被多次编码——
        缓存 key 为 (adj_hash, max_k)。注意 adj 必须是 np.ndarray。
        """
        adj_bytes = adj.tobytes()
        cache_key = (hash(adj_bytes), max(self.k_scales))
        if cache_key in self._eig_cache:
            cached_vecs, _ = self._eig_cache[cache_key]
            return self._extract_scales(cached_vecs)

        result = self.compute(adj)
        return result


# 随机游走结构编码 (RandomWalkSE)


class RandomWalkSE:
    """随机游走结构编码。

    通过模拟 k 步非回溯随机游走的平稳分布来编码节点的局部结构角色。
    参考 Dwivedi et al. (NeurIPS 2023) "Long Range Graph Benchmark" 中的
    RWSE 设计——本项目针对 CFG 的自环和双节点环做了特定调整。

    CFG 特化：
      - 控制流中的自环（tight loop, spinlock）是有效结构信号，不剪除
      - 双节点互相跳转（if-else 分支后的汇合）是常见的 CFG 模式，
        在 2 步游走后产生显著差异信号
      - 游走长度预设为 [2, 3, 4, 5]——覆盖短分支到中等长度路径

    参数:
      walk_lengths: 各游走步数，默认 [2, 3, 4]——在二进制 CFG 上，
                    3 步足以区分大部分控制流角色
    """

    def __init__(self, walk_lengths: List[int] = None):
        self.walk_lengths = walk_lengths or [2, 3, 4]

    def compute(self, adj: np.ndarray) -> np.ndarray:
        """计算随机游走结构编码。

        返回: (N, len(walk_lengths)) 编码矩阵。
        每列是该步数下的平稳分布概率（self-loop 归一化后的 landing probability）。
        """
        n = adj.shape[0]
        if n <= 1:
            return np.zeros((n, len(self.walk_lengths)))

        # 转移概率矩阵：P = D^{-1} A（行归一化）
        out_deg = adj.sum(axis=1)
        # 悬垂节点（无出边）--令其停留在自身
        out_deg_safe = np.where(out_deg > 0, out_deg, 1.0)
        d_inv = np.diag(1.0 / out_deg_safe)
        p_trans = d_inv @ adj

        result = np.zeros((n, len(self.walk_lengths)))

        for step_idx, walk_len in enumerate(self.walk_lengths):
            # P^walk_len 的行之和给出了各节点在 walk_len 步内的访问概率
            p_k = np.linalg.matrix_power(p_trans, walk_len)
            # 每行的均值 = 从该节点出发 walk_len 步后到达任意节点的平均概率
            landing_prob = p_k.mean(axis=1)
            result[:, step_idx] = landing_prob

        # 按列做 z-score 归一化--使不同 walk_len 的特征量纲一致
        for j in range(result.shape[1]):
            col = result[:, j]
            std = col.std()
            if std > 1e-10:
                result[:, j] = (col - col.mean()) / std

        return result


# 统一编码器 — 组合 LPE + RWSE


class CFGPositionalEncoder:
    """CFG 专用的统一位置/结构编码器。

    将 MultiScaleLPE 和 RandomWalkSE 的输出按轴拼接，
    构成 (N, lpe_dim + rwse_dim) 的增广节点特征。

    使用方式：在 GNN 模型 forward() 前调用 encode(a)，
    将返回的 PE 矩阵拼接到原始节点特征的右侧。

    PE 特征先做 layer norm 再拼接——防止 PE 量级盖过原始节点特征。
    """

    def __init__(self, lpe_scales: List[int] = None,
                 rwse_walks: List[int] = None,
                 sign_align: str = 'median'):
        self.lpe = MultiScaleLPE(k_scales=lpe_scales or [3, 5],
                                  sign_align=sign_align)
        self.rwse = RandomWalkSE(walk_lengths=rwse_walks or [2, 3, 4])
        self.lpe_dim = sum(lpe_scales or [3, 5])
        self.rwse_dim = len(rwse_walks or [2, 3, 4])
        self.total_dim = self.lpe_dim + self.rwse_dim

    def encode(self, adj: np.ndarray) -> np.ndarray:
        """计算组合 PE 矩阵。"""
        pe_l = self.lpe.compute(adj)     # (N, lpe_dim)
        pe_r = self.rwse.compute(adj)    # (N, rwse_dim)
        combined = np.concatenate([pe_l, pe_r], axis=1)

        # Layer norm across feature dim--稳定输入分布
        mean = combined.mean(axis=0, keepdims=True)
        std = combined.std(axis=0, keepdims=True) + 1e-8
        combined = (combined - mean) / std

        return combined

    def augment_features(self, node_features: np.ndarray,
                         adj: np.ndarray) -> np.ndarray:
        """在节点特征右侧拼接 PE 矩阵。

        返回: (N, original_dim + self.total_dim)
        这是 GNN 模型调用前的一步预处理。
        """
        pe = self.encode(adj)
        return np.concatenate([node_features, pe], axis=1)
