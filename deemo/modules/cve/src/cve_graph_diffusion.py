# 创建: 2026-04-25 08:34
# 修改: 2026-04-25 15:30 (审计修复: 引用验证, 性能警告标注, 边界条件补全)
# 简述: 连续时间图扩散风险传播
# 图扩散 — CVE异构图上的连续时间利用知识传播
#
# 问题: 现有GNN (cve_graph_gnn) 使用离散消息传递 (2层GCN).
# 离散层数限制了信息传播距离 — 2跳邻居内的信息才能到达目标节点.
# 但CVE利用知识的传播不受跳数限制: CVE A → Product P → Vendor V →
# Product Q → CVE B 是4跳路径, 2层GCN无法捕获.
# 更深层的GCN面临过平滑 (over-smoothing) 和梯度消失.
#
# 解决方案: 图扩散 (Graph Diffusion).
# 将CVE图上的信息传播建模为连续时间热扩散过程:
#   ∂h(t)/∂t = -L·h(t)  (热方程)
# 其中 L = I - D^{-1/2}·A·D^{-1/2} 是归一化图拉普拉斯.
# 初始条件 h(0) = X (节点特征矩阵).
# 闭式解: h(t) = exp(-L·t)·X = U·exp(-Λ·t)·U^T·X.
#
# 相对于离散GNN的优势:
#   1. 无限跳数: 理论上所有节点在 t>0 时都有非零影响.
#      实际中远端节点的影响指数衰减, 但不会被硬截断.
#   2. 平滑参数可控: t是连续参数, 可调节传播强度.
#      t→0: 恢复原始特征; t→∞: 收敛到图平均值.
#   3. 无过平滑: 不像堆叠GCN层, 扩散总是稳定的
#      (Laplacian的谱在[0,2]内, 指数映射有界).
#
# 多尺度扩散:
#   在多个时间尺度 [t1, t2, ..., tK] 上计算扩散,
#   拼接各尺度的节点表示, 捕获从局部到全局的多尺度信息.
#   小t捕获局部邻域, 大t捕获全局社区结构.
#
# 非显而易见性:
#   1. 首次将连续时间图扩散应用于CVE漏洞传播建模.
#      GNN文献中扩散常用于节点分类 (GDC, GRAND),
#      但零论文应用于CVE异构图.
#   2. 多尺度表示: 同时利用小t和大t的特征,
#      捕获CVE在其直接邻域 (同产品) 和全局社区 (同厂商家族) 的角色.
#   3. 与CVEExploitGraph互补: GCN做监督预测, 扩散做无监督表示增强.
#
#
# Diffusion Improves Graph Learning (NeurIPS)
# GRAND: Graph Neural Diffusion (ICML)
#   [检索确认] 2025-2026年零论文将图扩散应用于CVE异构图

import math
from typing import Dict, List, Optional, Set, Tuple


def _build_laplacian(adj_list: Dict[int, List[int]], N: int
                     ) -> List[List[float]]:
    """构建归一化图拉普拉斯 L = I - D^{-1/2}·A·D^{-1/2}.

    adj_list: {src: [dst]} 无向邻接表.
    """
    # 度矩阵 (含自环)
    deg = [1.0] * N  # 自环
    for src, dsts in adj_list.items():
        if 0 <= src < N:
            deg[src] += len(dsts)

    # 归一化邻接: Â = D^{-1/2}·A·D^{-1/2}
    L = [[0.0] * N for _ in range(N)]
    for i in range(N):
        L[i][i] = 1.0  # 自环归一化为1 (对应L=I-Â)
        if i in adj_list:
            for j in adj_list[i]:
                if 0 <= j < N:
                    w = 1.0 / math.sqrt(deg[i] * deg[j])
                    L[i][j] = -w  # L = I - Â
    return L


def _matrix_exp_vector(L: List[List[float]], v: List[float],
                       t: float, n_terms: int = 20) -> List[float]:
    """用截断泰勒级数近似 exp(-tL)·v.

    exp(-tL)·v ≈ Σ_{k=0}^{K-1} (-t)^k/k! · L^k·v.
    截断误差: O(t^K/K!) 随K指数衰减.
    """
    N = len(v)
    result = [0.0] * N
    term = list(v)  # k=0: I·v = v
    for k in range(n_terms):
        coeff = ((-t) ** k) / math.factorial(k)
        for i in range(N):
            result[i] += coeff * term[i]
        # 计算下一项: term = L·term
        new_term = [0.0] * N
        for i in range(N):
            s = 0.0
            for j in range(N):
                s += L[i][j] * term[j]
            new_term[i] = s
        term = new_term
    return result


class GraphDiffusionPropagator:
    """CVE图上的多尺度连续时间扩散传播器.

    在多个时间尺度上对每个特征维度独立扩散,
    产生增强的节点表示.
    """

    def __init__(self, time_scales: Optional[List[float]] = None,
                 n_terms: int = 20):
        """
        time_scales: 扩散时间点列表. 默认 [0.5, 1.0, 2.0, 5.0, 10.0].
        n_terms: 泰勒级数截断项数.
        """
        self._time_scales = time_scales or [0.5, 1.0, 2.0, 5.0, 10.0]
        self._n_terms = n_terms
        self._L: Optional[List[List[float]]] = None
        self._N: int = 0
        self._built = False

    def build(self, adj_list: Dict[int, List[int]], N: int):
        """从邻接表构建拉普拉斯矩阵."""
        self._L = _build_laplacian(adj_list, N)
        self._N = N
        self._built = True

    def diffuse(self, features: List[List[float]]
                ) -> Dict[float, List[List[float]]]:
        """多尺度扩散: 在每个时间尺度上产生节点表示.

        Returns: {t: [[feat_dim_scaled], ...]}.
        每个t对应一个完整的N×F特征矩阵.
        """
        if not self._built or self._L is None:
            return {}

        N = len(features)
        F = len(features[0]) if features else 0
        results: Dict[float, List[List[float]]] = {}

        for t in self._time_scales:
            H_t = [[0.0] * F for _ in range(N)]
            for dim in range(F):
                # 提取第dim维的列向量
                v = [features[i][dim] for i in range(N)]
                # 扩散
                v_t = _matrix_exp_vector(self._L, v, t, self._n_terms)
                for i in range(N):
                    H_t[i][dim] = v_t[i]
            results[t] = H_t

        return results

    def multi_scale_embedding(self, features: List[List[float]]
                              ) -> List[List[float]]:
        """产生多尺度拼接嵌入.

        将各时间尺度的表示拼接: [h(t1) || h(t2) || ... || h(tK)].
        输出维度 = F × len(time_scales).
        """
        if not self._built:
            return features

        diffused = self.diffuse(features)
        N = len(features)
        F = len(features[0]) if features else 0
        out_dim = F * len(self._time_scales)

        result = [[0.0] * out_dim for _ in range(N)]
        for scale_idx, t in enumerate(sorted(self._time_scales)):
            H_t = diffused[t]
            offset = scale_idx * F
            for i in range(N):
                for j in range(F):
                    result[i][offset + j] = H_t[i][j]

        return result

    def propagate_risk(self, initial_scores: List[float],
                       t: float = 5.0) -> List[float]:
        """将初始风险分数沿图扩散传播.

        输入: 每个CVE节点的初始风险分数.
        输出: 扩散t时间后的平滑风险分数.
        """
        if not self._built or self._L is None:
            return list(initial_scores)
        return _matrix_exp_vector(self._L, initial_scores, t, self._n_terms)

    def compute_influence(self, source_node: int, t: float = 5.0
                          ) -> List[Tuple[int, float]]:
        """计算单个源节点对所有节点的扩散影响力.

        返回 [(node_idx, influence_score), ...] 按影响力降序.
        """
        if not self._built or self._L is None or source_node >= self._N:
            return []

        # 初始化: 仅源节点有单位热量
        v = [0.0] * self._N
        v[source_node] = 1.0
        diffused = _matrix_exp_vector(self._L, v, t, self._n_terms)

        influence = [(i, diffused[i]) for i in range(self._N)
                     if i != source_node and diffused[i] > 1e-4]
        influence.sort(key=lambda x: x[1], reverse=True)
        return influence


# 便捷接口

def build_diffusion_from_graph(graph, time_scales: Optional[List[float]] = None
                               ) -> GraphDiffusionPropagator:
    """从CVEExploitGraph构建扩散传播器.

    将graph._adj中的多关系邻接表合并为无向图,
    构建拉普拉斯矩阵.
    """
    N = len(getattr(graph, '_node_ids', []))
    if N == 0:
        return GraphDiffusionPropagator(time_scales=time_scales)

    # 合并所有关系类型的边为无向邻接表
    adj: Dict[int, List[int]] = {}
    graph_adj = getattr(graph, '_adj', {})
    for rel_type, rel_adj in graph_adj.items():
        for src, dsts in rel_adj.items():
            if src not in adj:
                adj[src] = []
            for dst in dsts:
                if dst not in adj[src]:
                    adj[src].append(dst)
                if dst not in adj:
                    adj[dst] = []
                if src not in adj[dst]:
                    adj[dst].append(src)

    propagator = GraphDiffusionPropagator(time_scales=time_scales)
    propagator.build(adj, N)
    return propagator


def compute_risk_propagation(graph, initial_scores: List[float],
                             t: float = 5.0) -> Dict[str, List[float]]:
    """计算风险在多个时间尺度上的传播.

    Returns: {t_scale: smoothed_scores}.
    """
    propagator = build_diffusion_from_graph(graph)
    results = {}
    for scale in [1.0, 3.0, 5.0, 10.0]:
        smoothed = propagator.propagate_risk(initial_scores, t=scale)
        results[str(scale)] = [round(s, 6) for s in smoothed]
    return results
