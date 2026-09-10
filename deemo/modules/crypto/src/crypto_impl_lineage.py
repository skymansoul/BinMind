"""
密码学实现谱系推断 — 通过层次聚类和距离度量推断多个实现的演化关系。

设计意图:
  crypto_diversity统计"有多少个不同的AES实现", 但回答不了更深层的问题:
    (a) 变体B是从变体A演化来的, 还是独立开发的?
    (b) 三个AES实现中, 哪两个更相似? 它们共享了最近的共同祖先吗?
    (c) 检测到的变体是否形成了一个从"安全→脆弱"的渐进退化链?

  本模块使用层次聚类推断实现之间的谱系关系:
    H1 (距离矩阵): 成对汉明距离 → 不相似度矩阵 D_ij
    H2 (UPGMA树): 非加权配对算术平均法 → 层次聚类树形图
    H3 (Silhouette评分): 聚类质量评估 → 确定最佳聚类数k
    H4 (谱系根推断): 基于"最接近标准参考实现" → 推断最可能的原始实现

  与crypto_lineage的区别: lineage追踪代码复用(同架构), 本模块做跨实现的
  演化关系推断(可跨架构, 使用crypto_semantic_hash的距离)。

  - Sokal & Michener: UPGMA聚类方法。
  - Rousseeuw: Silhouette系数 — 聚类质量度量。
  - Jain & Dubes: 聚类分析算法综述。

边界条件:
  - 层次聚类在样本量>100时O(n²)内存压力显著 — 预筛选指纹到top-50。
  - UPGMA假设分子钟(恒定的演化速率) — 对密码学实现, 此假设不一定成立。
  - 谱系推断是统计推断 — "最像祖先"未必是真正的祖先。
"""

import math
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

@dataclass
class LineageNode:
    """谱系树中的节点 — 可以是单个实现或一个聚类。"""
    node_id: int = 0
    label: str = ""                # 算法名或聚类标签
    children: List['LineageNode'] = field(default_factory=list)
    height: float = 0.0            # 合并高度(=组间距离/2)
    member_count: int = 1          # 该节点下的实现数量

@dataclass
class LineageTree:
    algorithm: str = ""
    root: Optional[LineageNode] = None
    silhouette_scores: List[Tuple[int, float]] = field(default_factory=list)
    best_k: int = 1                # 最佳聚类数
    inferred_root_impl: str = ""   # 推断的根实现(最像标准参考的)

# UPGMA层次聚类

def _upgma_cluster(dist_matrix: List[List[float]],
                    labels: List[str]) -> LineageNode:
    """
    UPGMA(非加权配对算术平均法)层次聚类。

    算法:
      1. 每个样本初始化为独立叶子节点
      2. 找距离最小的两个节点→合并为新节点(高度=距离/2)
      3. 新节点到其他节点的距离=两子节点距离的算术平均
      4. 重复直到只剩一个根节点
    """
    n = len(dist_matrix)
    if n == 0:
        return LineageNode(node_id=0, label='empty')
    if n == 1:
        return LineageNode(node_id=0, label=labels[0])

    # 初始化: 每个样本为一个节点
    nodes = [LineageNode(node_id=i, label=labels[i]) for i in range(n)]
    # 距离矩阵副本(可变)
    d = [row[:] for row in dist_matrix]
    next_id = n

    while len(nodes) > 1:
        m = len(nodes)
        # 找最小距离对(忽略对角)
        min_val = float('inf')
        min_i, min_j = -1, -1
        for i in range(m):
            for j in range(i + 1, m):
                if d[i][j] < min_val:
                    min_val = d[i][j]
                    min_i, min_j = i, j

        if min_i == -1:
            break  # 无法继续

        # 合并两个节点
        new_node = LineageNode(
            node_id=next_id,
            label=f'cluster_{next_id}',
            children=[nodes[min_i], nodes[min_j]],
            height=min_val / 2.0,
            member_count=nodes[min_i].member_count + nodes[min_j].member_count)
        next_id += 1

        # 更新距离矩阵(UPGMA: 算术平均)
        new_distances = []
        for k in range(m):
            if k != min_i and k != min_j:
                avg = (d[min_i][k] * nodes[min_i].member_count +
                       d[min_j][k] * nodes[min_j].member_count) / \
                      (nodes[min_i].member_count + nodes[min_j].member_count)
                new_distances.append(avg)

        # 重建距离矩阵
        new_nodes = [new_node]
        for k in range(m):
            if k != min_i and k != min_j:
                new_nodes.append(nodes[k])

        new_m = len(new_nodes)
        new_d = [[0.0] * new_m for _ in range(new_m)]
        for i2 in range(1, new_m):
            new_d[0][i2] = new_distances[i2 - 1]
            new_d[i2][0] = new_distances[i2 - 1]
        for i2 in range(1, new_m):
            for j2 in range(i2 + 1, new_m):
                # 找原距离矩阵中对应的值
                old_i = [idx for idx, nd in enumerate(nodes) if nd is new_nodes[i2]][0]
                old_j = [idx for idx, nd in enumerate(nodes) if nd is new_nodes[j2]][0]
                new_d[i2][j2] = d[old_i][old_j]
                new_d[j2][i2] = d[old_i][old_j]

        nodes = new_nodes
        d = new_d

    return nodes[0] if nodes else LineageNode(node_id=0, label='empty')

# Silhouette评分

def _silhouette_score(dist_matrix: List[List[float]],
                       cluster_assignments: List[int]) -> float:
    """
    计算Silhouette系数评估聚类质量。
    每个样本: s = (b - a) / max(a, b)
      a = 样本到同簇其他样本的平均距离
      b = 样本到最近的其他簇的平均距离
    返回所有样本的平均Silhouette值。
    """
    n = len(dist_matrix)
    if n <= 1 or len(set(cluster_assignments)) <= 1:
        return 0.0

    scores = []
    for i in range(n):
        ci = cluster_assignments[i]
        # a: 到同簇其他样本的平均距离
        same_cluster = [j for j in range(n) if cluster_assignments[j] == ci and j != i]
        a = sum(dist_matrix[i][j] for j in same_cluster) / len(same_cluster) if same_cluster else 0.0

        # b: 到最近其他簇的平均距离
        other_clusters = set(cluster_assignments) - {ci}
        min_b = float('inf')
        for oc in other_clusters:
            other_members = [j for j in range(n) if cluster_assignments[j] == oc]
            b_val = sum(dist_matrix[i][j] for j in other_members) / len(other_members)
            min_b = min(min_b, b_val)
        b = min_b if min_b != float('inf') else a

        denom = max(a, b)
        scores.append((b - a) / denom if denom > 0 else 0.0)

    return sum(scores) / len(scores)

def _compute_cluster_assignments(root: LineageNode, n: int,
                                  k: int) -> List[int]:
    """
    从UPGMA树中提取k个聚类的成员分配。
    按高度切割树 → k个聚类。
    """
    # 找到切割高度: 第(n-k)个内部节点的高度
    heights = []
    def _collect_heights(node):
        if node.children:
            heights.append(node.height)
            for c in node.children:
                _collect_heights(c)
    _collect_heights(root)
    heights.sort()

    if k <= 1 or k >= n:
        return [0] * n

    cut_h = heights[n - k - 1] if n - k - 1 < len(heights) else heights[-1]

    # 按切割高度分配聚类
    assignments = [-1] * n
    def _assign(node, cluster_id):
        if not node.children or node.height <= cut_h:
            # 叶子或切割点以下 → 分配cluster_id
            _mark_leaves(node, cluster_id)
            return cluster_id + 1
        else:
            for c in node.children:
                cluster_id = _assign(c, cluster_id)
            return cluster_id

    def _mark_leaves(node, cid):
        if not node.children:
            # 找对应标签的索引
            for i in range(n):
                if i == node.node_id:  # 简化: 用node_id=原始索引
                    assignments[i] = cid
                    break
        else:
            for c in node.children:
                _mark_leaves(c, cid)

    next_cid = 0
    _assign(root, next_cid)
    # 将未分配的标记为0
    for i in range(n):
        if assignments[i] == -1:
            assignments[i] = 0
    return assignments

# 主推断函数

def infer_lineage(fingerprints: List,
                  labels: Optional[List[str]] = None,
                  algorithm: str = "unknown"
                  ) -> LineageTree:
    """
    从语义指纹集合推断实现谱系。

    fingerprints: crypto_semantic_hash.SemanticFingerprint列表。
    labels: 各指纹的显示标签(默认使用algorithm+offset)。
    """
    n = len(fingerprints)
    if n < 2:
        return LineageTree(algorithm=algorithm)

    if labels is None:
        labels = [f'{getattr(fp, "algorithm", "?")}@{getattr(fp, "anchor_offset", 0):#x}'
                  for fp in fingerprints]

    # 构建距离矩阵(汉明距离归一化到[0,1])
    dist_matrix = [[0.0] * n for _ in range(n)]
    for i in range(n):
        for j in range(i + 1, n):
            try:
                hd = fingerprints[i].hamming_distance(fingerprints[j])
                dist_matrix[i][j] = hd / 128.0  # 128-bit哈希
                dist_matrix[j][i] = hd / 128.0
            except Exception:
                dist_matrix[i][j] = 1.0
                dist_matrix[j][i] = 1.0

    # UPGMA聚类
    root = _upgma_cluster(dist_matrix, labels)

    # Silhouette评估(对k=2,3,...,min(n-1,10)计算)
    sil_scores: List[Tuple[int, float]] = []
    best_k, best_sil = 1, -1.0
    for k in range(2, min(n, 10)):
        try:
            assignments = _compute_cluster_assignments(root, n, k)
            sil = _silhouette_score(dist_matrix, assignments)
            sil_scores.append((k, round(sil, 4)))
            if sil > best_sil:
                best_sil = sil
                best_k = k
        except Exception:
            pass

    # 谱系根推断: 找全局平均距离最小的指纹(最接近"中心")
    avg_dists = [sum(row) / (n - 1) if n > 1 else 0.0 for row in dist_matrix]
    root_idx = avg_dists.index(min(avg_dists)) if avg_dists else 0
    inferred_root = labels[root_idx] if root_idx < len(labels) else ''

    return LineageTree(
        algorithm=algorithm, root=root,
        silhouette_scores=sil_scores, best_k=best_k,
        inferred_root_impl=inferred_root)

def export_lineage_json(tree: LineageTree) -> str:
    """将谱系树导出为JSON(用于可视化)。"""
    import json

    def _node_to_dict(node: LineageNode) -> dict:
        d = {'label': node.label, 'height': round(node.height, 4),
             'members': node.member_count}
        if node.children:
            d['children'] = [_node_to_dict(c) for c in node.children]
        return d

    root_dict = _node_to_dict(tree.root) if tree.root else {}
    return json.dumps({
        'algorithm': tree.algorithm,
        'best_k': tree.best_k,
        'inferred_root': tree.inferred_root_impl,
        'tree': root_dict,
        'silhouette_scores': [{'k': k, 'score': s} for k, s in tree.silhouette_scores],
    }, indent=2, ensure_ascii=False)
