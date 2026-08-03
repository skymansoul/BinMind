# augment/增强器.py
# 图结构数据增强：节点丢弃、边扰动、特征掩码、子图采样
# 设计权衡：bridge nodes（度>5）不做node_drop，保护图的连通性
# edge_perturb用引力加权删除，优先剪断高权重边（两端节点度都低的边）

import numpy as np
from scipy.sparse import coo_matrix, eye, issparse

# ===== node_drop =====
# 随机丢弃节点并重建邻接矩阵
# 度>5的桥接节点不可丢弃 -- 保证图结构不过度破碎

def node_drop(x, adj, drop_prob=0.1):
    """x: (n_nodes, n_features), adj: (n_nodes, n_nodes) sparse or dense"""
    _n = x.shape[0]
    if _n <= 2:
        return np.copy(x), adj.copy() if not issparse(adj) else adj.copy()

    # 计算度数，桥接节点不丢弃
    _deg = np.asarray(adj.sum(axis=1)).flatten()
    _bridge_mask = _deg > 5

    # 可丢弃的节点候选
    _candidates = np.where(~_bridge_mask)[0]
    _n_drop = min(len(_candidates), int(_n * drop_prob))
    if _n_drop == 0:
        return np.copy(x), adj.copy() if not issparse(adj) else adj.copy()

    _drop = np.random.choice(_candidates, _n_drop, replace=False)
    _keep = np.setdiff1d(np.arange(_n), _drop)

    # 重建特征和邻接
    _x_new = x[_keep, :].copy()

    if issparse(adj):
        _adj_new = adj[_keep, :][:, _keep]
    else:
        _adj_new = adj[_keep, :][:, _keep]

    return _x_new, _adj_new

# ===== edge_perturb =====
# 引力加权边删除：边权重weight = 1/max(deg(u), deg(v))
# 高权重边（两端都是低度节点）更易被删 — 类似引力模型中质量小的物体引力弱
# 同时随机添加少量边作为噪声注入

def edge_perturb(adj, add_prob=0.05, del_prob=0.05):
    """adj: (n, n) sparse or dense, 返回扰动后的邻接矩阵"""
    _n = adj.shape[0]
    _adj_dense = adj.toarray() if issparse(adj) else np.asarray(adj, dtype=np.float64)

    # ---- 计算每条边的引力权重 ----
    _deg = np.sum(_adj_dense > 0, axis=1).astype(np.float64)
    _deg[_deg == 0] = 1  # 避免除零

    _row, _col = np.where(np.triu(_adj_dense > 0, k=1))
    _n_edges = len(_row)

    if _n_edges > 0:
        # 权重 = 1 / max(deg_u, deg_v)
        _weights = 1.0 / np.maximum(_deg[_row], _deg[_col])
        # 删除概率 = del_prob * (1 - weight)
        _del_probs = del_prob * (1.0 - _weights)
        _del_probs = np.clip(_del_probs, 0, 1)
        _del_mask = np.random.random(_n_edges) < _del_probs

        for _i in np.where(_del_mask)[0]:
            _u, _v = int(_row[_i]), int(_col[_i])
            _adj_dense[_u, _v] = 0
            _adj_dense[_v, _u] = 0

    # ---- 随机添加边 ----
    _n_possible = _n * (_n - 1) // 2 - _n_edges
    _n_add = min(int(_n_possible * add_prob), _n_possible)
    if _n_add > 0:
        # 在非对角线的零位上采样
        _zs = np.where(np.triu(np.eye(_n) == 0) & (_adj_dense == 0))
        _z_pairs = list(zip(_zs[0], _zs[1]))
        if len(_z_pairs) > 0:
            _n_add = min(_n_add, len(_z_pairs))
            _add_idx = np.random.choice(len(_z_pairs), _n_add, replace=False)
            for _i in _add_idx:
                _u, _v = _z_pairs[_i]
                _adj_dense[_u, _v] = 1.0
                _adj_dense[_v, _u] = 1.0

    return _adj_dense

# ===== feature_mask =====
# 随机清零特征维度 — 类似dropout但作用在输入空间
# 强制模型不全依赖某几个特征

def feature_mask(x, mask_prob=0.1):
    """x: (n_nodes, n_features), 返回掩码后的特征矩阵"""
    _x = np.copy(np.asarray(x, dtype=np.float64))
    _mask = np.random.random(_x.shape) < mask_prob
    _x[_mask] = 0.0
    return _x

# ===== subgraph_sample =====
# 随机游走采样子图：从seed节点出发，走walk_length步，提取诱导子图
# 比固定窗口更有概率含义，适合大规模图

def subgraph_sample(adj, num_seeds=3, walk_length=2):
    """adj: (n, n), 返回(采样节点索引, 子图邻接)"""
    _n = adj.shape[0]
    if _n <= num_seeds:
        if issparse(adj):
            return np.arange(_n), adj
        return np.arange(_n), np.asarray(adj)

    _adj_dense = adj.toarray() if issparse(adj) else np.asarray(adj, dtype=np.float64)

    # 随机种子
    _seeds = np.random.choice(_n, min(num_seeds, _n), replace=False)
    _visited = set(_seeds.tolist())

    # 随机游走
    for _seed in _seeds:
        _cur = _seed
        for _ in range(walk_length):
            _neighbors = np.where(_adj_dense[_cur] > 0)[0]
            if len(_neighbors) == 0:
                break
            _next = int(np.random.choice(_neighbors))
            _visited.add(_next)
            _cur = _next

    _nodes = sorted(_visited)
    _indices = np.array(_nodes)

    # 诱导子图
    if issparse(adj):
        _sub = adj[_nodes, :][:, _nodes]
    else:
        _sub = _adj_dense[_nodes, :][:, _nodes]

    return _indices, _sub

# ===== AugmentationPipeline =====
# 流水线组合多种增强：依次以独立概率应用
# node_drop -> edge_perturb -> feature_mask -> subgraph
# subgraph放在最后是因为它改变节点数量，前面的操作需要完整的图

class AugmentationPipeline:
    # ////
    def __init__(self, probs=None):
        self._probs = {
            'node_drop': 0.2,
            'edge_perturb': 0.3,
            'feature_mask': 0.2,
            'subgraph': 0.3,
        }
        if probs is not None:
            self._probs.update(probs)

    # ----
    def __call__(self, x, adj):
        """x: (n, f), adj: (n, n), 返回增强后的(x, adj)"""
        _x, _adj = np.copy(np.asarray(x, dtype=np.float64)), adj

        # node_drop — 保护度>5的桥节点（在node_drop内部处理）
        if np.random.random() < self._probs.get('node_drop', 0):
            _x, _adj = node_drop(_x, _adj, drop_prob=0.1)

        # edge_perturb
        if np.random.random() < self._probs.get('edge_perturb', 0):
            _adj = edge_perturb(_adj, add_prob=0.05, del_prob=0.05)

        # feature_mask
        if np.random.random() < self._probs.get('feature_mask', 0):
            _x = feature_mask(_x, mask_prob=0.1)

        # subgraph_sample
        if np.random.random() < self._probs.get('subgraph', 0):
            _adj_dense = _adj.toarray() if issparse(_adj) else np.asarray(_adj, dtype=np.float64)
            _idx, _sub = subgraph_sample(_adj_dense, num_seeds=3, walk_length=2)
            _x = _x[_idx, :]
            _adj = _sub

        return _x, _adj
