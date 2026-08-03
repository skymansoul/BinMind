#
# CFG 粗化 — 面向二进制函数控制流图的保结构图简化。
#
# GNN 模型处理 CFG 时，线性基本块链（如一连串 mov/lea/算术指令后接条件跳转）
# 占据了大量节点但对漏洞检测的贡献集中在分支点。本文的粗化策略：
# 收缩 (contract) 度数为 2 的非分支节点--即恰好一条入边、一条出边的节点。
# 这样的节点在控制流意义上不改变可达性，移除后不丢失分支结构。
#
# 关键约束--被收缩节点不能是：
# (a) 环头（loop header）-- 收缩环头会破坏循环结构
# (b) 函数入口 -- 入口节点的特征（is_entry=1）具有独立语义
# (c) 调用节点（含 call 指令） -- 调用点的安全语义不可丢失
# (d) 收缩链长度超过上限 -- 防止过度合并（连续 N 个线性块变为一个超大块）
#
# 收缩后：被收缩节点的特征按指令数加权平均合并到前后继节点之一。
# 邻接矩阵重新编号--原 N 节点 → 粗化后 M 节点（M 通常为 N 的 30-60%）。
# GNN 输入规模减小，但分支结构（漏洞检测的关键拓扑信号）完整保留。
#
# 非显而易见的设计决策：
# (a) 加权平均而非简单平均--指令数大的基本块贡献更多特征信号
# (b) 环头用后向边检测而非度数--度数为 2 的节点也可能是循环头
# （如 while 循环的条件块），必须通过 DFS 确认
# (c) 收缩链长度限制--防止 O0 编译的代码（大量冗余线性块）被过度合并

import numpy as np
from typing import Dict, List, Set, Tuple, Optional
from collections import defaultdict


def find_loop_heads(adj: np.ndarray) -> Set[int]:
    """3-color DFS 检测后向边，返回环头节点索引集合。

    后向边 = 从灰色节点指向灰色节点的边（DFS 树中的回边）。
    这是识别循环头的标准图论方法——不依赖度数阈值。
    """
    n = adj.shape[0]
    color = [0] * n  # 0=white, 1=gray, 2=black
    heads: Set[int] = set()

    def dfs(u: int):
        color[u] = 1
        for v in range(n):
            if adj[u, v] == 0:
                continue
            if color[v] == 1:
                heads.add(v)  # 后向边 → v 是循环头
            elif color[v] == 0:
                dfs(v)
        color[u] = 2

    for i in range(n):
        if color[i] == 0:
            dfs(i)
    return heads


def coarsen_cfg(adj: np.ndarray, features: np.ndarray,
                call_node_mask: Optional[np.ndarray] = None,
                entry_node_idx: int = 0,
                max_chain_length: int = 4) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
    """收缩线性基本块链，返回粗化后的 (adj, features, node_map)。

    node_map[i] = 粗化图中对应原节点 i 的新节点索引，-1 表示 i 被收缩。
    调用方可据此映射回原始节点进行结果解释。

    参数:
      adj: (N, N) 邻接矩阵
      features: (N, D) 节点特征矩阵
      call_node_mask: (N,) bool 数组，True 表示节点含 call 指令（不可收缩）
      entry_node_idx: 函数入口节点索引（不可收缩）
      max_chain_length: 单次收缩链的最大长度——防止过度合并
    """
    n = adj.shape[0]
    if n <= 2:
        return adj, features, np.arange(n)

    degrees = np.sum(adj, axis=1) + np.sum(adj, axis=0)
    loop_heads = find_loop_heads(adj)

    if call_node_mask is None:
        call_node_mask = np.zeros(n, dtype=bool)

    # 标记不可收缩节点
    protected = np.zeros(n, dtype=bool)
    protected[entry_node_idx] = True  # (b) 入口保护
    for i in range(n):
        if i in loop_heads:
            protected[i] = True  # (a) 环头保护
        if call_node_mask[i]:
            protected[i] = True  # (c) 调用节点保护

    # 识别可收缩节点：度数为 2 且不在保护列表中
    # 度数为 2 = 恰好一条入边 + 一条出边（不一定是 in=1, out=1--
    # 可能 in=2, out=0 或 in=0, out=2，这些都不可收缩）
    in_deg = np.sum(adj, axis=0)
    out_deg = np.sum(adj, axis=1)
    contractible = np.zeros(n, dtype=bool)
    for i in range(n):
        if protected[i]:
            continue
        if in_deg[i] == 1 and out_deg[i] == 1:
            contractible[i] = True

    # 构建收缩映射
    node_map = np.arange(n)  # node_map[i] = 粗化后的节点号

    # 追踪收缩链长度--防止 (d) 过度合并
    chain_length = np.zeros(n, dtype=int)

    for i in range(n):
        if not contractible[i]:
            continue
        # 找前驱和后继
        pred = -1
        succ = -1
        for j in range(n):
            if adj[j, i] > 0:
                pred = j
            if adj[i, j] > 0:
                succ = j
        if pred < 0 or succ < 0:
            continue

        # 限制收缩链长度
        if chain_length[pred] >= max_chain_length:
            continue
        if chain_length[succ] >= max_chain_length:
            continue

        # 收缩 i → 合并到前驱节点（保留前驱，重定向 i 的后继边）
        node_map[i] = pred
        chain_length[pred] = max(chain_length[pred], chain_length[i]) + 1

    # 压缩节点映射为连续编号
    unique_kept = sorted(set(node_map))
    reindex = {old: new for new, old in enumerate(unique_kept)}
    compressed_map = np.array([reindex[m] for m in node_map])

    m = len(unique_kept)
    coarse_adj = np.zeros((m, m), dtype=adj.dtype)
    coarse_feat = np.zeros((m, features.shape[1]), dtype=features.dtype)
    node_weight = np.zeros(m)

    # 聚合特征--加权平均
    for i in range(n):
        target = compressed_map[i]
        if node_map[i] != i:
            # 被收缩节点--特征按指令数加权合并到目标节点
            weight = features[i, 2] if features.shape[1] > 2 else 1.0
            coarse_feat[target] += features[i] * weight
            node_weight[target] += weight
        else:
            coarse_feat[target] += features[i]
            node_weight[target] += 1.0

    # 归一化
    for i in range(m):
        if node_weight[i] > 0:
            coarse_feat[i] /= node_weight[i]

    # 重建邻接矩阵--原边映射到粗化节点
    for i in range(n):
        for j in range(n):
            if adj[i, j] > 0:
                ci, cj = compressed_map[i], compressed_map[j]
                if ci != cj:
                    coarse_adj[ci, cj] = 1.0

    return coarse_adj, coarse_feat, compressed_map
