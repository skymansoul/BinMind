# re-export from compat/ — 知识图谱桩
# importlib 代理策略，保持最小侵入
# 参考: Call Graphlets (arXiv:2406.02606) GNN + 深度度量学习 &
#        Binary2vec (2025) 跨架构嵌入 + contrastive learning
import os as _os
import importlib.util as _iu

_r = _os.path.join(_os.path.dirname(_os.path.dirname(__file__)), 'core', 'compat', 'knowledge_graph.py')
_spec = _iu.spec_from_file_location('knowledge_graph', _r)
_mod = _iu.module_from_spec(_spec)
_spec.loader.exec_module(_mod)

for _sym in dir(_mod):
    if not _sym.startswith('_'):
        globals()[_sym] = getattr(_mod, _sym)

# --- 图谱增强: call graphlet 特征提取 ---
# Call Graphlets 论文 (2406.02606) 的核心思想：
# 将函数调用图的局部邻域结构编码为图元 (graphlet) 统计特征，
# 送入 GNN 进行函数级别的相似性检索。此处提供 graphlet 计数工具。
from collections import Counter as _Ctr
from itertools import combinations as _combos

def count_3_node_graphlets(adj_list: dict[str, set[str]]) -> dict[str, int]:
    """在函数调用图中统计所有 3 节点 graphlet 类型。
    3 节点有向图共有 16 种同构类型 (Milo et al., 2002)；
    此简化实现仅区分: triangle, in_star, out_star, two_path, disconnected。
    复杂度 O(|V|^3)，仅适用于 ≤1000 节点的图。"""
    nodes = list(adj_list.keys())
    if len(nodes) > 1000:
        return {'warning_too_large': len(nodes)}

    counts = _Ctr()
    for a, b, c in _combos(nodes, 3):
        edges = []
        for u, v in [(a, b), (b, a), (a, c), (c, a), (b, c), (c, b)]:
            if v in adj_list.get(u, set()):
                edges.append((u, v))
        edge_count = len(edges)
        if edge_count == 0:
            counts['disconnected'] += 1
        elif edge_count <= 2:
            counts['two_path'] += 1
        elif edge_count <= 4:
            counts['in_out_star'] += 1
        else:
            counts['triangle'] += 1
    return dict(counts)

def normalize_graphlet_vector(raw_counts: dict[str, int]) -> list[float]:
    """归一化 graphlet 计数为特征向量。
    返回 [triangle_ratio, in_out_star_ratio, two_path_ratio, disconnected_ratio]"""
    total = sum(raw_counts.values())
    if total == 0:
        return [0.0] * 4
    return [
        raw_counts.get('triangle', 0) / total,
        raw_counts.get('in_out_star', 0) / total,
        raw_counts.get('two_path', 0) / total,
        raw_counts.get('disconnected', 0) / total,
    ]
