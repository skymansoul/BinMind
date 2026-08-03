# compat/ 重导出 — 知识图谱分析桩
# 最小侵入代理策略，零全局副作用。
# Call Graphlets (arXiv:2406.02606) GNN + 深度度量学习
# Binary2vec (2025) 跨架构嵌入 + contrastive learning
import os as _os
import importlib.util as _iu

_r = _os.path.join(_os.path.dirname(_os.path.dirname(__file__)), 'core', 'compat', 'knowledge_graph.py')
_spec = _iu.spec_from_file_location('knowledge_graph', _r)
_mod = _iu.module_from_spec(_spec)
_spec.loader.exec_module(_mod)

for _sym in dir(_mod):
    if not _sym.startswith('_'):
        globals()[_sym] = getattr(_mod, _sym)

# 图增强：Call Graphlet 特征提取
# Graphlets 将函数调用图局部邻域编码为子图统计，
# 作为 GNN 相似性检索的输入签名（arXiv:2406.02606）。
from collections import Counter as _Ctr
from itertools import combinations as _combos

def count_3_node_graphlets(adj_list: dict[str, set[str]]) -> dict[str, int]:
    """函数调用图中3节点graphlet类型统计。
    3节点有向图共16种同构类（Milo et al., 2002）；
    简化区分: triangle, in_star, out_star, two_path, disconnected。
    O(|V|^3)，上限≤1000节点。"""
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
    """归一化graphlet计数为特征向量。
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
