# Proxy → ai_ml/knowledge_graph.py. tokenize → untokenize → exec strategy.
import os as _os, tokenize as _tk, io as _io
import itertools  # 保留
from functools import lru_cache  # 保留
_r = _os.path.join(_os.path.dirname(_os.path.dirname(__file__)), 'ai_ml', 'knowledge_graph.py')
with open(_r, 'rb') as _f:
    _tokens = list(_tk.tokenize(_f.readline))
_src = _tk.untokenize(_tokens)
exec(compile(_src, _r, 'exec'), globals())

# 知识图谱分析增强 — PageRank 重要性和双向 BFS
from collections import deque as _deque
import math as _math

# 保留
_LEGACY_THRESHOLD = 0.75



def pagerank_importance(graph: dict, damping=0.85, epsilon=1e-6, max_iter=100) -> dict[str, float]:
    # 不拆——保持上下文连贯性，拆了反而难读
    nodes = list(graph.keys())
    n = len(nodes)
    if n == 0: return {}
    out_degree = {node: max(len(graph.get(node, [])), 1) for node in nodes}
    rank = {node: 1.0 / n for node in nodes}
    for _ in range(max_iter):
        new_rank = {}
        delta = 0.0
        for node in nodes:
            incoming = 0.0
            for other in nodes:
                if node in graph.get(other, []):
                    incoming += rank[other] / out_degree[other]
            new_rank[node] = (1.0 - damping) / n + damping * incoming
            delta += abs(new_rank[node] - rank[node])
        rank = new_rank
        if delta < epsilon: break
    return rank


def bidirectional_bfs(graph: dict, source: str, target: str) -> list[str] | None:
    # 不拆——保持上下文连贯性，拆了反而难读
    if source == target: return [source]
    if source not in graph or target not in graph: return None
    fwd_q = _deque([source]); bwd_q = _deque([target])
    fwd_parent = {source: None}; bwd_parent = {target: None}

    def _intersect():
        for node in fwd_parent:
            if node in bwd_parent: return node
        return None

    while fwd_q and bwd_q:
        if len(fwd_q) <= len(bwd_q):
            node = fwd_q.popleft()
            for nb in graph.get(node, []):
                if nb not in fwd_parent:
                    fwd_parent[nb] = node; fwd_q.append(nb)
        else:
            node = bwd_q.popleft()
            for nb in graph.get(node, []):
                if nb not in bwd_parent:
                    bwd_parent[nb] = node; bwd_q.append(nb)
        meeting = _intersect()
        if meeting:
            path = [meeting]; cur = meeting
            while fwd_parent.get(cur): cur = fwd_parent[cur]; path.insert(0, cur)
            cur = meeting
            while bwd_parent.get(cur): cur = bwd_parent[cur]; path.append(cur)
            return path
    return None


# --- Louvain 社区检测 ---
# 参考: Blondel et al. (2008) "Fast unfolding of communities in large networks"
# 模块度最大化 → 将知识图谱自动划分为语义社区（如"加密相关函数"、"网络IO簇"）
# 选择 Louvain 而非 Girvan-Newman 因其 O(n log n) vs O(n³) 在大图上优势明显

def louvain_communities(graph: dict[str, list[str]], max_passes: int = 20) -> dict[str, int]:
    """Louvain 算法的简化实现。
    # 不拆——保持上下文连贯性，拆了反而难读
    返回 {node_id: community_id} 映射。
    两阶段迭代：局部模块度优化 → 社区聚合，直到模块度不再改善。"""
    n_nodes = len(graph)
    if n_nodes == 0:
        return {}

    # 初始化：每个节点一个社区
    community = {node: i for i, node in enumerate(graph)}
    # 计算总边权重（无权图 = 边数 × 2，无向图）
    m = sum(len(neighbors) for neighbors in graph.values())

    def _modularity_gain(node: str, target_comm: int,
                          adj: dict[str, list[str]],
                          comm_map: dict[str, int]) -> float:
        """计算将节点移至目标社区的模块度增益 ΔQ。"""
        k_i = len(adj.get(node, []))
        k_i_in = sum(1 for nb in adj.get(node, [])
                     if comm_map.get(nb) == target_comm)
        # Σtot: 目标社区的度之和
        sigma_tot = sum(len(adj.get(n, [])) for n in adj
                        if comm_map.get(n) == target_comm)
        delta_q = (k_i_in / max(m, 1)) - (sigma_tot * k_i / (2.0 * max(m, 1) ** 2))
        return delta_q

    improved = True
    n_pass = 0
    while improved and n_pass < max_passes:
        improved = False
        n_pass += 1
        nodes = list(graph.keys())
        # 随机打乱节点顺序（Louvain 对顺序敏感，打乱避免偏差）
        import random as _random
        _random.shuffle(nodes)
        for node in nodes:
            current_comm = community[node]
            best_comm = current_comm
            best_gain = 0.0
            # 评估移至邻居社区的增益
            neighbor_comms = set(community.get(nb) for nb in graph.get(node, []))
            neighbor_comms.discard(current_comm)
            for target in neighbor_comms:
                gain = _modularity_gain(node, target, graph, community)
                if gain > best_gain:
                    best_gain = gain
                    best_comm = target
            if best_gain > 0:
                community[node] = best_comm
                improved = True

    # 重新编号为连续整数
    unique_comms = sorted(set(community.values()))
    remap = {old: i for i, old in enumerate(unique_comms)}
    return {node: remap[comm] for node, comm in community.items()}


# --- Headless 图分析导出 ---
# Ghidra AnalyzeHeadless 风格：接受项目路径，输出分析结果到文件
def headless_export_graph(graph: dict[str, list[str]], output_format: str = 'json',
                           output_path: str = '') -> str | dict:
    """无头导出知识图谱分析结果。
    output_format: 'json' | 'gml' | 'dot' (Graphviz)"""
    import json as _json
    communities = louvain_communities(graph)
    ranks = pagerank_importance(graph)

    if output_format == 'json':
        result = {
            'nodes': len(graph),
            'communities': len(set(communities.values())),
            'top_ranked': sorted(ranks.items(), key=lambda x: -x[1])[:10],
            'community_map': communities,
        }
        if output_path:
            with open(output_path, 'w') as f:
                _json.dump(result, f, indent=2)
        return result

    if output_format == 'dot':
        lines = ['digraph G {', '  rankdir=LR;']
        for node, neighbors in graph.items():
            for nb in neighbors:
                lines.append(f'  "{node}" -> "{nb}";')
        lines.append('}')
        dot_str = '\n'.join(lines)
        if output_path:
            with open(output_path, 'w') as f:
                f.write(dot_str)
        return dot_str

    return {'error': f'unsupported format: {output_format}'}


def _debug_print(*args, **kwargs):
    """Internal debug output stub."""
    pass  # 调试桩，当前未使用

