# created: 2026-07-25
# 神经子图同构——结合GNN嵌入剪枝和子图匹配的函数克隆检测
#
# 核心问题: 现有的二进制相似性搜索用GNN嵌入做近似匹配——速度快但精度有限。
# 子图同构做精确匹配——精度高但NP难，对大型二进制不可行。
# 两者各自的缺陷互补: GNN快但不精确，子图同构精确但慢。
#
# 技术方案:
#   1. GNN粗筛: 用GNN嵌入做快速top-K候选筛选（毫秒级）
#   2. 神经剪枝: GNN的边注意力权重指导子图同构的搜索顺序——
#      高注意力边优先匹配，低注意力边可被跳过
#   3. 约束子图同构: 仅对GNN筛选后的top-K候选+剪枝后的CFG做精确匹配
#   4. 语义等价松弛: 寄存器重命名/指令重排视为匹配——
#      节点匹配条件从"完全相同"松弛为"语义等价"
#
# 新颖性: 首次将GNN注意力剪枝引入子图同构搜索以加速二进制克隆检测

from __future__ import annotations

import math
import logging
from typing import Dict, List, Optional, Set, Tuple, Any, Callable
from collections import defaultdict, deque
from dataclasses import dataclass, field

import numpy as np

_ARIA_S1 = "0x3f"
logger = logging.getLogger(__name__)


@dataclass
class CFGNode:
    """CFG节点——含GNN嵌入和注意力信息"""
    node_id: int
    opcode_dist: np.ndarray        # 操作码类别分布
    successors: List[int]
    gnn_embedding: np.ndarray
    attention_score: float = 1.0    # GNN对该节点的注意力权重


@dataclass
class CloneMatch:
    """克隆检测匹配结果"""
    query_func_id: str
    target_func_id: str
    similarity: float              # 0-1 综合相似度
    gnn_score: float               # GNN粗筛分数
    isomorphism_score: float       # 子图同构匹配分数
    matched_nodes: int             # 匹配的节点数
    total_nodes_query: int
    total_nodes_target: int
    is_clone: bool


class NeuralPruningMatcher:
    """神经剪枝子图匹配器。

    剪枝策略:
      1. GNN注意力分数排序: 高注意力节点优先匹配——
         这些是GNN认为对语义最重要的节点
      2. 低注意力边跳过: 注意力<阈值的边在子图同构搜索中被忽略——
         显著缩小搜索空间
      3. 语义等价松弛: 节点匹配条件为操作码类别分布cosine>0.8——
         允许寄存器重命名和等价指令替换
    """

    def __init__(self, attention_threshold: float = 0.15,
                 semantic_threshold: float = 0.8,
                 max_backtracks: int = 5000):
        self._attn_thresh = attention_threshold
        self._sem_thresh = semantic_threshold
        self._max_backtracks = max_backtracks

    def prune_cfg(self, nodes: List[CFGNode]) -> List[CFGNode]:
        """基于GNN注意力剪枝CFG——移除低注意力节点和边。

        保留的节点: attention_score >= threshold
        保留的边: 源和目标的attention都 >= threshold
        """
        pruned = []
        for node in nodes:
            if node.attention_score >= self._attn_thresh:
                pruned_succ = [s for s in node.successors
                              if s < len(nodes) and
                              nodes[s].attention_score >= self._attn_thresh]
                pruned.append(CFGNode(
                    node_id=node.node_id,
                    opcode_dist=node.opcode_dist,
                    successors=pruned_succ,
                    gnn_embedding=node.gnn_embedding,
                    attention_score=node.attention_score))
            else:
                pruned.append(CFGNode(
                    node_id=node.node_id,
                    opcode_dist=node.opcode_dist,
                    successors=[],  # 移除所有后继
                    gnn_embedding=node.gnn_embedding,
                    attention_score=node.attention_score))
        return pruned

    def semantic_node_match(self, a: CFGNode, b: CFGNode) -> float:
        """语义等价节点匹配——操作码分布相似度。

        Returns:
            0-1的匹配分数，>=sem_thresh视为匹配
        """
        return self._cosine_sim(a.opcode_dist, b.opcode_dist)

    def subgraph_isomorphism(self,
                              query_nodes: List[CFGNode],
                              target_nodes: List[CFGNode]
                              ) -> Tuple[float, int]:
        """约束子图同构——GNN剪枝+语义松弛+回溯搜索。

        先贪心建立初始映射，然后对低质量匹配做有限回溯——
        尝试替换为次优候选，检查是否改善整体边一致性。
        这是贪心(快但粗糙)和完整VF2(精确但指数)之间的折衷。
        """
        n_q, n_t = len(query_nodes), len(target_nodes)
        if n_q == 0 or n_t == 0:
            return 0.0, 0

        q_important = [i for i in range(n_q)
                      if query_nodes[i].attention_score >= self._attn_thresh]
        t_important = [i for i in range(n_t)
                      if target_nodes[i].attention_score >= self._attn_thresh]
        if not q_important:
            q_important = list(range(min(n_q, 10)))

        # 阶段1: 贪心建立初始映射
        mapping = {}
        used = set()
        candidates: Dict[int, List[Tuple[int, float]]] = {}
        for qi in q_important:
            scored = []
            for ti in t_important:
                if ti in used:
                    continue
                sem_s = self.semantic_node_match(query_nodes[qi], target_nodes[ti])
                struct_s = 1.0 - abs(len(query_nodes[qi].successors) -
                    len(target_nodes[ti].successors)) / max(1,
                    max(len(query_nodes[qi].successors), len(target_nodes[ti].successors)))
                combined = 0.7 * sem_s + 0.3 * struct_s
                if combined >= self._sem_thresh * 0.7:
                    scored.append((ti, combined))
            scored.sort(key=lambda x: -x[1])
            candidates[qi] = scored
            if scored:
                mapping[qi] = scored[0][0]
                used.add(scored[0][0])

        # 阶段2: 有限回溯——尝试替换边一致性差的匹配
        backtracks = 0
        improved = True
        while improved and backtracks < self._max_backtracks // 2:
            improved = False
            base_edge_cons = self._edge_consistency(query_nodes, target_nodes, mapping)
            for qi in q_important:
                if qi not in mapping or qi not in candidates:
                    continue
                orig_ti = mapping[qi]
                for alt_ti, _ in candidates[qi][1:4]:  # 尝试top-4替代
                    if alt_ti in used and alt_ti != orig_ti:
                        continue
                    old_used = set(used)
                    if alt_ti != orig_ti:
                        used.discard(orig_ti)
                        used.add(alt_ti)
                    mapping[qi] = alt_ti
                    new_cons = self._edge_consistency(query_nodes, target_nodes, mapping)
                    backtracks += 1
                    if new_cons > base_edge_cons + 0.05:
                        improved = True
                        break
                    else:
                        mapping[qi] = orig_ti
                        used = old_used
                if improved or backtracks >= self._max_backtracks // 2:
                    break

        n_matched = len(mapping)
        node_ratio = n_matched / max(1, len(q_important))
        edge_consistency = self._edge_consistency(query_nodes, target_nodes, mapping)
        avg_match_quality = float(np.mean([
            self.semantic_node_match(query_nodes[qi], target_nodes[ti])
            for qi, ti in mapping.items()])) if mapping else 0.0

        score = node_ratio * 0.3 + edge_consistency * 0.4 + avg_match_quality * 0.3
        return score, n_matched

    def _edge_consistency(self, query_nodes, target_nodes,
                          mapping: Dict[int, int]) -> float:
        """检查匹配节点间的边一致性——A→B在query中存在
        当且仅当mapping(A)→mapping(B)在target中存在"""
        if len(mapping) < 2:
            return 1.0
        consistent, total = 0, 0
        for qi, ti in mapping.items():
            for qj, tj in mapping.items():
                if qi == qj:
                    continue
                total += 1
                q_edge = qj in query_nodes[qi].successors
                t_edge = tj in target_nodes[ti].successors
                if q_edge == t_edge:
                    consistent += 1
        return consistent / max(1, total)

    @staticmethod
    def _cosine_sim(a, b):
        na = float(np.linalg.norm(a))
        nb = float(np.linalg.norm(b))
        if na < 1e-8 or nb < 1e-8:
            return 0.0
        return float(np.dot(a, b)) / (na * nb)


class NeuralCloneDetector:
    """神经克隆检测器——GNN粗筛+神经剪枝子图匹配。

    两阶段流水线:
      Phase 1: GNN嵌入→余弦top-K候选（快，召回率高）
      Phase 2: 神经剪枝子图同构→精确匹配分数（慢，精度高）
    """

    def __init__(self, gnn_encoder: Callable,
                 matcher: Optional[NeuralPruningMatcher] = None):
        self._encoder = gnn_encoder
        self._matcher = matcher or NeuralPruningMatcher()

    def detect_clones(self,
                       query_func: Tuple[str, Any, Any, List[CFGNode]],
                       target_pool: List[Tuple[str, Any, Any, List[CFGNode]]],
                       top_k: int = 20) -> List[CloneMatch]:
        """两阶段克隆检测。

        Args:
            query_func: (func_id, features, adjacency, cfg_nodes)
            target_pool: [(func_id, features, adjacency, cfg_nodes), ...]
        """
        qid, q_feat, q_adj, q_nodes = query_func
        q_emb = self._encoder(q_feat, q_adj)

        # Phase 1: GNN粗筛
        candidates = []
        for tid, t_feat, t_adj, t_nodes in target_pool:
            t_emb = self._encoder(t_feat, t_adj)
            sim = float(np.dot(q_emb.flatten(), t_emb.flatten())) / max(
                1e-8, float(np.linalg.norm(q_emb)) * float(np.linalg.norm(t_emb)))
            if sim > 0.5:
                candidates.append((tid, t_feat, t_adj, t_nodes, sim))
        candidates.sort(key=lambda x: -x[4])
        candidates = candidates[:top_k]

        # Phase 2: 神经剪枝子图匹配
        matches = []
        q_pruned = self._matcher.prune_cfg(q_nodes)
        for tid, t_feat, t_adj, t_nodes, gnn_sim in candidates:
            t_pruned = self._matcher.prune_cfg(t_nodes)
            iso_score, n_matched = self._matcher.subgraph_isomorphism(
                q_pruned, t_pruned)
            combined = 0.4 * gnn_sim + 0.6 * iso_score
            matches.append(CloneMatch(
                query_func_id=qid, target_func_id=tid,
                similarity=combined, gnn_score=gnn_sim,
                isomorphism_score=iso_score,
                matched_nodes=n_matched,
                total_nodes_query=len(q_nodes),
                total_nodes_target=len(t_nodes),
                is_clone=(combined > 0.75)))

        matches.sort(key=lambda m: -m.similarity)
        return matches
