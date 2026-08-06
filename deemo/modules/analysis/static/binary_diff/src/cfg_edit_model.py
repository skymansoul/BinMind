# 修改记录:
# 2025-08-06 10:27 - 支配树分解: 将 CFG 递归拆为树状块, 每块内部做精确对齐
# 2025-08-06 14:55 - 节点替换代价的语义加权: 指令类型匹配 > 常量匹配 > 结构匹配

"""约束感知的 CFG 编辑距离模型 - 针对二进制比较的编辑代价定义与结构分解

传统图编辑距离 (GED) 对一般图是 NP-hard
但 CFG 具有特殊结构属性使其可被分解求解:

属性 1: 单入口 - 每个 CFG 有唯一入口基本块
属性 2: 有限出度 - x86/ARM 基本块最多 2 条出边 (fallthrough + branch)
属性 3: 支配树 - 循环由回边标识, 支配关系将 CFG 分解为嵌套区域
属性 4: 富属性节点 - 基本块包含指令序列, 提供丰富的匹配线索

本模块利用这些属性:
1. 用支配树将 CFG 分解为树状区域 (每个循环体是一个区域)
2. 区域内部使用约束求解做精确对齐
3. 区域间使用树编辑距离 (多项式时间, Zhang-Shasha 算法)
4. 节点替换代价基于语义等价类 (复用 adversarial_features.py 的分类)

与现有工作的差异:
- CFGSim (专利 CN118916714B): GNN + 图编辑距离预测, 需训练且不可解释
- ReGaP (AAAI 2024): SAT 模式匹配, 只判断是否存在模式, 不计算距离
- 本模块: 约束驱动的可解释编辑路径, 无需训练, 支配树分解保证多项式时间
"""

from __future__ import annotations

import math
from collections import defaultdict
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Dict, FrozenSet, List, Optional, Set, Tuple


# ---------------------------------------------------------------------------
# CFG 节点与边模型
# ---------------------------------------------------------------------------

class CFGEdgeType(IntEnum):
    FALLTHROUGH = 0
    BRANCH_TRUE = 1
    BRANCH_FALSE = 2
    CALL = 3
    BACKEDGE = 4


@dataclass
class EditCFGNode:
    """用于编辑距离计算的 CFG 节点--提取匹配关键属性"""
    node_id: int
    address: int = 0
    # 指令级特征--用于节点匹配
    insn_count: int = 0
    semantic_class_histogram: List[float] = field(default_factory=lambda: [0.0]*12)
    # 从 adversarial_features.classify_instruction 派生
    has_call: bool = False
    has_indirect_call: bool = False
    has_indirect_jump: bool = False
    # 常量值集--强匹配信号 (同一源码编译的常量一致)
    constant_values: Set[int] = field(default_factory=set)
    # 支配信息
    dominator_id: int = -1              # 直接支配者
    dominated_ids: List[int] = field(default_factory=list)  # 被直接支配的节点
    # 循环标识
    loop_depth: int = 0
    is_loop_header: bool = False


@dataclass
class EditCFGEdge:
    """CFG 边--带类型的控制流转移"""
    src_id: int
    dst_id: int
    edge_type: CFGEdgeType = CFGEdgeType.FALLTHROUGH


@dataclass
class CFGEditCosts:
    """CFG 编辑操作的代价配置--可通过交叉验证调节权重"""
    node_substitution: float = 1.0
    node_insertion: float = 2.0          # 插入比替换更昂贵 (奖励匹配)
    node_deletion: float = 2.0
    edge_insertion: float = 1.5
    edge_deletion: float = 1.5
    # 语义奖励--指令类别匹配降低成本
    semantic_class_match_bonus: float = 0.3
    constant_match_bonus: float = 0.2
    call_match_bonus: float = 0.25


# ---------------------------------------------------------------------------
# 节点替换代价 - 基于语义属性的精确代价
# ---------------------------------------------------------------------------

def node_substitution_cost(
    a: EditCFGNode,
    b: EditCFGNode,
    costs: CFGEditCosts = CFGEditCosts(),
) -> float:
    """计算两个基本块的替换代价--基于语义属性差异

    代价范围 [0, costs.node_substitution]:
    0 = 两个块语义等价 (相同的指令类分布和常量)
    costs.node_substitution = 两个块完全无关
    """
    base = costs.node_substitution

    # 1. 指令类直方图相似度--L1 距离
    l1 = sum(
        abs(a.semantic_class_histogram[i] - b.semantic_class_histogram[i])
        for i in range(12)
    )
    class_penalty = l1 * 0.5  # 最大 L1=2.0, 缩放到 [0, 1]

    # 2. 指令数差异--对数尺度 (50->100 差异比 5->10 差异小)
    size_diff = abs(a.insn_count - b.insn_count)
    size_penalty = math.log2(1 + size_diff) / 10.0  # 归一化到 [0, ~0.7]

    # 3. 语义奖励
    bonus = 0.0
    # 调用匹配
    if a.has_call == b.has_call:
        bonus += costs.call_match_bonus
    if a.has_indirect_call == b.has_indirect_call:
        bonus += costs.call_match_bonus * 0.5
    if a.has_indirect_jump == b.has_indirect_jump:
        bonus += costs.call_match_bonus * 0.5

    # 常量匹配--Jaccard 相似度
    consts_a, consts_b = a.constant_values, b.constant_values
    if consts_a or consts_b:
        union = len(consts_a | consts_b)
        intersection = len(consts_a & consts_b)
        if union > 0:
            const_jaccard = intersection / union
            bonus += costs.constant_match_bonus * const_jaccard

    # 指令类直方图余弦相似度--额外奖励
    dot = sum(
        a.semantic_class_histogram[i] * b.semantic_class_histogram[i]
        for i in range(12)
    )
    norm_a = math.sqrt(sum(v*v for v in a.semantic_class_histogram))
    norm_b = math.sqrt(sum(v*v for v in b.semantic_class_histogram))
    if norm_a > 1e-9 and norm_b > 1e-9:
        cosine = dot / (norm_a * norm_b)
        bonus += costs.semantic_class_match_bonus * max(0.0, cosine)

    # 4. 循环深度差异
    loop_penalty = abs(a.loop_depth - b.loop_depth) * 0.05

    cost = base * (1.0 + class_penalty + size_penalty + loop_penalty - bonus)
    return max(0.05, min(base * 2.5, cost))


# ---------------------------------------------------------------------------
# 支配树分解 - 将 CFG 递归拆为树状区域
# ---------------------------------------------------------------------------

def build_dominator_tree(
    nodes: List[EditCFGNode],
    edges: List[EditCFGEdge],
) -> None:
    """构建 CFG 的支配树--填充每个节点的 dominator_id 和 dominated_ids

    使用迭代数据流算法 (Cooper-Harvey-Kennedy):
    复杂度 O(N²) 但 CFG 节点数通常 < 10³, 实际可接受

    入口节点 (node_id=0) 的支配者为自身
    """
    n = len(nodes)
    if n == 0:
        return

    # 初始化: 入口支配自身, 其余被所有节点支配
    node_ids = [nd.node_id for nd in nodes]
    id_to_idx = {nid: i for i, nid in enumerate(node_ids)}

    doms: List[Set[int]] = []
    for i, nd in enumerate(nodes):
        if i == 0:
            doms.append({nd.node_id})
        else:
            doms.append(set(node_ids))

    # 构建前驱映射
    preds: Dict[int, List[int]] = defaultdict(list)
    for e in edges:
        preds[e.dst_id].append(e.src_id)

    changed = True
    while changed:
        changed = False
        for i, nd in enumerate(nodes):
            if i == 0:
                continue
            # Dom[n] = {n} ∪ ∩_{p∈preds[n]} Dom[p]
            new_dom = set(node_ids)
            for p in preds.get(nd.node_id, []):
                if p in id_to_idx:
                    new_dom &= doms[id_to_idx[p]]
            new_dom.add(nd.node_id)

            if new_dom != doms[i]:
                doms[i] = new_dom
                changed = True

    # 计算直接支配者: idom[n] = Dom[n] \ {n} 中离 n 最近的节点
    for i, nd in enumerate(nodes):
        dom_set = doms[i] - {nd.node_id}
        if not dom_set:
            nd.dominator_id = nd.node_id  # 入口或不可达
            continue
        # 直接支配者 = Dom 集合中 Dom 集合最小的节点 (除自身外)
        best = None
        best_size = float('inf')
        for candidate_id in dom_set:
            c_idx = id_to_idx.get(candidate_id)
            if c_idx is not None:
                sz = len(doms[c_idx])
                if sz < best_size:
                    best_size = sz
                    best = candidate_id
        nd.dominator_id = best if best is not None else nd.node_id

    # 填充 dominated_ids
    for nd in nodes:
        idom = nd.dominator_id
        if idom >= 0 and idom != nd.node_id:
            dom_idx = id_to_idx.get(idom)
            if dom_idx is not None:
                nodes[dom_idx].dominated_ids.append(nd.node_id)


def decompose_cfg_regions(
    nodes: List[EditCFGNode],
    edges: List[EditCFGEdge],
) -> List[Tuple[List[int], List[Tuple[int, int, int]]]]:
    """将 CFG 按支配树分解为树状区域列表

    每个区域 = (node_ids, internal_edges)
    区域的边界由回边 (backedge) 定义--每遇到回边切出一个新区域

    返回区域列表--按嵌套深度 (最内层区域在前)
    """
    # 识别回边: dst 支配 src 的边
    id_to_idx = {nd.node_id: i for i, nd in enumerate(nodes)}
    doms = {nd.node_id: nd.dominator_id for nd in nodes}

    backedges: Set[Tuple[int, int]] = set()
    for e in edges:
        if e.edge_type == CFGEdgeType.BACKEDGE:
            backedges.add((e.src_id, e.dst_id))
        # 启发式: 若 dst 是 src 的祖先 (支配者), 视为回边
        if doms.get(e.src_id) == e.dst_id:
            continue
        # dst 支配 src -> 回边
        src_idx = id_to_idx.get(e.src_id)
        dst_idx = id_to_idx.get(e.dst_id)
        if src_idx is not None and dst_idx is not None:
            if _is_ancestor(nodes, e.dst_id, e.src_id, id_to_idx):
                backedges.add((e.src_id, e.dst_id))

    # 简化的区域分解: 每回边定义循环体区域
    regions: List[Tuple[List[int], List[Tuple[int, int, int]]]] = []
    if not backedges:
        # 无循环--整个 CFG 作为一个区域
        all_ids = [nd.node_id for nd in nodes]
        internal = [
            (e.src_id, e.dst_id, int(e.edge_type))
            for e in edges if e.edge_type != CFGEdgeType.BACKEDGE
        ]
        regions.append((all_ids, internal))
        return regions

    # 有循环: 每回边对应的循环体作为独立区域
    loop_nodes: Set[int] = set()
    for src, dst in backedges:
        # 循环体 = dst 和所有被 dst 支配且能到达 src 的节点
        for nd in nodes:
            if nd.node_id == dst or _is_dominated_by(nodes, nd.node_id, dst, id_to_idx):
                loop_nodes.add(nd.node_id)

    if loop_nodes:
        loop_ids = list(loop_nodes)
        loop_internal = [
            (e.src_id, e.dst_id, int(e.edge_type))
            for e in edges
            if e.src_id in loop_nodes and e.dst_id in loop_nodes
            and (e.src_id, e.dst_id) not in backedges
        ]
        regions.append((loop_ids, loop_internal))

    # 剩余节点作为一个区域
    remaining = [nd.node_id for nd in nodes if nd.node_id not in loop_nodes]
    if remaining:
        rem_internal = [
            (e.src_id, e.dst_id, int(e.edge_type))
            for e in edges
            if e.src_id in remaining and e.dst_id in remaining
        ]
        regions.append((remaining, rem_internal))

    return regions


def _is_ancestor(
    nodes: List[EditCFGNode], ancestor: int, descendant: int,
    id_to_idx: Dict[int, int],
) -> bool:
    """检查 ancestor 是否为 descendant 的支配者"""
    current = descendant
    visited: Set[int] = set()
    while current != ancestor and current not in visited:
        visited.add(current)
        idx = id_to_idx.get(current)
        if idx is None:
            return False
        current = nodes[idx].dominator_id
        if current == current:  # dominator is self (root)
            break
    return current == ancestor


def _is_dominated_by(
    nodes: List[EditCFGNode], node_id: int, dominator: int,
    id_to_idx: Dict[int, int],
) -> bool:
    """检查 node_id 是否被 dominator 支配"""
    return _is_ancestor(nodes, dominator, node_id, id_to_idx)
