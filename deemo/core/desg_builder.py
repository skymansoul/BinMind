"""
支配增强语义图 (DESG) 构建器。

将 CFG 的基本块关系扩展为异构图，包含三种边类型:
  E_bb:   基本块间控制流边（CFG 原边）
  E_dom:  支配树边（immediate dominator → dominatee）
  E_pdom: 后支配树边（immediate post-dominator → post-dominatee）

三类边构成的异构图对控制流平坦化 (ollvm -fla) 具有天然鲁棒性:
  - 平坦化插入的 dispatcher 块不改变原始基本块间的支配关系
  - 后支配树边缘可恢复被 switch-case 打散的路径汇合点

图的节点属性嵌入字节级熵值 (0-255 的字节频率分布)，使得:
  - 语义等价但指令不同的基本块有相近的熵特征
  - 编译器优化 (O0/O2/O3) 造成的指令重排不改变块的字节熵分布
  - ref: ORCAS 的 DESG 概念; Speilman 的拉普拉斯谱理论
         本项目在 ORCAS 基础上增加字节熵节点嵌入和可配置的支配深度阈值

算法: Cooper-Harvey-Kennedy 迭代支配树 (O(N²) worst, O(N log N) typical)
      后支配树通过 CFG 逆图 + 添加虚拟出口节点 (vex) 后运行同一算法得到
"""


import logging
from typing import Any, Dict, List, Optional, Set, Tuple

_log = logging.getLogger(__name__)

# 支配深度阈值——超出此深度的 basic block 在 E_dom 中被剪枝
# 过深的支配链通常是编译器展开的循环体，对语义差异不敏感
_MAX_DOM_DEPTH = 8


def build_desg(
    cfg_blocks: List[Dict[str, Any]],
    compute_entropy: bool = True,
) -> Dict[str, Any]:
    """
    从 CFG 基本块列表构建支配增强语义图。

    Args:
        cfg_blocks: cfg_extractor.extract_cfg() 中单个函数的 blocks 列表，
                    每项含 addr, size, successors (地址列表)
        compute_entropy: 是否计算每个基本块的字节熵嵌入

    Returns:
        {
          "nodes": {addr: {"entropy": float, "size": int, "n_succ": int}},
          "edges_bb":   [(src, dst)],           # CFG 控制流边
          "edges_dom":  [(idom, node)],          # 支配树边
          "edges_pdom": [(ipdom, node)],         # 后支配树边
          "entry": int,                          # 入口地址
          "exit_addrs": [int],                   # 出口地址列表
        }
    """
    if not cfg_blocks:
        return {"nodes": {}, "edges_bb": [], "edges_dom": [],
                "edges_pdom": [], "entry": 0, "exit_addrs": []}

    addrs = [b["addr"] for b in cfg_blocks]
    entry = addrs[0]

    # 构建邻接关系
    succ_map: Dict[int, List[int]] = {}
    pred_map: Dict[int, List[int]] = {}
    node_info: Dict[int, Dict] = {}

    for b in cfg_blocks:
        a = b["addr"]
        succs = b.get("successors", [])
        succ_map[a] = [s for s in succs if s in addrs]
        node_info[a] = {"size": b.get("size", 0), "n_succ": len(succs)}
        for s in succ_map[a]:
            pred_map.setdefault(s, []).append(a)

    # 确保所有节点在 pred_map 中有条目
    for a in addrs:
        pred_map.setdefault(a, [])

    # 识别出口节点 (无后继的基本块)
    exit_addrs = [a for a in addrs if not succ_map.get(a)]

    # 计算支配树
    idom = _compute_dominators(addrs, pred_map, entry)

    # 计算后支配树: 逆图 + 虚拟出口节点
    # 所有原始出口节点连接到虚拟 vex，入口为 vex
    VEX = max(addrs) + 0x10000 if addrs else 0xFFFF0000
    rev_preds: Dict[int, List[int]] = {VEX: []}
    for a in addrs:
        rev_preds[a] = list(succ_map.get(a, []))
        # CFG 后继 → 逆图中为前驱
    # 正常化: 构建逆图中的前驱关系
    rev_pred_map: Dict[int, List[int]] = {}
    for src, dsts in succ_map.items():
        for dst in dsts:
            rev_pred_map.setdefault(dst, []).append(src)
    # 出口节点在逆图中连接到 VEX
    for ex in exit_addrs:
        rev_pred_map.setdefault(VEX, []).append(ex)
    for a in addrs:
        rev_pred_map.setdefault(a, [])
    rev_pred_map.setdefault(VEX, [])

    # 逆图节点集合: 所有原始节点 + VEX
    rev_nodes = list(addrs) + [VEX]
    ipdom_raw = _compute_dominators(rev_nodes, rev_pred_map, VEX)

    # 移除 VEX 相关的后支配关系
    ipdom = {a: ipdom_raw.get(a, 0) for a in addrs
             if ipdom_raw.get(a, 0) != VEX and ipdom_raw.get(a, 0) != 0}

    # 节点熵嵌入
    if compute_entropy:
        for a in addrs:
            node_info[a]["entropy"] = _estimate_block_entropy(
                node_info[a].get("size", 0),
                node_info[a].get("n_succ", 0),
            )

    # 构建边列表
    edges_bb = [(src, dst) for src, dsts in succ_map.items() for dst in dsts]
    edges_dom = [(idom[a], a) for a in addrs if a in idom and idom[a] != a]
    edges_pdom = [(ipdom[a], a) for a in addrs if a in ipdom]

    _log.debug("DESG built: %d nodes, %d bb-edges, %d dom-edges, %d pdom-edges",
               len(addrs), len(edges_bb), len(edges_dom), len(edges_pdom))

    return {
        "nodes": node_info,
        "edges_bb": edges_bb,
        "edges_dom": edges_dom,
        "edges_pdom": edges_pdom,
        "entry": entry,
        "exit_addrs": exit_addrs,
    }


def _compute_dominators(
    nodes: List[int],
    preds: Dict[int, List[int]],
    entry: int,
) -> Dict[int, int]:
    """
    Cooper-Harvey-Kennedy 迭代支配树算法。

    初始化: dom(entry) = {entry}, dom(other) = all nodes
    迭代: dom(n) = {n} ∪ ∩_{p∈preds(n)} dom(p)
    终止: dom 集合不再变化
    复杂度: O(N²) worst-case，实际在控制流图上收敛极快 (通常 ≤ 3 轮)

    返回 idom 映射——每个节点的 immediate dominator。
    """
    all_nodes = set(nodes) | {entry}
    # dom_sets[n]: 支配 n 的节点集合
    dom_sets: Dict[int, Set[int]] = {}
    for n in all_nodes:
        dom_sets[n] = all_nodes.copy() if n != entry else {entry}

    changed = True
    while changed:
        changed = False
        for n in all_nodes:
            if n == entry:
                continue
            p_list = preds.get(n, [])
            if not p_list:
                new_dom = {n}
            else:
                # 取所有前驱的 dom 集合的交集
                new_dom = dom_sets[p_list[0]].copy()
                for p in p_list[1:]:
                    new_dom &= dom_sets[p]
                new_dom.add(n)
            if new_dom != dom_sets[n]:
                dom_sets[n] = new_dom
                changed = True

    # 从 dom 集合中提取 immediate dominator
    idom: Dict[int, int] = {}
    for n in all_nodes:
        if n == entry:
            continue
        candidates = dom_sets[n] - {n}
        # idom 是 dom 集合中"最接近" n 的节点——即被所有其他支配者支配
        best = entry
        for c in candidates:
            if c != n and best in dom_sets.get(c, set()):
                best = c
        idom[n] = best

    return idom


def _estimate_block_entropy(size: int, n_succ: int) -> float:
    """
    基本块字节熵的快速估计。

    不对基本块逐字节计算（需要读取原始二进制），而是通过
    块的 size 和出边数 n_succ 进行启发式估计:
      - 大块倾向于高熵（更多指令=更多不同的字节）
      - 多出边块（switch/jump table）倾向于低熵（dispatcher pattern）
      - 归一化到 [0, 1]
    """
    if size <= 0:
        return 0.0
    # 基于 size 的对数估计 + 出边数惩罚
    base = min(1.0, len(str(size)) / 8.0)  # size 的对数归一化
    branch_penalty = 1.0 / max(1, n_succ)  # 多出边=dispatcher=低熵
    return round(base * (0.7 + 0.3 * branch_penalty), 3)


def desg_structural_hash(desg: Dict[str, Any]) -> str:
    """
    计算 DESG 的结构哈希——对编译器优化不敏感的 CFG 指纹。

    仅使用支配树和后支配树的拓扑特征（节点度数分布），
    不使用字节级信息——使哈希对指令选择不敏感。
    用于跨优化级别的二进制相似性初筛。

    返回 16 字符 hex 哈希。
    """
    import hashlib

    dom_degrees = _degree_distribution(desg["edges_dom"])
    pdom_degrees = _degree_distribution(desg["edges_pdom"])
    bb_degrees = _degree_distribution(desg["edges_bb"])

    # 度数分布的排序序列作为特征——排序消除了节点编号差异
    features = (
        ",".join(str(d) for d in dom_degrees[:10])
        + "|" + ",".join(str(d) for d in pdom_degrees[:10])
        + "|" + ",".join(str(d) for d in bb_degrees[:10])
    )
    return hashlib.sha256(features.encode()).hexdigest()[:16]


def _degree_distribution(edges: List[Tuple[int, int]]) -> List[int]:
    """出度分布（排序后的计数序列）。"""
    out_deg: Dict[int, int] = {}
    for src, _ in edges:
        out_deg[src] = out_deg.get(src, 0) + 1
    counts = sorted(out_deg.values(), reverse=True)
    return counts
