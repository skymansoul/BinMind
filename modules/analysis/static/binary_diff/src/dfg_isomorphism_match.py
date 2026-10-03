from dataclasses import dataclass, field
from collections import defaultdict
import hashlib
from typing import Optional


@dataclass
class DFGNode:
    """DFG 中的一个节点-一条指令 + 数据依赖。"""
    pc: int
    opcode: str = ''           # 语义操作符 (mov/add/cmp/call)
    defines: set[str] = field(default_factory=set)
    uses: set[str] = field(default_factory=set)
    neighborhood_hash: str = ''  # 2-hop 邻域哈希


@dataclass
class DFGEdge:
    """DFG 中的一条有向边-src 输出被 dst 使用。"""
    src_pc: int
    dst_pc: int
    use_name: str = ''         # 被使用的寄存器/变量名


@dataclass
class DFGGraph:
    """函数的完整数据流图。"""
    func_addr: int
    func_name: str = ''
    nodes: dict[int, DFGNode] = field(default_factory=dict)
    edges: list[DFGEdge] = field(default_factory=list)
    arch: str = 'unknown'


def build_dfg_from_instructions(ins_list: list[dict],
                                func_addr: int = 0) -> DFGGraph:
    """从指令列表构建数据流图。"""
    graph = DFGGraph(func_addr=func_addr)
    # 跟踪每个"存储位置"(寄存器+抽象内存) 的最新定义指令地址
    last_def: dict[str, int] = {}

    for ins in ins_list:
        mnemonic = ins.get('mnemonic', '').lower()
        pc = ins.get('address', 0)
        ops = str(ins.get('operands', ''))

        defines, uses = _extract_def_use(mnemonic, ops)

        node = DFGNode(pc=pc, opcode=mnemonic, defines=defines, uses=uses)
        graph.nodes[pc] = node

        # 建立数据依赖边: 每个 use → 此 use 的上一次定义
        for u in uses:
            if u in last_def:
                graph.edges.append(DFGEdge(src_pc=last_def[u], dst_pc=pc, use_name=u))

        # 更新定义位置
        for d in defines:
            last_def[d] = pc

    # 计算邻域哈希
    for pc, node in graph.nodes.items():
        node.neighborhood_hash = _compute_neighborhood_hash(pc, graph)

    return graph


def _extract_def_use(mnemonic: str, operands: str) -> tuple[set[str], set[str]]:
    """提取指令的 def/use 集合。简化的寄存器级分析。"""
    parts = [p.strip() for p in operands.replace('[', '').replace(']', '').split(',')]
    # 目的操作数 = def
    defines = set()
    uses = set()
    dst = parts[0] if parts else ''
    if dst and not dst.startswith(('0x', '[')):
        defines.add(dst)
    # 源操作数 = use
    for src in parts[1:]:
        if src and not src.startswith(('0x', '[')):
            uses.add(src)
    # 特殊: memory 操作
    if '[' in operands:
        m = __import__('re').search(r'\[([^\]]+)\]', operands)
        if m:
            uses.add(f'mem:{m.group(1)}')
    return defines, uses


def _compute_neighborhood_hash(node_pc: int, graph: DFGGraph, radius: int = 2) -> str:
    """计算节点的 2-hop 邻域哈希-用于跨图节点匹配。"""
    h = hashlib.sha256()
    node = graph.nodes.get(node_pc)
    if node is None:
        return h.hexdigest()[:12]

    # 1-hop: 直接邻居
    nbrs_in = [e.src_pc for e in graph.edges if e.dst_pc == node_pc]
    nbrs_out = [e.dst_pc for e in graph.edges if e.src_pc == node_pc]

    # 编码: opcode + degree + neighbor opcodes
    h.update(node.opcode.encode())
    h.update(str(len(nbrs_in) + len(nbrs_out)).encode())
    for nbr_pc in sorted(nbrs_in + nbrs_out)[:8]:
        nbr = graph.nodes.get(nbr_pc)
        if nbr:
            h.update(nbr.opcode.encode())

    return h.hexdigest()[:12]


def compute_dfg_similarity(g1: DFGGraph, g2: DFGGraph) -> float:
    """计算两个 DFG 的相似度-二分图匹配 + 贪心扩展。"""
    # 1. 基于邻域哈希的节点匹配-建立候选配对
    hash_to_nodes1: dict[str, list[int]] = defaultdict(list)
    hash_to_nodes2: dict[str, list[int]] = defaultdict(list)
    for pc, n in g1.nodes.items():
        hash_to_nodes1[n.neighborhood_hash].append(pc)
    for pc, n in g2.nodes.items():
        hash_to_nodes2[n.neighborhood_hash].append(pc)

    # 2. 贪心选择匹配: 相同邻域哈希的节点对
    matches: dict[int, int] = {}  # pc1 → pc2
    used_pc2: set[int] = set()
    for nhash, pcs1 in hash_to_nodes1.items():
        pcs2 = hash_to_nodes2.get(nhash, [])
        for pc1 in pcs1:
            if pc1 in matches:
                continue
            for pc2 in pcs2:
                if pc2 not in used_pc2:
                    matches[pc1] = pc2
                    used_pc2.add(pc2)
                    break

    # 3. 扩展匹配: 已匹配节点的邻居优先-保持局部拓扑一致性
    changed = True
    while changed:
        changed = False
        for e1 in g1.edges:
            if e1.src_pc in matches and e1.dst_pc not in matches:
                m_src = matches[e1.src_pc]
                for e2 in g2.edges:
                    if e2.src_pc == m_src and e2.dst_pc not in used_pc2:
                        node1 = g1.nodes.get(e1.dst_pc)
                        node2 = g2.nodes.get(e2.dst_pc)
                        if node1 and node2 and node1.opcode == node2.opcode:
                            matches[e1.dst_pc] = e2.dst_pc
                            used_pc2.add(e2.dst_pc)
                            changed = True
                            break

    # 相似度 = 匹配节点数 / 最大图节点数
    max_nodes = max(len(g1.nodes), len(g2.nodes))
    if max_nodes == 0:
        return 0.0
    return len(matches) / max_nodes


__all__ = [
    'DFGGraph', 'DFGNode', 'DFGEdge',
    'build_dfg_from_instructions', 'compute_dfg_similarity',
]
