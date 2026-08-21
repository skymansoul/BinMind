#                               关系即使 A 和 B 不是全局变量也可推断锁依赖
#
# 锁图 - 锁获取的偏序关系图，用于死锁检测
#
# 节点: 锁标识符（从 SyncSite.lock_identifier 推导）
# 有向边 A → B: 存在某个函数先获取锁 A 再获取锁 B（锁序偏序）
#
# 死锁条件: 锁图中存在有向环 A → B →. → A
# 每个 SCC（强连通分量）大小 >1 对应一个潜在的死锁

import logging
from typing import Dict, List, Set, Tuple, Optional
from dataclasses import dataclass, field
from collections import defaultdict

from .sync_primitive import SyncSite, SyncType, build_lock_pairs

logger = logging.getLogger(__name__)


@dataclass
class LockNode:
    """锁图中的一个节点-代表一个锁标识符"""
    lock_id: str
    sites: List[SyncSite] = field(default_factory=list)  # 所有操作此锁的 SyncSite
    func_count: int = 0  # 涉及此锁的函数数量


@dataclass
class LockOrderEdge:
    """锁图中的一条有向边 src_lock → dst_lock"""
    src_lock: str
    dst_lock: str
    witness_func: str  # 产生此边关系的函数名（用于报告）
    witness_addr: int


@dataclass
class LockGraph:
    """锁依赖有向图"""
    nodes: Dict[str, LockNode] = field(default_factory=dict)
    edges: List[LockOrderEdge] = field(default_factory=list)
    # 邻接表 - 用于快速检测传递闭包
    _adj: Dict[str, Set[str]] = field(default_factory=lambda: defaultdict(set))


def build_lock_graph(sites: List[SyncSite]) -> LockGraph:
    """从同步操作位点构建锁依赖图

    算法：
    对每个函数：
    1. 按指令偏移排序锁操作
    2. 在 lock(A) 和对应的 unlock(A) 之间的所有 lock(B)
    都产生 A → B 的偏序关系
    3. 嵌套的锁对也递归产生关系（传递闭包由 SCC 检测处理）

    复杂度 O(F × S × L)，F=函数数, S=每函数平均锁操作数, L=嵌套深度
    对大型二进制文件（10k+函数）可考虑采样-目前先保证正确性
    """
    graph = LockGraph()

    # 按函数分组
    by_func: Dict[int, List[SyncSite]] = {}
    for site in sites:
        sid = (site.func_addr, site.func_name)
        by_func.setdefault(site.func_addr, []).append(site)
        # 注册锁节点
        lid = site.lock_identifier
        if lid not in graph.nodes:
            graph.nodes[lid] = LockNode(lock_id=lid)
        graph.nodes[lid].sites.append(site)

    # 函数内锁序提取
    for func_addr, func_sites in by_func.items():
        func_sites.sort(key=lambda s: s.insn_offset)

        # 维护一个"当前持有的锁"栈
        held: List[SyncSite] = []

        for site in func_sites:
            is_lock = site.sync_type in (SyncType.MUTEX_LOCK, SyncType.MUTEX_TRYLOCK,
                                          SyncType.RWLOCK_WRLOCK, SyncType.RWLOCK_RDLOCK,
                                          SyncType.SPIN_LOCK)
            is_unlock = site.sync_type in (SyncType.MUTEX_UNLOCK, SyncType.RWLOCK_UNLOCK,
                                            SyncType.SPIN_UNLOCK)

            if is_lock:
                # 当前持有的每个锁 → 正在获取的锁 = 偏序
                for held_site in held:
                    if held_site.lock_identifier != site.lock_identifier:
                        edge = LockOrderEdge(
                            src_lock=held_site.lock_identifier,
                            dst_lock=site.lock_identifier,
                            witness_func=site.func_name,
                            witness_addr=site.func_addr,
                        )
                        graph.edges.append(edge)
                        graph._adj[held_site.lock_identifier].add(site.lock_identifier)

                held.append(site)

            elif is_unlock:
                # 配对最近的对应锁并弹出
                for i in range(len(held) - 1, -1, -1):
                    if held[i].lock_identifier == site.lock_identifier:
                        held.pop(i)
                        break
                # 未匹配的 unlock 忽略（可能是外部传入的锁）

    # 统计每个锁的使用函数数
    funcs_per_lock: Dict[str, Set[str]] = defaultdict(set)
    for site in sites:
        funcs_per_lock[site.lock_identifier].add(site.func_name)
    for lid, node in graph.nodes.items():
        node.func_count = len(funcs_per_lock.get(lid, set()))

    return graph


def _tarjan_scc(adj: Dict[str, Set[str]]) -> List[List[str]]:
    """Tarjan 强连通分量算法-比简单环搜索更高效

    返回所有 SCC，每个 SCC 是节点 ID 列表。大小 >1 的 SCC 含环
    """
    index = 0
    indices: Dict[str, int] = {}
    lowlink: Dict[str, int] = {}
    on_stack: Set[str] = set()
    stack: List[str] = []
    sccs: List[List[str]] = []

    def strongconnect(v: str):
        nonlocal index
        indices[v] = index
        lowlink[v] = index
        index += 1
        stack.append(v)
        on_stack.add(v)

        for w in adj.get(v, set()):
            if w not in indices:
                strongconnect(w)
                lowlink[v] = min(lowlink[v], lowlink[w])
            elif w in on_stack:
                lowlink[v] = min(lowlink[v], indices[w])

        if lowlink[v] == indices[v]:
            scc = []
            while True:
                w = stack.pop()
                on_stack.discard(w)
                scc.append(w)
                if w == v:
                    break
            sccs.append(scc)

    for v in adj:
        if v not in indices:
            strongconnect(v)

    return sccs


def detect_deadlock_cycles(graph: LockGraph) -> List[Tuple[List[str], List[LockOrderEdge]]]:
    """检测锁图中的死锁环

    返回 [(cycle_nodes, involved_edges),.]-每个环对应一个潜在死锁

    注意：
    - 仅报告大小 >1 的 SCC 中的全体节点-不是每个具体环
    - SCC 中任意两点之间存在有向路径，所以整个 SCC 都是潜在死锁区域
    - 生产环境中应进一步过滤：排除 trylock 保护的环（有回退策略）
    """
    sccs = _tarjan_scc(graph._adj)

    deadlock_cycles = []
    for scc in sccs:
        if len(scc) <= 1:
            continue

        # 找到此 SCC 中涉及的所有边
        scc_set = set(scc)
        involved_edges = [
            e for e in graph.edges
            if e.src_lock in scc_set and e.dst_lock in scc_set
        ]

        deadlock_cycles.append((scc, involved_edges))

    if deadlock_cycles:
        logger.warning("检测到 %d 个潜在死锁 SCC", len(deadlock_cycles))

    return deadlock_cycles
