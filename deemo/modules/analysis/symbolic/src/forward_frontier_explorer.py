#
# 前向支配前沿探索器——用 CFG 支配树信息引导符号执行路径选择
#
# 路径多样性管理 (path_diversity_core.py) 从"已探索路径间的相似度"做选择——
# 保证探索的路径多样化。但多样性本身不保证覆盖新代码——
# 更"不同"的路径可能都在同一片已穷尽的代码区域内打转
#
# 本模块从另一个维度优化路径选择：预测哪些路径最可能到达未探索的基本块
#
# 核心数据结构：
# domination_tree[node] = 支配该节点的直接支配者 (idom)
# explored_blocks = 已到达的基本块集合
# frontier_blocks = 未到达，但至少有 1 个前驱已被探索的块
#
# 支配前沿 (domin frontier) 的直观意义：
#   块 B 在支配前沿中 = "刚刚超出被支配区域" ——
# 即 B 自身不被当前路径支配，但 B 的某个前驱被支配
# 这些 frontier 块是"再往前一步就能探索到的盲区"
#
# 优先级策略（二段式）：
# 1. Dominator proximi: 距当前探索区域支配者的距离越近，优先级越高
# 支配者 = 已探索区域中支配了最多其他已探索块的那个块
# 2. Block rari: 如果多个 frontier 块到支配者的距离相同
#      则选在函数中"更少见"的块（入度低、指令数少）——
# 这些块更可能是错误处理/边界条件路径，传统 fuzzer 不易触达
#
# ref: Lengauer, T. & Tarjan, R. E. "fast algorithm for finding
# dominators flowgraph." TOPLAS 1.1 (1979): 121-141
# — LT 算法计算直接支配者 O(E log V)
# 本项目不重新实现 LT——假设 CFG 的 idom 已从 angr/IDA 导入
# 本模块消费 idom 数据，提供 frontier-based 路径评分
#
# ref: Cyphert, K. & Breck, J. et al. "Smooth 模糊测试."
# USENIX Securi 2024 (USENIX Associa)
# — 提出将符号执行中的路径选择建模为平滑优化问题
# 本项目采取其对偶视角：不优化"选哪条路径"的连续函数
# 而是计算每条路径到 frontier 的离散近似距离，取最近者

import math
import heapq
from typing import Dict, List, Tuple, Set, Optional
from collections import defaultdict, deque
from dataclasses import dataclass, field


@dataclass
class FrontierBlock:
    """一个未探索但"近在咫尺"的基本块"""
    block_addr: int
    distance_from_dominator: int  # CFG 边数
    predecessor_count: int        # 在 CFG 中的入度
    instruction_count: int        # 块内指令数
    rarity_score: float           # 基于入度和指令数的稀有度 [0, 1]
    heat_penalty: float = 0.0     # 热力衰减——已被多次引导但未成功到达


@dataclass
class PathFrontierScore:
    """一条符号执行路径到支配前沿的评分"""
    path_id: str
    current_addr: int
    nearest_frontier_dist: int   # 到最近 frontier 块的最短 CFG 距离
    total_frontier_score: float  # 综合评分——越高越优先
    reachable_frontiers: List[int]  # 此路径可达的前沿块地址列表


class ForwardFrontierExplorer:
    """基于支配树信息的符号执行路径优先级排序器
    
    消费一个函数的 CFG（基本块 + 边 + idom 映射）
    结合当前已探索块集合，对候选路径评分
    """

    def __init__(self):
        # 支配树: block_addr → idom (直接支配者)
        self._idom: Dict[int, int] = {}
        # CFG 边: src_addr → [dst_addr,.]
        self._cfg_edges: Dict[int, List[int]] = defaultdict(list)
        # 反向 CFG: dst_addr → [src_addr,.]（用于找 frontier）
        self._rev_cfg: Dict[int, List[int]] = defaultdict(list)
        # 块的指令数
        self._block_sizes: Dict[int, int] = {}
        # 已探索的基本块
        self._explored: Set[int] = set()
        # frontier 块 → 被引导次数的热力衰减计数器
        self._frontier_heat: Dict[int, int] = defaultdict(int)
        # 热力半衰期: 每被引导 HEAT_HALFLIFE 次，heat_penal += 0.1
        self._HEAT_HALFLIFE = 5

    def load_cfg(self,
                 idom: Dict[int, int],
                 cfg_edges: Dict[int, List[int]],
                 block_sizes: Optional[Dict[int, int]] = None):
        """加载函数的 CFG 结构
        
        Args:
        idom: 直接支配者映射 (node → immedi dominator)
        cfg_edges: CFG 邻接表 (src → [dst_list])
        block_sizes: 可选——各基本块的指令数
        """
        self._idom = dict(idom)
        self._cfg_edges = defaultdict(list)
        self._rev_cfg = defaultdict(list)
        for src, dsts in cfg_edges.items():
            self._cfg_edges[src] = list(dsts)
            for dst in dsts:
                self._rev_cfg[dst].append(src)
        if block_sizes:
            self._block_sizes = dict(block_sizes)

    def mark_explored(self, block_addr: int):
        """标记一个基本块已被符号执行探索到"""
        self._explored.add(block_addr)

    def mark_explored_batch(self, addresses: List[int]):
        """批量标记已探索的基本块"""
        self._explored.update(addresses)

    def _compute_dominator_distance(self, block_addr: int,
                                    dominator_addr: int) -> int:
        """计算 block_addr 到 dominator_addr 在支配树上的距离
        
        沿 idom 链向上追溯到 dominator 或函数入口（idom[addr]==addr 或不存在）
        返回穿越的 idom 步数
        """
        dist = 0
        current = block_addr
        visited = set()
        while current != dominator_addr and current not in visited:
            visited.add(current)
            if current in self._idom and self._idom[current] != current:
                current = self._idom[current]
                dist += 1
            else:
                # 到达支配树的根（函数入口）
                break
        return dist if current == dominator_addr else 999  # 不可达

    def find_frontier_blocks(self) -> List[FrontierBlock]:
        """定位支配前沿——未探索但至少有一个前驱已探索的块
        
        返回: 按 (距支配者距离, 稀有度分) 排序的前沿块列表
        """
        if not self._explored:
            return []

        # 前沿 = {未探索} ∩ {已探索块的直接后继}
        frontier_addrs: Set[int] = set()
        for explored_addr in self._explored:
            for succ in self._cfg_edges.get(explored_addr, []):
                if succ not in self._explored:
                    frontier_addrs.add(succ)

        if not frontier_addrs:
            return []

        # 找到当前已探索区域中的"主支配者"
        # 策略：在所有的 idom 关系中计数 —— 被最多其他已探索块作为 idom 引用的块
        dominator_hits: Dict[int, int] = defaultdict(int)
        for addr in self._explored:
            dom = self._idom.get(addr)
            if dom and dom in self._explored:
                dominator_hits[dom] += 1

        primary_dominator = max(dominator_hits, key=dominator_hits.get) \
            if dominator_hits else (min(self._explored) if self._explored else 0)

        result = []
        for faddr in frontier_addrs:
            dist = self._compute_dominator_distance(faddr, primary_dominator)
            pred_count = len(self._rev_cfg.get(faddr, []))
            insn_count = self._block_sizes.get(faddr, 3)

            # 稀有度 = 入度越低、指令越少 → 越罕见（错误处理/边界路径的典型特征）
            # 归一化入度稀有度: 入度 1 → rari=1.0, 入度 ≥8 → rari=0.1
            rarity_pred = max(0.1, 1.0 / max(1, math.log2(pred_count + 1)))
            # 小基本块更可能是边界路径——指令
            rarity_size = max(0.1, 1.0 / max(1, math.log2(insn_count + 1)))
            rarity = 0.6 * rarity_pred + 0.4 * rarity_size  # 加权平均

            # 热力衰减
            heat_count = self._frontier_heat.get(faddr, 0)
            heat_penalty = min(0.5, (heat_count // self._HEAT_HALFLIFE) * 0.1)

            result.append(FrontierBlock(
                block_addr=faddr,
                distance_from_dominator=dist,
                predecessor_count=pred_count,
                instruction_count=insn_count,
                rarity_score=round(rarity, 4),
                heat_penalty=round(heat_penalty, 2),
            ))

        # 排序：距离近 > 稀有度高 > 热力惩罚低
        result.sort(key=lambda fb: (
            fb.distance_from_dominator,
            -fb.rarity_score + fb.heat_penalty,
        ))
        return result

    def score_paths(self,
                    paths: List[Tuple[str, int]],
                    # (path_id, current_block_addr)
                    cfg_shortest_path_cache: Optional[Dict[Tuple[int, int], int]] = None,
                    ) -> List[PathFrontierScore]:
        """对路径列表评分，按到达前沿的优先级排序
        
        Args:
        paths: 候选路径列表——(path_id, 当前所在块地址)
        cfg_shortest_path_cache: 可选的 (src, dst) → 最短距离的预计算缓存
        
        返回:
        按 total_frontier_score 降序排列的评分列表
        """
        frontiers = self.find_frontier_blocks()
        if not frontiers:
            return [PathFrontierScore(
                path_id=pid, current_addr=addr,
                nearest_frontier_dist=999, total_frontier_score=0.0,
                reachable_frontiers=[],
            ) for pid, addr in paths]

        # 取前 20 个最有价值的前沿块——减少计算量
        top_frontiers = frontiers[:20]
        frontier_addrs = {fb.block_addr for fb in top_frontiers}

        results = []
        for path_id, current_addr in paths:
            reachable = []
            min_dist = 999

            for fb in top_frontiers:
                # 从当前块到 frontier 块的最短 CFG 距离
                dist = self._shortest_path_bfs(
                    current_addr, fb.block_addr,
                    cache=cfg_shortest_path_cache,
                    max_depth=50,  # 距离超过 50 的不可达 —— 放弃
                )
                if dist < 999:
                    reachable.append(fb.block_addr)
                    min_dist = min(min_dist, dist)

            # 综合评分 = 到达最近前沿的距离倒数 + 可达前沿块的总价值
            proximity_score = 1.0 / max(1, min_dist)  # 越近越高
            frontier_value = sum(
                (1.0 - fb.heat_penalty) * fb.rarity_score
                for fb in top_frontiers
                if fb.block_addr in reachable
            ) / max(1, len(top_frontiers))

            total_score = 0.6 * proximity_score + 0.4 * frontier_value

            results.append(PathFrontierScore(
                path_id=path_id,
                current_addr=current_addr,
                nearest_frontier_dist=min_dist,
                total_frontier_score=round(total_score, 5),
                reachable_frontiers=reachable,
            ))

        results.sort(key=lambda s: -s.total_frontier_score)
        return results

    def record_frontier_guided(self, frontier_addr: int):
        """记录一次对某前沿块的引导尝试
        
        用于热力衰减——同一个前沿被反复引导但始终未到达时
        其优先级应逐渐降低（可能是死代码或不精确的 CFG 边）
        """
        self._frontier_heat[frontier_addr] += 1

    def _shortest_path_bfs(self,
                           src: int,
                           dst: int,
                           cache: Optional[Dict[Tuple[int, int], int]] = None,
                           max_depth: int = 50) -> int:
        """CFG 上的 BFS 最短路径。使用缓存以避免重复搜索"""
        if src == dst:
            return 0

        cache_key = (src, dst)
        if cache and cache_key in cache:
            return cache[cache_key]

        visited: Set[int] = {src}
        queue = deque([(src, 0)])
        while queue:
            node, dist = queue.popleft()
            if dist >= max_depth:
                continue
            for succ in self._cfg_edges.get(node, []):
                if succ == dst:
                    if cache is not None:
                        cache[cache_key] = dist + 1
                    return dist + 1
                if succ not in visited:
                    visited.add(succ)
                    queue.append((succ, dist + 1))

        if cache is not None:
            cache[cache_key] = 999
        return 999  # 不可达

    def select_best_path(self,
                         paths: List[Tuple[str, int]],
                         cfg_cache: Optional[Dict[Tuple[int, int], int]] = None,
                         ) -> Optional[Tuple[str, int, float]]:
        """从候选路径中选择最有希望到达未探索区域的一条
        
        返回:
        (path_id, current_addr, score) 或 None（无候选时）
        """
        scored = self.score_paths(paths, cfg_cache)
        if not scored:
            return None
        best = scored[0]
        return (best.path_id, best.current_addr, best.total_frontier_score)

    def frontier_summary(self) -> Dict:
        """返回前沿状态的简要摘要（用于日志/仪表板）"""
        frontiers = self.find_frontier_blocks()
        return {
            'frontier_count': len(frontiers),
            'top_frontier_addrs': [fb.block_addr for fb in frontiers[:5]],
            'explored_blocks': len(self._explored),
            'total_cfg_blocks': len(self._idom) or len(self._cfg_edges),
            'exploration_coverage': round(
                len(self._explored) / max(1, len(self._idom) or len(self._cfg_edges)), 4
            ),
        }
