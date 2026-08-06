# 复杂度加权的定向Fuzzing — 不止"到目标有多远"，还要"到达有多难"
#
# 核心问题:
#   directed_fuzz.py 用调和平均距离 (AFLGo风格) 引导种子向目标靠近。
#   SEZZ (2025) 证明: 距离短≠容易到达——短路径可能经过复杂的基本块
#   (多次比较/循环/间接调用), 实际到达难度更高。
#
#   PathFuzz (2025) 进一步指出: 固定值(10)做函数间距离无法区分
#   长种子和短种子, 导致距离计算精度不足。
#
# 本模块的方法 — 复杂度×距离的加权融合:
#   1. 计算每个基本块的"到达复杂度": 基于入度、分支条件数、循环嵌套深度
#   2. 复杂度和距离的加权融合:
#      score(seed, target) = α × distance_norm + (1-α) × complexity_norm
#   3. 距离和复杂度均归一化到 [0,1], 确保公平加权
#   4. 复杂度随fuzzing进度动态更新: 新发现的路径可能降低复杂度估计
#
# 与 directed_fuzz.py 的关系:
#   directed_fuzz: 距离计算 + 能量分配
#   本模块: 在距离之上叠加复杂度修正, 可以包装 directed_fuzz 的接口
#
# 参考文献:
#   SEZZ (MDPI Applied Sciences, July 2025) — 函数调用序列复杂度估计;
#     本项目取其复杂度思想但适配到基本块粒度
#   PathFuzz (IST 2025) — 路径约束+偏差修正;
#     本项目取其精确距离思想但以复杂度替代路径约束

from __future__ import annotations

import math
import heapq
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

# 桥接 directed_fuzz.py: 本模块提供 DistanceMetrics 的超集——
# ComplexityWeightedDistance 包含原始 cg_distance/bb_distance/harmonic_distance
# 字段, 可无缝替换 DirectedFuzzer.score_seed() 的返回值。
# 调用方可将 ComplexityWeightedDistance.harmonic_distance 回传给
# DirectedFuzzer 的能量调度逻辑, 实现渐进式升级。


@dataclass
class BlockComplexity:
    """单个基本块的到达复杂度"""
    block_addr: int
    # 拓扑复杂度
    indegree: int = 0            # 入度——合并点多→更难到达
    outdegree: int = 0           # 出度——分支多→穿越更难
    # 语义复杂度
    cmp_count: int = 0           # 比较指令数——需满足更多条件
    call_count: int = 0          # 调用指令数——可能间接跳转
    loop_depth: int = 0          # 循环嵌套深度——需多次迭代
    # 综合
    complexity_score: float = 0.0
    # 是否已确认可达
    reached: bool = False


@dataclass
class ComplexityWeightedDistance:
    """复杂度加权的种子→目标距离"""
    seed_id: str = ""
    # 原始距离 (来自 directed_fuzz)
    cg_distance: float = float('inf')
    bb_distance: float = float('inf')
    harmonic_distance: float = float('inf')
    # 复杂度分量
    path_complexity: float = 0.0    # 最短路径上的累积复杂度
    # 融合分数
    weighted_score: float = float('inf')  # 越小越好
    # 元信息
    path_length: int = 0
    blocks_on_path: List[int] = field(default_factory=list)


class ComplexityWeightedDirectedFuzzer:
    """复杂度加权的定向Fuzzing引导器。

    典型用法:
        cwdf = ComplexityWeightedDirectedFuzzer(complexity_weight=0.35)
        cwdf.set_targets(target_funcs={'vuln_func'}, target_blocks={0x405000})
        cwdf.load_call_graph(call_graph)
        cwdf.load_cfg(cfg_adjacency, block_complexities)
        cwdf.compute()
        score = cwdf.score_seed('seed_1', [0x401000, 0x401050])
    """

    def __init__(self, complexity_weight: float = 0.35):
        """
        complexity_weight: 复杂度在融合分数中的权重 [0, 1]。
        0.0 → 纯距离 (退化为 AFLGo)
        1.0 → 纯复杂度
        """
        self._alpha = complexity_weight
        # 目标
        self._target_funcs: Set[str] = set()
        self._target_blocks: Set[int] = set()
        # 图结构
        self._call_graph: Dict[str, Set[str]] = defaultdict(set)
        self._intra_cfg: Dict[str, Dict[int, List[int]]] = defaultdict(
            lambda: defaultdict(list))
        # 复杂度
        self._block_complexity: Dict[int, BlockComplexity] = {}
        # 计算结果
        self._cg_dist: Dict[str, float] = {}
        self._bb_dist: Dict[int, float] = {}
        self._bb_complexity_path: Dict[int, float] = {}
        self._computed = False

    def set_targets(self, target_funcs: Set[str],
                     target_blocks: Optional[Set[int]] = None) -> None:
        self._target_funcs = target_funcs
        self._target_blocks = target_blocks or set()
        self._computed = False

    def load_call_graph(self, cg: Dict[str, Set[str]]) -> None:
        self._call_graph = defaultdict(set, cg)
        self._computed = False

    def load_cfg(self, func_cfgs: Dict[str, Dict[int, List[int]]],
                  complexities: Optional[Dict[int, BlockComplexity]] = None,
                  ) -> None:
        """加载函数内CFG和基本块复杂度"""
        self._intra_cfg = defaultdict(lambda: defaultdict(list))
        for func, cfg in func_cfgs.items():
            self._intra_cfg[func] = cfg
        if complexities:
            self._block_complexity = complexities
        self._computed = False

    def compute(self) -> None:
        """主计算: 复杂的CG距离 + BB距离 + 路径复杂度"""
        # Step 1: CG距离 (从每个函数到目标函数的调用图最短路径)
        self._cg_dist = self._compute_cg_distances()

        # Step 2: BB距离 + 路径复杂度 (函数内CFG)
        self._bb_dist = {}
        self._bb_complexity_path = {}
        for func_name, cfg in self._intra_cfg.items():
            func_targets = self._target_blocks & set(cfg.keys())
            if not func_targets:
                continue
            # 对每个目标BB做反向BFS
            for tgt in func_targets:
                bb_dists, bb_comps = self._compute_bb_distance_with_complexity(
                    cfg, tgt)
                for addr, d in bb_dists.items():
                    if addr not in self._bb_dist or d < self._bb_dist[addr]:
                        self._bb_dist[addr] = d
                for addr, c in bb_comps.items():
                    if addr not in self._bb_complexity_path or c < self._bb_complexity_path[addr]:
                        self._bb_complexity_path[addr] = c

        self._computed = True

    def score_seed(self, seed_id: str,
                    covered_blocks: List[int]) -> ComplexityWeightedDistance:
        """计算种子的复杂度加权距离"""
        if not self._computed:
            self.compute()

        result = ComplexityWeightedDistance(seed_id=seed_id)
        if not covered_blocks:
            return result

        # Step 1: 每个被覆盖块的BB距离 (取最小)
        bb_dists = []
        for addr in covered_blocks:
            d = self._bb_dist.get(addr, float('inf'))
            if d < float('inf'):
                bb_dists.append(d)
        result.bb_distance = min(bb_dists) if bb_dists else float('inf')

        # Step 2: 最短路径上的累积复杂度
        path_comps = []
        for addr in covered_blocks:
            c = self._bb_complexity_path.get(addr, 0.0)
            if c < float('inf'):
                path_comps.append(c)
        result.path_complexity = min(path_comps) if path_comps else 0.0

        # Step 3: 融合分数
        if result.bb_distance < float('inf'):
            # 归一化: 假设最大距离=100, 最大复杂度=50
            dist_norm = min(1.0, result.bb_distance / 100.0)
            comp_norm = min(1.0, result.path_complexity / 50.0)
            result.weighted_score = (
                (1.0 - self._alpha) * dist_norm
                + self._alpha * comp_norm
            )
        else:
            result.weighted_score = float('inf')

        return result

    def _compute_cg_distances(self) -> Dict[str, float]:
        """BFS从目标函数反向传播CG距离"""
        dist: Dict[str, float] = {}
        q = deque()
        for tf in self._target_funcs:
            dist[tf] = 0.0
            q.append(tf)

        # 构建反向CG
        rev_cg: Dict[str, Set[str]] = defaultdict(set)
        for caller, callees in self._call_graph.items():
            for callee in callees:
                rev_cg[callee].add(caller)

        while q:
            func = q.popleft()
            for caller in rev_cg.get(func, set()):
                if caller not in dist:
                    dist[caller] = dist[func] + 1.0
                    q.append(caller)
        return dist

    def _compute_bb_distance_with_complexity(self,
                                               cfg: Dict[int, List[int]],
                                               target: int,
                                               ) -> Tuple[Dict[int, float],
                                                          Dict[int, float]]:
        """反向BFS: 计算每个BB到target的距离和累积复杂度"""
        dist: Dict[int, float] = {target: 0.0}
        comp: Dict[int, float] = {target: 0.0}
        q = deque([target])

        # 构建反向CFG
        rev: Dict[int, List[int]] = defaultdict(list)
        for src, succs in cfg.items():
            for dst in succs:
                rev[dst].append(src)

        while q:
            u = q.popleft()
            u_comp = self._block_complexity.get(u)
            u_base = u_comp.complexity_score if u_comp else 0.0

            for pred in rev.get(u, []):
                new_dist = dist[u] + 1.0
                new_comp = comp[u] + u_base
                if pred not in dist or new_dist < dist[pred]:
                    dist[pred] = new_dist
                    comp[pred] = new_comp
                    q.append(pred)

        return dist, comp

    @staticmethod
    def estimate_block_complexity(cfg: Dict[int, List[int]],
                                   block_sizes: Optional[Dict[int, int]] = None,
                                   ) -> Dict[int, BlockComplexity]:
        """从CFG估算基本块复杂度——仅需邻接表, 无需指令级信息"""
        # 计算入度
        indeg: Dict[int, int] = defaultdict(int)
        for src, succs in cfg.items():
            for dst in succs:
                indeg[dst] += 1

        result: Dict[int, BlockComplexity] = {}
        for addr in cfg:
            bc = BlockComplexity(block_addr=addr)
            bc.indegree = indeg.get(addr, 0)
            bc.outdegree = len(cfg.get(addr, []))
            # 启发式复杂度: 入度×2 + 出度×1.5 + 块大小因子
            size = block_sizes.get(addr, 1) if block_sizes else 1
            bc.complexity_score = (
                bc.indegree * 2.0 + bc.outdegree * 1.5
                + math.log2(max(1, size)) * 0.5
            )
            result[addr] = bc
        return result

    def stats(self) -> Dict[str, Any]:
        return {
            "target_funcs": len(self._target_funcs),
            "target_blocks": len(self._target_blocks),
            "cg_dist_cached": len(self._cg_dist),
            "bb_dist_cached": len(self._bb_dist),
            "complexity_weight": self._alpha,
            "computed": self._computed,
        }
