# 定向模糊测试引擎 — 基于调用图距离的种子能量分配与路径引导
# 核心思想: 计算每个基本块到目标（漏洞嫌疑区域/补丁变更函数）的最短距离，
# 种子距离=该种子执行路径上所有基本块的平均目标距离。
# 距离越近->能量越高->变异次数越多->更快到达目标区域。
#
# 参考文献:
#   BEACON (Huang et al. USENIX 2022): Directed Grey-Box Fuzzing with
#     Provable Path Pruning — 基于层级的距离近似
#   Hawkeye (Chen et al. CCS 2018): Towards a Desired Directed Grey-box
#     Fuzzer — 邻域函数距离+调用链距离
#   MC2 (Shahriar et al. CCS 2022): Rigorous and Efficient Directed
#     Greybox Fuzzing — 调用图级+基本块级双重距离
#   RDFuzz (Ye et al. ESEC/FSE 2023): Accelerating Directed Fuzzing with
#     Intertwined Schedule and Optimized Mutation
#   SoK: Where to Fuzz? (Luo et al. CSF 2024) — 定向Fuzzing目标选择综述
import math
import time
import heapq
from typing import Dict, List, Set, Tuple, Optional, Any
from collections import defaultdict, deque
from dataclasses import dataclass, field


@dataclass
class DistanceMetrics:
    """基本块的距离度量 — 多级距离: 调用图级+基本块级"""
    cg_distance: float = float('inf')     # 调用图最短路径到目标函数的步数
    bb_distance: float = float('inf')     # 函数内基本块CFG最短路径到目标BB
    harmonic: float = float('inf')        # 调和平均: 2/(1/cg + 1/bb)

    def combined(self) -> float:
        return self.harmonic


class DirectedFuzzer:
    """定向模糊测试调度器。

    工作流:
    1. set_targets(target_funcs, target_blocks) — 设定目标
    2. load_call_graph(caller->callee) + load_intra_cfg(func->[bb->successors])
    3. compute_distances() — 计算全程序的基本块-目标距离
    4. score_seed(cov_blocks) -> 对种子执行路径计算平均距离->能量
    """

    INF = float('inf')

    def __init__(self):
        # 目标集
        self._target_funcs: Set[str] = set()
        self._target_blocks: Set[int] = set()
        # 图结构
        self._call_graph: Dict[str, Set[str]] = defaultdict(set)  # caller -> callees
        self._call_graph_rev: Dict[str, Set[str]] = defaultdict(set)
        self._intra_cfg: Dict[str, Dict[int, List[int]]] = defaultdict(
            lambda: defaultdict(list))  # func -> bb -> successors
        # 距离缓存
        self._cg_dist: Dict[str, float] = {}          # func -> call graph distance
        self._bb_dist: Dict[int, float] = {}          # bb_addr -> intra BB distance
        self._combined: Dict[int, float] = {}          # bb_addr -> harmonic combined
        self._computed = False
        # 调度状态
        self._seed_energy: Dict[str, float] = {}
        self._round = 0

    # ---- 目标设定 ----
    def set_targets(self, target_funcs: List[str] = None,
                    target_blocks: List[int] = None) -> None:
        if target_funcs:
            self._target_funcs = set(target_funcs)
        if target_blocks:
            self._target_blocks = set(target_blocks)
        self._computed = False

    def add_target_block(self, bb_addr: int) -> None:
        self._target_blocks.add(bb_addr)
        self._computed = False

    # ---- 图加载 ----
    def load_call_graph(self,
                        edges: List[Tuple[str, str]]) -> None:
        """edges: [(caller, callee), ...]"""
        self._call_graph.clear()
        self._call_graph_rev.clear()
        for caller, callee in edges:
            self._call_graph[caller].add(callee)
            self._call_graph_rev[callee].add(caller)
        self._computed = False

    def load_intra_cfg(self, func_name: str,
                       bb_edges: Dict[int, List[int]]) -> None:
        """bb_edges: {bb_addr: [successor_addrs]}"""
        for bb, succs in bb_edges.items():
            self._intra_cfg[func_name][bb] = list(succs)
        self._computed = False

    # ---- 距离计算 ----
    def compute_distances(self) -> None:
        """两级距离: 先计算调用图距离，再合并函数内BB距离。

        调和平均: d_comb = 2 / (1/d_cg + 1/d_bb)
        若BB在目标函数内 -> d_cg = 0
        若BB本身是目标 -> d_bb = 0
        """
        self._compute_cg_distances()
        self._compute_bb_distances()
        self._compute_combined()
        self._computed = True

    def _compute_cg_distances(self) -> None:
        """从目标函数反向BFS遍历调用图，计算每个函数到最近目标的调用图距离(步数)。

        若函数本身是目标 -> distance=0。
        """
        self._cg_dist = {}
        queue = deque()
        for tf in self._target_funcs:
            self._cg_dist[tf] = 0.0
            queue.append((tf, 0.0))
        # 收集所有已知函数（caller+callee的并集）
        all_funcs = set(self._call_graph.keys()) | set(
            self._call_graph_rev.keys()) | self._target_funcs
        for func in all_funcs:
            if func not in self._cg_dist:
                self._cg_dist[func] = self.INF

        while queue:
            current, dist = queue.popleft()
            # 反向遍历: 谁调用了current？
            for caller in self._call_graph_rev.get(current, set()):
                new_dist = dist + 1.0
                if new_dist < self._cg_dist.get(caller, self.INF):
                    self._cg_dist[caller] = new_dist
                    queue.append((caller, new_dist))

    def _compute_bb_distances(self) -> None:
        """对每个函数内CFG，从目标基本块反向BFS，计算函数内BB距离。

        若无目标BB在函数内 -> 函数内所有BB距离=INF，仅靠调用图距离驱动。
        """
        self._bb_dist = {}
        for func_name, cfg in self._intra_cfg.items():
            # 构建反向CFG
            rev_cfg: Dict[int, List[int]] = defaultdict(list)
            all_bbs: Set[int] = set()
            for bb, succs in cfg.items():
                all_bbs.add(bb)
                for s in succs:
                    all_bbs.add(s)
                    rev_cfg[s].append(bb)

            # BFS从目标BB出发
            queue = deque()
            local_dist: Dict[int, float] = {}
            for bb in all_bbs:
                if bb in self._target_blocks:
                    local_dist[bb] = 0.0
                    queue.append((bb, 0.0))
                else:
                    local_dist[bb] = self.INF

            while queue:
                bb, dist = queue.popleft()
                for pred in rev_cfg.get(bb, []):
                    new_dist = dist + 1.0
                    if new_dist < local_dist.get(pred, self.INF):
                        local_dist[pred] = new_dist
                        queue.append((pred, new_dist))

            self._bb_dist.update(local_dist)

        # 未在任何函数内的目标BB单独处理
        for tb in self._target_blocks:
            if tb not in self._bb_dist:
                self._bb_dist[tb] = 0.0

    def _compute_combined(self) -> None:
        """调和平均合并两级距离。"""
        self._combined = {}
        all_bbs = set(self._bb_dist.keys())
        for func_name, cfg in self._intra_cfg.items():
            all_bbs.update(cfg.keys())
            for succs in cfg.values():
                all_bbs.update(succs)

        cg_for_func: Dict[int, float] = {}
        for func_name in self._intra_cfg:
            for bb in self._intra_cfg[func_name]:
                cg_for_func[bb] = self._cg_dist.get(func_name, self.INF)

        for bb in all_bbs:
            d_cg = cg_for_func.get(bb, self.INF)
            d_bb = self._bb_dist.get(bb, self.INF)
            if d_cg < self.INF and d_bb < self.INF:
                denom = (1.0 / max(0.001, d_cg)) + (1.0 / max(0.001, d_bb))
                self._combined[bb] = 2.0 / max(0.001, denom) if denom > 0 else self.INF
            elif d_cg < self.INF:
                self._combined[bb] = d_cg
            elif d_bb < self.INF:
                self._combined[bb] = d_bb
            else:
                self._combined[bb] = self.INF

    # ---- 种子评分 ----
    def seed_distance(self,
                      covered_blocks: List[int]) -> float:
        """计算种子到目标区域的平均距离。

        距离 = 所有被覆盖块中combined距离的调和平均。
        距离越小 -> 种子越靠近目标。
        """
        if not self._computed:
            return self.INF

        valid = [self._combined.get(bb, self.INF)
                 for bb in covered_blocks
                 if bb in self._combined]
        if not valid:
            return self.INF

        # 调和平均（对outlier有鲁棒性）
        reciprocals = [1.0 / max(0.001, d) for d in valid]
        return len(reciprocals) / sum(reciprocals)

    def score_seed(self, seed_id: str,
                   covered_blocks: List[int],
                   new_to_target: bool = False) -> float:
        """返回种子能量 [0.1, 10.0]。

        距离越小->能量越高；新发现目标路径->额外2x加成。
        公式: energy = 10 * 1/(1+d) * (2.0 if new_to_target else 1.0)
        """
        dist = self.seed_distance(covered_blocks)
        if dist >= self.INF:
            base = 0.3
        else:
            base = 10.0 / (1.0 + dist)
        boost = 2.0 if new_to_target else 1.0
        energy = base * boost
        self._seed_energy[seed_id] = energy
        self._round += 1
        return max(0.1, min(10.0, energy))

    def select_best_seed(self, seeds: Dict[str, List[int]]
                         ) -> Optional[str]:
        """从种子池中选出距离最近的种子（能量最高）。"""
        if not seeds:
            return None
        best_id = None
        best_score = self.INF
        for sid, blocks in seeds.items():
            d = self.seed_distance(blocks)
            if d < best_score:
                best_score = d
                best_id = sid
        return best_id

    # ---- 路径引导变异 ----
    def guide_mutation(self, seed: bytearray,
                       uncovered_target_blocks: Set[int]) -> bytes:
        """定向变异: 偏向修改可能影响未到达目标的字节偏移。

        简化策略: 对种子中高熵区域（更可能对应分支条件）做密集变异。
        """
        # 未实现完整数据流追踪 -> 回退到均匀变异
        # 完整实现需要输入-比较指令的映射
        import random
        rounds = max(1, min(32, len(seed) // 8))
        for _ in range(rounds):
            idx = random.randint(0, len(seed) - 1)
            seed[idx] ^= (1 << random.randint(0, 7))
        return bytes(seed)

    # ---- 距离热力图 ----
    def distance_report(self, top_k: int = 20) -> Dict[str, Any]:
        """返回距离最近的前K个BB和当前调度统计。"""
        sorted_bbs = sorted(
            [(bb, d) for bb, d in self._combined.items()
             if d < self.INF],
            key=lambda x: x[1])[:top_k]
        return {
            'target_funcs': sorted(self._target_funcs),
            'target_blocks': sorted(self._target_blocks),
            'funcs_with_cg_dist': len(self._cg_dist),
            'bbs_with_distance': len(self._combined),
            'closest_bbs': [
                {'bb': hex(bb), 'distance': round(d, 2)}
                for bb, d in sorted_bbs],
            'seed_energies': dict(sorted(
                self._seed_energy.items(),
                key=lambda x: -x[1])[:10]),
            'computed': self._computed,
        }

    def compute_all_distances(self) -> None:
        self.compute_distances()

    def get_bb_distance(self, bb_addr: int) -> float:
        return self._combined.get(bb_addr, self.INF)

    def is_target_reached(self, covered_blocks: List[int]) -> bool:
        return any(bb in self._target_blocks for bb in covered_blocks)


# ---------------------------------------------------------------------------
# 调用图距离的路径剪枝: BEACON风格层级近似
# 当调用图过大或无法完全加载时，使用层级编号近似CG距离。
# 对调用图中每个函数赋予(layer, index)坐标 ->
# 距离 ≈ |layer_a - layer_b| * layer_weight + |index_a - index_b|
# ---------------------------------------------------------------------------
def approximate_cg_distance(func_positions: Dict[str, Tuple[int, int]],
                           target: str) -> Dict[str, float]:
    if target not in func_positions:
        return {f: float('inf') for f in func_positions}

    target_layer, target_idx = func_positions[target]
    dists = {}
    for func, (layer, idx) in func_positions.items():
        if func == target:
            dists[func] = 0.0
            continue
        dists[func] = abs(layer - target_layer) * 3.0 + abs(idx - target_idx) * 1.0
    return dists


def quick_directed_seed_select(
        seeds: Dict[str, List[int]],
        bb_distances: Dict[int, float]) -> str:
    """便捷入口: 给定种子->覆盖块映射和BB距离表，选出最近种子。"""
    best = ""
    best_d = float('inf')
    for sid, blocks in seeds.items():
        dists = [bb_distances.get(bb, float('inf')) for bb in blocks]
        if dists:
            d = sum(dists) / len(dists)
            if d < best_d:
                best_d = d
                best = sid
    return best
