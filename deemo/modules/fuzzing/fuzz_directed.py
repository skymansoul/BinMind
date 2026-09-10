"""定向模糊测试工具集 -- 目标引导的代码区域聚焦。

  Hawkeye                -- 期望定向灰盒模糊测试器
  RDFuzz   (Zotero)                          -- 交织调度+优化变异的加速定向模糊测试
  AFLGo                    -- 基于模拟退火的定向灰盒模糊测试
  AFLRun               -- 无偏多目标能量分配+路径多样性
  One Fuzz Doesn't Fit All (Zotero)          -- 目标定制化程序状态限制
  SemFuzz  (Zotero)                          -- 基于语义的 PoC 漏洞利用自动生成

与常规 (非定向) 模糊测试的区别:
  常规 Fuzzing: 最大化全局覆盖率
  定向 Fuzzing: 尽快到达指定的代码位置 (如 patch 位置、CVE fix 位置)

  1. 距离计算: 控制流图 (CFG) 上从当前基本块到目标的最短距离
  2. 种子评分: 距离越近 → 分数越高 → 越可能被选中
  3. 变异偏向: 对靠近目标的种子给予更激进的变异参数
"""

import hashlib
import heapq
import json
import logging
import math
import random
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)

@dataclass
class TargetSite:
    """模糊测试的目标代码位置。"""
    address: int
    function_name: str = ""
    label: str = ""           # "CVE-2024-XXXX patch", "security_critical_checksum"
    weight: float = 1.0       # 多目标场景下的目标权重
    line_number: int = 0
    source_file: str = ""

@dataclass
class CFGNode:
    """控制流图节点 (基本块)。"""
    address: int
    successors: List[int] = field(default_factory=list)
    func_name: str = ""
    distance_to_target: float = float('inf')

class DistanceCalculator:
    """CFG 上的距离计算引擎。

    从目标位置开始反向 BFS, 计算每个基本块到最近目标的最短距离。
    距离定义: 调用图 (CG) 上的函数间距离 + 控制流图 (CFG) 上的块间距离。

    Hawkeye 原始论文使用 harmonic distance, 此处实现其简化版。
    """

    def __init__(self):
        self._cfg: Dict[int, CFGNode] = {}
        self._call_graph: Dict[str, List[str]] = defaultdict(list)
        self._targets: List[TargetSite] = []

    def add_node(self, addr: int, successors: List[int],
                 func_name: str = "") -> None:
        self._cfg[addr] = CFGNode(
            address=addr, successors=successors, func_name=func_name
        )

    def add_call_edge(self, caller_func: str, callee_func: str) -> None:
        self._call_graph[caller_func].append(callee_func)

    def set_targets(self, targets: List[TargetSite]) -> None:
        self._targets = targets

    def compute_distances(self) -> Dict[int, float]:
        """计算所有基本块到最近目标的 harmonic distance。

        harmonic_distance(bb) = 0 (若 bb 是目标)
        否则 = Σ 1 / (1 + d(bb, t)) 对所有目标 t

        Hawkeye 强调 harmonic mean 比 minimum 更好地反映"多重目标覆盖"。
        """
        if not self._targets or not self._cfg:
            return {}

        target_addrs = {t.address for t in self._targets}

        # 从所有目标开始的 BFS
        distances: Dict[int, float] = {}
        queue = deque()

        for t_addr in target_addrs:
            if t_addr in self._cfg:
                distances[t_addr] = 0.0
                queue.append(t_addr)

        # 反向 BFS: 沿着 predecessor 方向
        # 因我们没有显式存储 preds, 需要先建立逆图
        reverse_edges: Dict[int, List[int]] = defaultdict(list)
        for addr, node in self._cfg.items():
            for succ in node.successors:
                reverse_edges[succ].append(addr)

        while queue:
            current = queue.popleft()
            cur_dist = distances[current]

            for pred in reverse_edges.get(current, []):
                if pred not in distances:
                    distances[pred] = cur_dist + 1.0
                    queue.append(pred)

        # 对未到达的块, 设为无穷大
        for addr in self._cfg:
            if addr not in distances:
                distances[addr] = float('inf')

        return distances

    def seed_distance(self, seed_edges: Set[int],
                      block_distances: Dict[int, float]) -> float:
        if not seed_edges:
            return float('inf')

        # 将 edge_id 反向映射为基本块地址 (简化: edge_id 就是 src_bb)
        harmonic_sum = 0.0
        count = 0
        for edge_id in seed_edges:
            dist = block_distances.get(edge_id, float('inf'))
            if dist < float('inf'):
                harmonic_sum += 1.0 / (1.0 + dist)
                count += 1

        if count == 0:
            return float('inf')

        return count / harmonic_sum if harmonic_sum > 0 else 0.0

class DirectedSeedSelector:
    """定向模糊测试的种子选择器。

    基于距离和多种启发式对种子队列排序, 优先选择
    距离目标更近且具有路径多样性的种子。
    """

    def __init__(self, distance_calc: DistanceCalculator):
        self._dist_calc = distance_calc
        self._block_distances: Dict[int, float] = {}
        self._seed_scores: Dict[str, float] = {}

    def update_distances(self) -> None:
        self._block_distances = self._dist_calc.compute_distances()

    def score_seed(self, seed_id: str, seed_edges: Set[int],
                   is_new: bool = False) -> float:
        """综合评分: 距离 + 新颖性 + 执行效率。

        AFLGo 使用模拟退火: 初期注重距离, 后期注重覆盖。
        此处用退火因子 α 随时间衰减, 实现类似效果。
        """
        dist = self._dist_calc.seed_distance(seed_edges, self._block_distances)

        # 距离分: 越近越高
        if dist < float('inf') and dist > 0:
            dist_score = 1.0 / (1.0 + dist)
        else:
            dist_score = 0.0

        # 覆盖分: 边越多越高
        cov_score = math.log2(1 + len(seed_edges)) / 15.0

        # 新颖性加分
        novelty_bonus = 0.2 if is_new else 0.0

        # 退火因子 (简化: 使用固定 0.6 weight 给距离)
        score = 0.6 * dist_score + 0.3 * cov_score + novelty_bonus

        self._seed_scores[seed_id] = score
        return score

    def select_top(self, seed_ids: List[str], top_n: int = 10) -> List[str]:
        """选择距离最近的前 N 个种子。"""
        scored = [
            (sid, self._seed_scores.get(sid, 0.0))
            for sid in seed_ids
        ]
        scored.sort(key=lambda x: x[1], reverse=True)
        return [sid for sid, _ in scored[:top_n]]

    # 目标提取器: 从补丁/CVE报告自动提取目标地址

class TargetExtractor:
    """从多种来源自动提取模糊测试目标。

    支持:
      - CVE patch diff: 提取新增/修改的基本块地址
      - Ghidra/IDA 导出的标记地址
      - 用户自定义的 JSON 目标列表
    """

    @staticmethod
    def from_diff(diff_text: str, binary_base: int = 0x400000) -> List[TargetSite]:
        """从 git diff 文本中提取目标。

        匹配模式: @@ -X,Y +A,B @@
        A 区域的代码即为新增/修改的代码, 应作为定向 fuzzing 目标。
        """
        import re
        targets = []
        for match in re.finditer(
            r'@@\s+-(\d+),(\d+)\s+\+(\d+),(\d+)\s+@@',
            diff_text
        ):
            new_start = int(match.group(3))
            new_count = int(match.group(4))
            # 近似: 每行对应一个基本块地址
            for i in range(min(new_count, 20)):
                addr = binary_base + new_start + i * 4
                targets.append(TargetSite(
                    address=addr,
                    label=f"patch_region_line_{new_start + i}",
                    weight=1.0,
                ))
        return targets

    @staticmethod
    def from_json(json_path: str) -> List[TargetSite]:
        """从 JSON 文件加载目标列表。"""
        with open(json_path, 'r', encoding='utf-8') as f:
            data = json.load(f)

        targets = []
        for item in data if isinstance(data, list) else data.get("targets", []):
            targets.append(TargetSite(
                address=item.get("address", 0),
                function_name=item.get("function", ""),
                label=item.get("label", ""),
                weight=item.get("weight", 1.0),
                line_number=item.get("line", 0),
                source_file=item.get("file", ""),
            ))
        return targets

    @staticmethod
    def from_cve_list(cve_ids: List[str]) -> List[TargetSite]:
        """从 CVE ID 列表生成提示 (实际地址需外部查表)。

        返回占位符 TargetSite, 标注 CVE ID 供后续匹配。
        """
        return [
            TargetSite(address=0, label=cve_id, weight=1.0)
            for cve_id in cve_ids
        ]

    # 定向模糊测试门面

class DirectedFuzzer:
    """定向模糊测试协调器。

    整合距离计算、种子评分和调度策略,
    作为常规模糊测试回路的外挂模块运行。
    """

    def __init__(self, target_sites: List[TargetSite]):
        self._dist_calc = DistanceCalculator()
        self._selector = DirectedSeedSelector(self._dist_calc)
        self._dist_calc.set_targets(target_sites)

    def configure_cfg(self, nodes: List[Tuple[int, List[int], str]]) -> None:
        """配置 CFG: [(addr, [successors], func_name), ...]"""
        for addr, succs, fname in nodes:
            self._dist_calc.add_node(addr, succs, fname)
        self._selector.update_distances()

    def rank_seeds(self, seeds: List[Tuple[str, Set[int], bool]]) -> List[Tuple[str, float]]:
        """对种子列表进行排序, 返回 [(seed_id, score), ...]。

        seeds: [(seed_id, edge_set, is_new), ...]
        """
        scored = []
        for sid, edges, is_new in seeds:
            score = self._selector.score_seed(sid, edges, is_new)
            scored.append((sid, score))
        scored.sort(key=lambda x: x[1], reverse=True)
        return scored

    def distance_stats(self) -> Dict:
        """距离分布统计。"""
        dists = self._dist_calc.compute_distances()
        finite = [d for d in dists.values() if d < float('inf')]
        if not finite:
            return {"reachable_blocks": 0, "total_blocks": len(dists)}
        return {
            "reachable_blocks": len(finite),
            "total_blocks": len(dists),
            "min_distance": min(finite),
            "max_distance": max(finite),
            "avg_distance": sum(finite) / len(finite),
            "blocks_within_5": sum(1 for d in finite if d <= 5),
        }
