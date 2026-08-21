#                          路径指纹 vs 每个候选的指纹, 而非全 O(N²) 比较
#
# 多样性感知的工作窃取 — 在分布式符号执行中避免冗余探索。
#
# WorkStealingCoordinator (work_stealing_coordinator.py) 按 least_loaded 选择
# 偷取目标, 用 pending_fork_points 做 tie-break。这在以下场景产生系统性浪费:
#   节点 A 和节点 B 各自独立探索了语义等价但结构细微不同的两条路径——
#   两者都在同一个函数的同一片代码区域中打转。B 空闲后向 A 偷取任务,
#   但 A 分配的任务恰好与 B 已经穷尽的路径高度相似——B 浪费计算资源
#   重新探索了一片已经（在语义上）被覆盖的区域。
#
# 本模块在窃取协议中增加多样性度量:
#   (a) 每个节点维护自身路径集的 SimHash 聚合指纹 (bitwise OR)
#   (b) 被窃取方 (victim) 在收到窃取请求时, 不随意分配任务——
#       而是从自己的待处理队列中选择与窃取方 (thief) 指纹
#       汉明距离最大的 K 个候选 (即最不相似的任务)
#   (c) 窃取方接收后更新自身聚合指纹——下轮窃取自然倾向于不同的任务
#
# 开销: 每条路径计算一次 64-bit SimHash (已在 path_diversity_core 中完成),
# SimHash 聚合为 O(k) 的 bitwise OR, 指纹比较为 O(1) 汉明距离。
# 总增量开销 < 1ms/窃取——在毫秒级的网络 RTT 面前可忽略。
#
# work_stealing_coordinator.py — 本项目的基础窃取框架
# Blumofe, R. & Leiserson, C. "Scheduling multithreaded computations
#      by work stealing." JACM 46.5: 720-748.
#      — 工作窃取的理论基础。本项目在其随机窃取策略上增加多样性度量,
#      将"任意任务"替换为"最不相似于 thief 已有路径集合的任务"

import hashlib
import math
import threading
from typing import Dict, List, Tuple, Set, Optional
from dataclasses import dataclass, field
from collections import defaultdict


@dataclass
class StealableTask:
    """一个可被窃取的符号执行任务——含路径多样性指纹。"""
    task_id: str
    path_id: str          # 关联的符号执行路径 ID
    simhash_sig: int      # 路径的 64-bit SimHash 指纹
    pending_fork_points: int = 0
    constraint_count: int = 0
    depth: int = 0


@dataclass
class NodeDiversityState:
    """节点的多样性状态快照——随心跳广播。"""
    node_id: str
    aggregate_simhash: int     # 所有活跃路径 SimHash 的 bitwise OR
    active_path_count: int
    solver_utilization: float
    pending_task_count: int
    last_updated: float = 0.0


def _compute_path_simhash(path_constraints: List[str],
                          path_depth: int = 0) -> int:
    """从路径约束计算 64-bit SimHash 指纹。

    与 path_diversity_core._simhash 保持兼容——使用 SHA-256 哈希投票。
    此处独立实现以避免跨模块依赖: 分布式节点可能不加载完整的符号执行模块。
    """
    counts = [0] * 64
    # 特征: 约束文本 + 深度
    feature_str = f"depth:{path_depth}|" + "|".join(path_constraints[:20])
    h = hashlib.sha256(feature_str.encode()).hexdigest()
    h_int = int(h, 16)
    for b in range(64):
        if (h_int >> b) & 1:
            counts[b] += 1
        else:
            counts[b] -= 1
    result = 0
    for b in range(64):
        if counts[b] > 0:
            result |= (1 << b)
    return result


def _hamming_distance(a: int, b: int) -> int:
    x = a ^ b
    dist = 0
    while x:
        dist += 1
        x &= x - 1
    return dist


class DiversityAwareTaskSelector:
    """多样性感知的任务选择器——在被窃取方运行。

    窃取到达时, 从 victim 的待处理队列中选出与 thief 指纹
    差异最大的任务——最大化窃取带来的边际多样性增益。
    """

    def __init__(self, max_candidates_to_compare: int = 50):
        self._max_candidates = max_candidates_to_compare
        # 已知节点指纹缓存——避免每次窃取都重新计算
        self._peer_fingerprints: Dict[str, int] = {}

    def update_peer_fingerprint(self, node_id: str, aggregate_simhash: int):
        """更新已知对等节点的聚合指纹。"""
        self._peer_fingerprints[node_id] = aggregate_simhash

    def select_diverse_tasks(
        self,
        available_tasks: List[StealableTask],
        thief_node_id: str,
        thief_aggregate_simhash: Optional[int] = None,
        count: int = 3,
    ) -> List[StealableTask]:
        """从可用任务中选择与 thief 现有路径差异最大的 count 个。"""
        if not available_tasks:
            return []

        # 获取 thief 指纹——优先用传入的实时值, 回退到缓存
        thief_sig = thief_aggregate_simhash
        if thief_sig is None:
            thief_sig = self._peer_fingerprints.get(thief_node_id, 0)

        # 若 thief 尚无指纹 (冷启动), 回退到 pending_fork_points 选择
        if thief_sig == 0:
            sorted_by_forks = sorted(
                available_tasks, key=lambda t: -t.pending_fork_points
            )
            return sorted_by_forks[:count]

        # 对候选任务计算与 thief 指纹的汉明距离
        # 仅评估前 max_candidates 个——典型队列深度 >1000, 全量排序开销大
        candidates = available_tasks[:self._max_candidates]
        scored = []
        for task in candidates:
            dist = _hamming_distance(task.simhash_sig, thief_sig)
            # 综合评分: 汉明距离 (60%) + pending_fork_points (40%)
            # fork_points 归一化到 [0, 64] 与汉明距离同比重
            fork_score = min(64, task.pending_fork_points) * 0.4
            diversity_score = dist * 0.6 + fork_score
            scored.append((task, diversity_score))

        scored.sort(key=lambda x: -x[1])
        return [task for task, _ in scored[:count]]


class DiversityAwareWorkStealingCoordinator:
    """多样性感知的分布式工作窃取协调器。

    在 WorkStealingCoordinator 的基础上增加路径多样性度量。
    每个节点维护自身路径集的聚合 SimHash 指纹,
    在窃取时优先选择与自身已有路径最不相似的任务。
    """

    def __init__(self, node_id: str):
        self._node_id = node_id
        # 本节点当前所有路径的 SimHash bitwise OR
        self._aggregate_simhash: int = 0
        self._active_path_count: int = 0
        # 本节点的可窃取任务队列
        self._task_queue: List[StealableTask] = []
        # 任务选择器
        self._selector = DiversityAwareTaskSelector()
        # 已知对等节点的状态
        self._peer_states: Dict[str, NodeDiversityState] = {}
        self._lock = threading.Lock()

    @property
    def aggregate_fingerprint(self) -> int:
        """当前节点的聚合路径指纹。"""
        return self._aggregate_simhash

    def register_path(self, path_id: str, constraints: List[str],
                      depth: int = 0, fork_points: int = 0):
        """向本节点的路径集中注册一条新路径——更新聚合指纹。

        聚合策略: bitwise OR——保守但快速。OR 的语义是"此节点探索过的
        所有路径的特征位合集"。OR 从不缩小——符合直觉: 节点探索越多,
        指纹覆盖面越广, 与"已饱和"节点的汉明距离自然地趋于 0。
        """
        sig = _compute_path_simhash(constraints, depth)
        task = StealableTask(
            task_id=f"{self._node_id}:{path_id}",
            path_id=path_id,
            simhash_sig=sig,
            pending_fork_points=fork_points,
            constraint_count=len(constraints),
            depth=depth,
        )

        with self._lock:
            self._aggregate_simhash |= sig
            self._active_path_count += 1
            self._task_queue.append(task)

            # 队列长度控制——超过 200 个任务时清理已完成的任务
            # (简单策略: 仅保留最近 150 个, 丢弃最老的 50 个)
            if len(self._task_queue) > 200:
                self._task_queue = self._task_queue[-150:]

    def remove_path(self, path_id: str):
        """移除已完成/剪枝的路径——不修改聚合指纹。

        OR 的不可逆性: 移除路径无法从 OR 指纹中"减去"其 SimHash 位。
        设计上接受此误差——因为 OR 的语义是"曾探索过", 而非"当前正探索"。
        若需精确的"当前活跃"指纹, 可从零重建——开销 O(n) 但 n ≤ 200,
        可在窃取响应时按需计算。
        """
        with self._lock:
            self._active_path_count = max(0, self._active_path_count - 1)
            self._task_queue = [
                t for t in self._task_queue if t.path_id != path_id
            ]

    def get_state(self) -> NodeDiversityState:
        """返回本节点的当前多样性状态——用于心跳广播。"""
        with self._lock:
            return NodeDiversityState(
                node_id=self._node_id,
                aggregate_simhash=self._aggregate_simhash,
                active_path_count=self._active_path_count,
                solver_utilization=0.0,  # 由调用方填充
                pending_task_count=len(self._task_queue),
                last_updated=0.0,  # 由调用方填充时间戳
            )

    def receive_peer_heartbeat(self, state: NodeDiversityState):
        """接收对等节点的心跳——更新本地指纹缓存。"""
        self._peer_states[state.node_id] = state
        self._selector.update_peer_fingerprint(
            state.node_id, state.aggregate_simhash
        )

    def select_tasks_for_thief(
        self, thief_node_id: str, count: int = 3
    ) -> List[StealableTask]:
        """被窃取方调用——从自身队列中选择对 thief 最有价值的任务。

        选择策略: 与 thief 的聚合指纹汉明距离最大的任务——
        即 thief 最不可能已经探索过的语义空间。
        """
        with self._lock:
            thief_state = self._peer_states.get(thief_node_id)
            thief_sig = thief_state.aggregate_simhash if thief_state else None
            return self._selector.select_diverse_tasks(
                available_tasks=list(self._task_queue),
                thief_node_id=thief_node_id,
                thief_aggregate_simhash=thief_sig,
                count=count,
            )

    def compute_thief_gain_estimate(
        self, thief_node_id: str, task_count: int = 3
    ) -> float:
        """预估窃取方在接收 task_count 个任务后的多样性增益。

        增益 = (thief 聚合指纹 | 被盗任务 SimHash) 与 (thief 原有指纹)
        的新增位数 / 64 ——即 thief 将获得多少新的特征位。

        增益 < 0.05 → 不推荐窃取 (thief 已有非常相似的路径)。
        """
        with self._lock:
            thief_state = self._peer_states.get(thief_node_id)
            thief_sig = thief_state.aggregate_simhash if thief_state else 0
            if thief_sig == 0:
                return 1.0  # 冷启动——任何任务都有增益

            selected = self.select_tasks_for_thief(thief_node_id, task_count)
            if not selected:
                return 0.0

            # 计算被选任务的聚合 SimHash
            task_or = 0
            for task in selected:
                task_or |= task.simhash_sig

            # 新位 = thief 目前没有但被盗任务有的位
            new_bits = task_or & (~thief_sig)
            new_bit_count = bin(new_bits).count('1')
            return new_bit_count / 64.0

    def get_peer_diversity_map(self) -> Dict[str, int]:
        """返回本节点与各对等节点的汉明距离映射。

        距离大 → 两节点探索了不同的语义空间 → 互窃价值高。
        距离小 → 两节点在相同区域打转 → 窃取意义不大。
        """
        with self._lock:
            result = {}
            for nid, state in self._peer_states.items():
                dist = _hamming_distance(
                    self._aggregate_simhash, state.aggregate_simhash
                )
                result[nid] = dist
            return dict(sorted(result.items(), key=lambda x: -x[1]))
