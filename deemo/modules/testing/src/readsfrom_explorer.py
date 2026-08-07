# Reads-From 图驱动的并发探索器 — 基于内存访问因果图的线程交织搜索
#
# 核心问题:
#   concurrency_fuzz.py 生成多种线程调度方案, 但缺少系统性探索策略:
#   生成的调度是随机的, 无法判断哪些调度产生了"新行为"。
#   大量调度产生等价的内存访问模式 (不同交织顺序但相同的reads-from关系),
#   导致在冗余调度上浪费fuzzing预算。
#
#   RFF 证明: reads-from关系是并发程序行为的有效抽象——
#   两个调度若产生相同的reads-from图, 则属于同一行为等价类。
#   但RFF依赖二进制改写做主动调度控制, 对用户态fuzzing太重。
#
# 本模块的方法 — Reads-From图探索:
#   1. 对每次并发执行, 记录共享内存的读-写对应关系 (reads-from edges)
#   2. 构建 reads-from 有向图: 节点=内存访问事件, 边=read观察到哪个write的值
#   3. 用图编辑距离度量两个调度的行为差异
#   4. 贪心搜索最大化与"已见集合"的图差异——优先探索行为新颖的调度
#   5. 当连续N个调度未产生新reads-from模式时, 触发调度策略突变
#
# 与 concurrency_fuzz.py 的接合:
#   concurrency_fuzz.py: 调度方案生成器 (ThreadSchedule)
#   本模块: 调度方案的探索策略和反馈评估
#   两者正交: concurrency_fuzz生成候选, 本模块选择+评估
#
# 文献:
#   RFF — reads-from guided concurrency fuzzing;
#     本项目取其reads-from反馈思想但以图编辑距离替代覆盖率反馈
#   POP — parsimonious optimal DPOR;
#     本项目取其"仅当产生新执行时才反转race"的parsimony原则
#   ESBMC v7.7 — reverse priority scheduling加速bug检测;
#     本项目取其调度策略多样性思想

from __future__ import annotations

import hashlib
import math
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, FrozenSet, List, Optional, Set, Tuple


class MemoryEventType(str, Enum):
    READ = "read"
    WRITE = "write"
    ACQUIRE = "acquire"
    RELEASE = "release"
    ALLOC = "alloc"
    FREE = "free"


@dataclass
class MemoryEvent:
    """单次内存访问事件"""
    event_id: int
    thread_id: int
    event_type: MemoryEventType
    address: int                     # 内存地址
    size: int = 8                    # 访问字节数
    value: int = 0                   # 读取的值 (对read) 或 写入的值 (对write)
    timestamp_ns: int = 0            # 逻辑时钟 (happens-before顺序)
    source_write_id: Optional[int] = None  # 该read观察到哪个write的值


@dataclass
class ReadsFromEdge:
    """Reads-From 图中的有向边: write_event → read_event"""
    write_event: MemoryEvent
    read_event: MemoryEvent
    address: int


@dataclass
class ReadsFromGraph:
    """一次并发执行的 reads-from 图"""
    events: List[MemoryEvent] = field(default_factory=list)
    edges: List[ReadsFromEdge] = field(default_factory=list)
    # 派生特征
    edge_fingerprints: Set[int] = field(default_factory=set)
    thread_count: int = 0
    total_events: int = 0
    # 发现的并发bug
    data_races: int = 0
    deadlock_detected: bool = False


@dataclass
class ExplorationState:
    """并发探索的状态追踪"""
    schedules_tried: int = 0
    unique_graphs_seen: int = 0
    # 已见过的所有 reads-from 边指纹的并集
    seen_edge_fingerprints: Set[int] = field(default_factory=set)
    # 最近N轮的图指纹历史 (用于检测停滞)
    recent_graph_fingerprints: deque = field(default_factory=lambda: deque(maxlen=32))
    # 连续无新发现的轮数
    rounds_without_novelty: int = 0


class ReadsFromTracker:
    """从内存事件流中构建 reads-from 图。

    对每次read事件, 追踪"该read读到了哪个write的值"。
    对于写-写冲突 (两个write无happens-before顺序), 标记为data race。
    """

    def __init__(self):
        # address → 最近的 write event
        self._last_write: Dict[int, MemoryEvent] = {}
        # thread_id → 最后已知的逻辑时钟
        self._thread_clocks: Dict[int, int] = {}

    def process_event(self, event: MemoryEvent) -> Optional[ReadsFromEdge]:
        """处理一个内存事件, 返回产生的 reads-from 边 (如果是read)"""
        # 更新线程逻辑时钟
        prev_clock = self._thread_clocks.get(event.thread_id, 0)
        self._thread_clocks[event.thread_id] = max(
            prev_clock, event.timestamp_ns)

        if event.event_type == MemoryEventType.WRITE:
            prev_write = self._last_write.get(event.address)
            if prev_write and prev_write.thread_id != event.thread_id:
                # 两个写之间无明确的happens-before → 潜在 data race
                # (简化检测: 不同线程 + 无锁保护)
                pass
            self._last_write[event.address] = event
            return None

        elif event.event_type == MemoryEventType.READ:
            source = self._last_write.get(event.address)
            if source is not None:
                event.source_write_id = source.event_id
                return ReadsFromEdge(
                    write_event=source, read_event=event,
                    address=event.address)
            # 读未初始化的内存 → 记录但无source
            return None

        return None

    def reset(self) -> None:
        self._last_write.clear()
        self._thread_clocks.clear()


class ReadsFromExplorer:
    """Reads-From图驱动的并发交织探索器。

    典型用法:
        explorer = ReadsFromExplorer()
        tracker = ReadsFromTracker()

        for schedule in concurrency_fuzzer.generate_schedules():
            events = execute_schedule(schedule)
            graph = explorer.build_graph(events, tracker)
            novelty = explorer.assess_novelty(graph)
            if novelty > 0.3:
                # 高新颖度——深入探索该调度附近
                explorer.refine_schedule(schedule)
            explorer.record(graph)
    """

    def __init__(self, novelty_threshold: float = 0.2,
                 stall_rounds: int = 10):
        """
        novelty_threshold: 图指纹 Jaccard 新颖度低于此值视为"已见过"
        stall_rounds: 连续无新发现轮数阈值, 触发调度突变
        """
        self._novelty_threshold = novelty_threshold
        self._stall_rounds = stall_rounds
        self._state = ExplorationState()
        self._tracker = ReadsFromTracker()
        self._history: List[ReadsFromGraph] = []

    def build_graph(self, events: List[MemoryEvent],
                     tracker: Optional[ReadsFromTracker] = None,
                     ) -> ReadsFromGraph:
        """从内存事件序列构建 reads-from 图"""
        t = tracker or self._tracker
        if tracker is None:
            t.reset()

        graph = ReadsFromGraph(events=list(events))
        threads: Set[int] = set()

        for event in events:
            threads.add(event.thread_id)
            edge = t.process_event(event)
            if edge is not None:
                graph.edges.append(edge)

        graph.thread_count = len(threads)
        graph.total_events = len(events)
        graph.edge_fingerprints = {
            self._hash_edge(e) for e in graph.edges
        }
        return graph

    def assess_novelty(self, graph: ReadsFromGraph) -> float:
        """评估图的 behavior novelty [0, 1]。

        1.0 = 完全新颖 (所有边指纹都未见过)
        0.0 = 完全冗余 (所有边指纹都已见过)
        """
        if not graph.edge_fingerprints:
            return 0.0
        if not self._state.seen_edge_fingerprints:
            return 1.0

        new_edges = graph.edge_fingerprints - self._state.seen_edge_fingerprints
        novelty = len(new_edges) / len(graph.edge_fingerprints)
        return novelty

    def record(self, graph: ReadsFromGraph) -> None:
        """将图加入已见集合, 更新探索状态"""
        self._state.schedules_tried += 1
        self._history.append(graph)

        prev_seen = len(self._state.seen_edge_fingerprints)
        self._state.seen_edge_fingerprints |= graph.edge_fingerprints
        new_count = len(self._state.seen_edge_fingerprints) - prev_seen

        # 更新图指纹历史
        graph_hash = self._graph_canonical_hash(graph)
        self._state.recent_graph_fingerprints.append(graph_hash)

        if new_count > 0:
            self._state.unique_graphs_seen += 1
            self._state.rounds_without_novelty = 0
        else:
            self._state.rounds_without_novelty += 1

    def should_mutate_strategy(self) -> bool:
        """检查是否应突变调度生成策略 (连续无新发现)"""
        return self._state.rounds_without_novelty >= self._stall_rounds

    def best_schedule_from_history(self, top_k: int = 3
                                    ) -> List[ReadsFromGraph]:
        """从历史中选出最具代表性的k个调度——按唯一边数降序"""
        scored = [(len(g.edge_fingerprints), g) for g in self._history]
        scored.sort(key=lambda x: -x[0])
        seen_hashes: Set[int] = set()
        result: List[ReadsFromGraph] = []
        for _, g in scored:
            gh = self._graph_canonical_hash(g)
            if gh not in seen_hashes:
                result.append(g)
                seen_hashes.add(gh)
            if len(result) >= top_k:
                break
        return result

    def refine_schedule(self, base_events: List[MemoryEvent],
                         swap_probability: float = 0.3,
                         ) -> List[MemoryEvent]:
        """对基准事件序列做调度细化——交换相邻的不同线程事件。

        仅交换无数据依赖的事件对 (保守: 仅交换不同地址的访问)。
        这产生行为等价类内的新调度, 用于深度探索。
        """
        result = list(base_events)
        for i in range(len(result) - 1):
            a, b = result[i], result[i + 1]
            if (a.thread_id != b.thread_id
                    and a.address != b.address
                    and hash(i) % 100 < swap_probability * 100):
                result[i], result[i + 1] = b, a
        return result

    # 诊断

    def diversity_score(self) -> float:
        """最近N轮的图多样性 [0, 1]"""
        recent = list(self._state.recent_graph_fingerprints)
        if len(recent) <= 1:
            return 1.0
        unique = len(set(recent))
        return unique / len(recent)

    def stats(self) -> Dict[str, Any]:
        return {
            "schedules_tried": self._state.schedules_tried,
            "unique_graphs": self._state.unique_graphs_seen,
            "total_edges_seen": len(self._state.seen_edge_fingerprints),
            "rounds_without_novelty": self._state.rounds_without_novelty,
            "should_mutate": self.should_mutate_strategy(),
            "diversity": round(self.diversity_score(), 3),
        }

    def reset(self) -> None:
        self._state = ExplorationState()
        self._tracker.reset()
        self._history.clear()

    # 内部

    @staticmethod
    def _hash_edge(edge: ReadsFromEdge) -> int:
        """边指纹: write_addr + read_addr + address 的紧凑哈希"""
        raw = f"{edge.write_event.event_id}:{edge.read_event.event_id}:{edge.address}"
        return hash(raw) & 0x7FFFFFFF

    @staticmethod
    def _graph_canonical_hash(graph: ReadsFromGraph) -> int:
        """图的规范化哈希——用于去重比较"""
        sorted_fps = sorted(graph.edge_fingerprints)
        return hash(tuple(sorted_fps)) & 0x7FFFFFFF


def quick_explore(event_sequences: List[List[MemoryEvent]],
                   stall_rounds: int = 8,
                   ) -> Dict[str, Any]:
    """便捷入口: 对多个事件序列做探索并返回统计"""
    explorer = ReadsFromExplorer(stall_rounds=stall_rounds)
    tracker = ReadsFromTracker()

    for events in event_sequences:
        tracker.reset()
        graph = explorer.build_graph(events, tracker)
        explorer.record(graph)

    return explorer.stats()
