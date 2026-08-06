# 因果污点传播图 — 基于差分数据流的崩溃根因链重建
#
# 核心洞察:
#   crash_cluster.py 按栈哈希分组崩溃——这是现象聚类, 不回答"哪些输入字节
#   导致了崩溃"。Sagitta (ACSAC 2025) 以在线插桩做数据流差分定位根因,
#   但依赖运行时插桩且仅处理单对输入。
#
#   本模块的方法:
#     1. 对崩溃输入和其未崩溃父输入分别做 subreg_taint 级污点追踪
#     2. 计算两个污点图的差分——提取仅在崩溃路径上传播的因果边
#     3. 归约因果边为 InputOffset→CrashPoint 的最小因果链
#
# 关键技术特征:
#   - 离线污点差分: 不依赖在线插桩, 利用 trace 重放
#   - 因果归约: 从全量污点图提取仅与崩溃相关的子图
#     (类似 Pearl do-calculus——仅保留区分崩溃/非崩溃的变量)
#   - 根因字节定位: 按 causal_flow 强度对输入字节排序
#
# 与 subreg_taint.py 的关系:
#   subreg_taint.py 提供逐指令的位级污点传播 (TaintBits)
#   本模块在其上构建: 多路径污点聚合、差分对比、因果图归约
#
# 参考文献:
#   Sagitta (Shinagawa et al. ACSAC 2025) — 数据流差分用于崩溃根因分析;
#     本项目取其"差分数据流"概念, 但以离线 trace 重放 + 因果归约替代
#     在线插桩, 并利用 subreg_taint 的寄存器别名精度提升分析粒度
#   BENZENE (IEEE S&P 2024 Distinguished Paper) — 欠约束状态变异生成
#     对比执行对; 本项目取其"对比执行"范式, 但以污点图替代全状态变异
#   RACING (USENIX Security 2024) — 强化学习+互信息做根因关联; 本项目
#     取其"消偏采样"思想, 以污点差分替代统计相关

from __future__ import annotations

import hashlib
import math
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any, Dict, FrozenSet, List, Optional, Set, Tuple

# 桥接 subreg_taint.py: 消费 SubRegTaintTracker 的污点状态
# SubRegTaintTracker 提供 _gpr (List[TaintBits]) 和 _instructions_executed,
# build_causal_report_from_tracker() 通过 duck-typing 消费这些属性
# 无需硬导入, 支持任何实现了相同接口的 tracker 对象


@dataclass
class TaintEdge:
    """污点图中的有向边: source → sink, 携带输入字节偏移的传播信息"""
    source_addr: int           # 源指令地址
    sink_addr: int             # 目标指令地址
    input_offsets: Set[int]    # 此边上传播的输入字节偏移集合
    register_name: str = ""    # 传播涉及的寄存器
    edge_type: str = "direct"  # direct | memory | implicit


@dataclass
class TaintGraph:
    """单次执行的污点传播图——节点为指令地址, 边为 taint 传播关系"""
    edges: List[TaintEdge] = field(default_factory=list)
    # crash site 标记
    crash_addr: int = 0
    crash_type: str = ""
    # 入口标记
    entry_addr: int = 0
    # 元信息
    input_hash: str = ""
    total_instructions: int = 0


@dataclass
class CausalChain:
    """从输入字节偏移到崩溃点的最小因果链

    这是归约后的结果——去除了与崩溃无关的污点传播边。
    """
    input_offset: int               # 根因输入字节偏移
    chain_addrs: List[int]           # 从输入消费到崩溃的指令地址序列
    confidence: float                # [0, 1] 因果置信度
    affected_registers: List[str]    # 链上涉及的寄存器
    crash_distance: int = 0          # 链上最后一条边到崩溃地址的指令距离
    is_direct_cause: bool = False    # 是否直接导致崩溃 (非传递)


@dataclass
class CausalTaintReport:
    """因果污点分析完整报告"""
    crash_id: str
    crash_type: str
    crash_addr: int
    total_causal_chains: int
    chains: List[CausalChain] = field(default_factory=list)
    # 根因字节范围: 对输入做最小修补即可消除崩溃的字节区间
    root_cause_byte_range: Tuple[int, int] = (0, 0)
    # 根因置信度
    root_cause_confidence: float = 0.0
    # 统计
    total_taint_edges_crash: int = 0
    total_taint_edges_parent: int = 0
    differential_edges: int = 0
    execution_time_s: float = 0.0
    summary: str = ""


class CausalTaintAnalyzer:
    """因果污点分析器——从崩溃/非崩溃执行对的污点图中提取根因链。

    使用模式:
        analyzer = CausalTaintAnalyzer()
        # 1. 摄入崩溃执行的污点图
        analyzer.ingest_crash_graph(crash_graph)
        # 2. 摄入父输入 (未崩溃) 的污点图
        analyzer.ingest_parent_graph(parent_graph)
        # 3. 差分 → 归约 → 生成根因链
        report = analyzer.analyze(crash_input=b"...", parent_input=b"...")
    """

    def __init__(self, min_confidence: float = 0.3):
        self._crash_graph: Optional[TaintGraph] = None
        self._parent_graph: Optional[TaintGraph] = None
        self._min_confidence = min_confidence

    def ingest_crash_graph(self, graph: TaintGraph) -> None:
        self._crash_graph = graph

    def ingest_parent_graph(self, graph: TaintGraph) -> None:
        self._parent_graph = graph

    def analyze(self,
                crash_input: bytes = b"",
                parent_input: bytes = b"",
                ) -> CausalTaintReport:
        """主分析入口——差分污点图并归约为因果链"""
        t0 = time.perf_counter()

        if self._crash_graph is None:
            return CausalTaintReport(
                crash_id="", crash_type="", crash_addr=0,
                total_causal_chains=0,
                execution_time_s=time.perf_counter() - t0,
                summary="无崩溃污点图",
            )

        crash_graph = self._crash_graph
        parent_graph = self._parent_graph

        # Step 1: 提取仅存在于崩溃路径的边 (差分边集)
        crash_edge_set = self._edge_fingerprint(crash_graph.edges)
        parent_edge_set = (
            self._edge_fingerprint(parent_graph.edges)
            if parent_graph else set()
        )
        diff_edges = crash_edge_set - parent_edge_set

        # 同时提取崩溃特有的输入偏移传播
        crash_only_edges = [
            e for e in crash_graph.edges
            if self._edge_fingerprint([e]) != parent_edge_set
        ]

        # Step 2: 构建输入偏移 → 指令地址的因果映射
        offset_to_addrs: Dict[int, Set[int]] = defaultdict(set)
        for edge in crash_only_edges:
            for off in edge.input_offsets:
                offset_to_addrs[off].add(edge.sink_addr)

        # Step 3: 计算每个输入偏移的因果流强度
        # 因果流 = 传播路径上的边数 / 传播距离 (归一化)
        offset_flow: Dict[int, float] = {}
        for off, addrs in offset_to_addrs.items():
            # 找到从输入消费到崩溃点的最短传播距离
            min_dist = self._shortest_path_to_crash(
                crash_graph, addrs, crash_graph.crash_addr)
            if min_dist > 0:
                offset_flow[off] = len(addrs) / min_dist
            else:
                offset_flow[off] = float(len(addrs))

        # Step 4: 构建因果链——按因果流强度降序
        total_flow = sum(offset_flow.values()) or 1.0
        chains: List[CausalChain] = []
        for off, flow in sorted(offset_flow.items(), key=lambda x: -x[1]):
            addrs = sorted(offset_to_addrs[off])
            confidence = min(1.0, flow / max(1.0, total_flow * 0.1))

            if confidence < self._min_confidence:
                continue

            # 计算链到崩溃点的距离
            crash_dist = self._shortest_path_to_crash(
                crash_graph, addrs, crash_graph.crash_addr)

            # 提取涉及的寄存器
            regs = list({
                e.register_name
                for e in crash_only_edges
                if off in e.input_offsets and e.register_name
            })

            chains.append(CausalChain(
                input_offset=off,
                chain_addrs=addrs,
                confidence=round(confidence, 4),
                affected_registers=regs[:5],
                crash_distance=crash_dist,
                is_direct_cause=(crash_dist <= 5),
            ))

        # Step 5: 确定根因字节范围——最高置信度链的连续区间
        root_range = (0, 0)
        root_conf = 0.0
        if chains:
            # 按输入偏移合并相邻的因果链 (gap <= 4 字节视为同一根因区域)
            sorted_chains = sorted(chains, key=lambda c: c.input_offset)
            best_start = sorted_chains[0].input_offset
            best_end = best_start + 1
            best_sum_conf = sorted_chains[0].confidence

            cur_start = best_start
            cur_end = best_start + 1
            cur_sum = sorted_chains[0].confidence

            for i in range(1, len(sorted_chains)):
                prev = sorted_chains[i - 1]
                curr = sorted_chains[i]
                if curr.input_offset - prev.input_offset <= 4:
                    cur_end = curr.input_offset + 1
                    cur_sum += curr.confidence
                else:
                    if cur_sum > best_sum_conf:
                        best_start, best_end, best_sum_conf = cur_start, cur_end, cur_sum
                    cur_start = curr.input_offset
                    cur_end = curr.input_offset + 1
                    cur_sum = curr.confidence

            if cur_sum > best_sum_conf:
                best_start, best_end, best_sum_conf = cur_start, cur_end, cur_sum

            root_range = (best_start, best_end)
            root_conf = min(1.0, best_sum_conf / max(1.0, len(chains) * 0.5))

        # Step 6: 生成报告
        crash_id = hashlib.sha256(
            crash_input[:256] + str(crash_graph.crash_addr).encode()
        ).hexdigest()[:16]

        elapsed = time.perf_counter() - t0
        report = CausalTaintReport(
            crash_id=crash_id,
            crash_type=crash_graph.crash_type,
            crash_addr=crash_graph.crash_addr,
            total_causal_chains=len(chains),
            chains=chains,
            root_cause_byte_range=root_range,
            root_cause_confidence=root_conf,
            total_taint_edges_crash=len(crash_graph.edges),
            total_taint_edges_parent=len(parent_graph.edges) if parent_graph else 0,
            differential_edges=len(crash_only_edges),
            execution_time_s=elapsed,
        )
        report.summary = self._build_summary(report)
        return report

    # ---- 边指纹: 用于集合差分 ----

    @staticmethod
    def _edge_fingerprint(edges: List[TaintEdge]) -> Set[Tuple[int, int, str]]:
        """将污点边转化为可哈希的指纹 (source, sink, edge_type)"""
        return {
            (e.source_addr, e.sink_addr, e.edge_type)
            for e in edges
        }

    # ---- 最短路径: 从污染源到崩溃点 ----

    @staticmethod
    def _shortest_path_to_crash(graph: TaintGraph,
                                 source_addrs: Set[int],
                                 crash_addr: int) -> int:
        """BFS 从污染源地址集合到崩溃地址的最短距离"""
        if crash_addr == 0 or not source_addrs:
            return 999

        # 构建邻接表: source → [sinks]
        adj: Dict[int, List[int]] = defaultdict(list)
        for e in graph.edges:
            adj[e.source_addr].append(e.sink_addr)

        q = deque()
        dist: Dict[int, int] = {}
        for sa in source_addrs:
            q.append(sa)
            dist[sa] = 0

        while q:
            u = q.popleft()
            if u == crash_addr:
                return dist[u]
            for v in adj.get(u, []):
                if v not in dist:
                    dist[v] = dist[u] + 1
                    if dist[v] > 200:
                        continue
                    q.append(v)

        return 999

    @staticmethod
    def _build_summary(report: CausalTaintReport) -> str:
        lines = [
            f"因果污点分析: {report.crash_id}",
            f"崩溃类型: {report.crash_type} @ {report.crash_addr:#x}",
            f"因果链数: {report.total_causal_chains}",
            f"根因字节范围: [{report.root_cause_byte_range[0]}, "
            f"{report.root_cause_byte_range[1]}) "
            f"(置信度 {report.root_cause_confidence:.2f})",
        ]
        if report.chains:
            lines.append("主要因果链 (前 5):")
            for c in report.chains[:5]:
                marker = " [直接]" if c.is_direct_cause else ""
                lines.append(
                    f"  input[{c.input_offset}] → {len(c.chain_addrs)} 步 → "
                    f"crash-{c.crash_distance}{marker} "
                    f"(置信度 {c.confidence:.2f})")
        return "\n".join(lines)

    def stats(self) -> Dict[str, Any]:
        return {
            "has_crash_graph": self._crash_graph is not None,
            "has_parent_graph": self._parent_graph is not None,
            "crash_edges": len(self._crash_graph.edges) if self._crash_graph else 0,
        }

    def reset(self) -> None:
        self._crash_graph = None
        self._parent_graph = None


# ============================================================
# 污点图构建辅助: 从 trace 或 subreg_taint 状态构建 TaintGraph
# ============================================================

class TaintGraphBuilder:
    """从指令 trace 构建 TaintGraph——桥接 subreg_taint + 崩溃上下文。

    输入: 指令 trace (地址序列) + SubRegTaintTracker 的逐指令状态快照
    输出: TaintGraph (含所有 taint 传播边)

    构建算法:
      对 trace 中每条指令:
        1. 解析其源/目标操作数
        2. 查询 SubRegTaintTracker 在指令前后的状态
        3. 若 taint 从源操作数传播到目标操作数 -> 创建 TaintEdge
    """

    @staticmethod
    def from_trace_and_taint(
        trace_addrs: List[int],
        taint_snapshots: List[Dict[str, Set[int]]],
        crash_addr: int = 0,
        crash_type: str = "",
        entry_addr: int = 0,
    ) -> TaintGraph:
        """从 trace 地址序列和逐指令污点快照构建污点图。

        trace_addrs[i] 对应 taint_snapshots[i] (第 i 条指令执行后的污点状态)。
        快照格式: {register_name: {tainted_input_offsets}}
        """
        edges: List[TaintEdge] = []
        prev_tainted: Dict[str, Set[int]] = {}

        for i, (addr, snap) in enumerate(zip(trace_addrs, taint_snapshots)):
            # 比较前后快照: 若某寄存器的 taint 增加了输入偏移,
            # 则前一条指令将 taint 传播到了该寄存器
            for reg, offsets in snap.items():
                prev_offsets = prev_tainted.get(reg, set())
                new_offsets = offsets - prev_offsets
                if new_offsets and i > 0:
                    # 前一条指令将 new_offsets 传播到了 reg
                    edges.append(TaintEdge(
                        source_addr=trace_addrs[i - 1],
                        sink_addr=addr,
                        input_offsets=new_offsets,
                        register_name=reg,
                        edge_type="direct",
                    ))
            prev_tainted = dict(snap)

        graph = TaintGraph(
            edges=edges,
            crash_addr=crash_addr,
            crash_type=crash_type,
            entry_addr=entry_addr or (trace_addrs[0] if trace_addrs else 0),
            total_instructions=len(trace_addrs),
        )
        return graph

    @staticmethod
    def minimal_graph(chains: List[CausalChain],
                       crash_addr: int = 0,
                       crash_type: str = "") -> TaintGraph:
        """从因果链列表反向构造最小污点图——仅含因果相关的边。

        用于可视化: 展示从根因输入字节到崩溃点的最小传播路径。
        """
        edges: List[TaintEdge] = []
        for chain in chains:
            for j in range(len(chain.chain_addrs) - 1):
                edges.append(TaintEdge(
                    source_addr=chain.chain_addrs[j],
                    sink_addr=chain.chain_addrs[j + 1],
                    input_offsets={chain.input_offset},
                    register_name=(
                        chain.affected_registers[0]
                        if chain.affected_registers else ""),
                    edge_type="causal",
                ))

        return TaintGraph(
            edges=edges,
            crash_addr=crash_addr,
            crash_type=crash_type,
            total_instructions=sum(len(c.chain_addrs) for c in chains),
        )


# ============================================================
# 与 subreg_taint 的接合
# ============================================================

def build_causal_report_from_tracker(
    crash_tracker_state,           # SubRegTaintTracker (崩溃执行后)
    parent_tracker_state=None,     # SubRegTaintTracker (父输入执行后, 可选)
    crash_input: bytes = b"",
    parent_input: bytes = b"",
    crash_addr: int = 0,
    crash_type: str = "",
) -> CausalTaintReport:
    """便捷入口: 从 SubRegTaintTracker 状态直接生成因果报告。

    这是 subreg_taint.py → causal_taint.py 的标准桥接路径。
    """
    analyzer = CausalTaintAnalyzer()

    # 从 tracker 提取 taint 边 (简化: 使用指令执行序列和污点快照)
    crash_graph = _extract_graph_from_tracker(
        crash_tracker_state, crash_addr, crash_type)
    analyzer.ingest_crash_graph(crash_graph)

    if parent_tracker_state is not None:
        parent_graph = _extract_graph_from_tracker(
            parent_tracker_state, crash_addr, crash_type)
        analyzer.ingest_parent_graph(parent_graph)

    return analyzer.analyze(crash_input, parent_input)


def _extract_graph_from_tracker(tracker,
                                 crash_addr: int = 0,
                                 crash_type: str = "") -> TaintGraph:
    """从 SubRegTaintTracker 提取污点图——构建 TaintEdge 列表"""
    edges: List[TaintEdge] = []
    tracked_offsets: Dict[int, Set[int]] = defaultdict(set)

    # 遍历 GPR 寄存器, 提取每个字节的 taint 源
    for gpr_idx in range(16):
        tb = tracker._gpr[gpr_idx]
        for byte_idx in range(8):
            sources = set()
            for bit in range(8):
                sources |= tb._sources[byte_idx * 8 + bit]
            if sources:
                tracked_offsets[gpr_idx].update(sources)

    # 为每个被污染的寄存器创建一条边 (简化表示)
    for gpr_idx, offsets in tracked_offsets.items():
        if offsets:
            edges.append(TaintEdge(
                source_addr=0,          # 输入源
                sink_addr=crash_addr,   # 崩溃点
                input_offsets=offsets,
                register_name=f"gpr{gpr_idx}",
                edge_type="direct",
            ))

    return TaintGraph(
        edges=edges,
        crash_addr=crash_addr,
        crash_type=crash_type,
        total_instructions=tracker._instructions_executed,
    )
