# 可达流上界: 调用图 + 数据依赖边 -> 可能流估计
# 已验证流比率: 实际追踪 / 可能流上界 -> 完备性百分比
# 上界估计改进: 使用 Floyd-Warshall 传递闭包
# 隐式流估计: 控制依赖边作为额外潜在流, 每条件分支增加1条隐式流

# 信息流分析完备性量化: 从二值(通过/失败)到连续完备性度量
# information_flow_verifier.py 验证信息流是否违反策略(如 secret->public)
# 但回答的是"是否存在违规流", 不回答"检查了多少可能的流"
# 完备性比率 = 已验证流 / 可能流上界

from __future__ import annotations

import math
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple


# 数据结构

@dataclass
class FlowEdge:
    """信息流图中的一条边"""
    src_node: str           # 源 (变量/函数/参数)
    dst_node: str           # 目标
    flow_type: str = 'data' # data | control | implicit
    verified: bool = False  # 是否已被 information_flow_verifier 检查


@dataclass
class CompletenessReport:
    """信息流完备性报告"""
    total_potential_flows: int       # 可能流的上界
    verified_flows: int              # 已验证的流
    completeness_ratio: float        # [0,1]
    # 分解
    data_flow_coverage: float
    control_flow_coverage: float
    # 未验证区域
    unverified_paths: List[Tuple[str, str]]  # 未检查的源->目标对
    # 置信度解释
    confidence_level: str = 'LOW'    # HIGH | MEDIUM | LOW


class InfoflowCompletenessAnalyzer:
    """信息流完备性分析器"""

    def __init__(self):
        self._flows: List[FlowEdge] = []

    def register_flow(self, flow: FlowEdge) -> None:
        """注册单个已验证或未验证的信息流"""
        self._flows.append(flow)

    def compute_completeness(
        self,
        call_graph: Optional[Dict[str, List[str]]] = None,
        data_deps: Optional[Dict[str, List[str]]] = None,
        verified_flows: Optional[List[Tuple[str, str]]] = None,
    ) -> CompletenessReport:
        """计算信息流分析的完备性

        call_graph: {caller: [callee]} - 用于估计控制流上界
        data_deps: {var: [dependent_vars]} - 用于估计数据流上界
        verified_flows: [(src, dst)] - 已验证的源->目标流

        返回 CompletenessReport
        """
        verified = set(verified_flows or [])

        # 1. 估计可能流的上界 (数据流 + 控制流 + 隐式流)
        potential_data = self._count_potential_data_flows(data_deps or {})
        potential_control = self._count_potential_control_flows(
            call_graph or {}
        )
        # 隐式流: 每条件分支创建 1 条额外的潜在隐式流
        implicit = self._count_implicit_flows(data_deps or {}, call_graph or {})
        total_potential = potential_data + potential_control + implicit

        # 2. 计数已验证的流
        # 数据流已验证
        verified_data = 0
        if data_deps:
            for src, dsts in data_deps.items():
                for dst in dsts:
                    if (src, dst) in verified:
                        verified_data += 1

        # 控制流已验证
        verified_control = 0
        if call_graph:
            for src, dsts in call_graph.items():
                for dst in dsts:
                    if (src, dst) in verified:
                        verified_control += 1

        total_verified = verified_data + verified_control + len([
            f for f in self._flows if f.verified
        ])

        # 3. 完备性比率
        completeness = total_verified / max(1, total_potential)
        data_cov = verified_data / max(1, potential_data)
        control_cov = verified_control / max(1, potential_control)

        # 4. 未验证路径
        unverified = []
        if data_deps:
            for src, dsts in data_deps.items():
                for dst in dsts:
                    if (src, dst) not in verified:
                        unverified.append((src, dst))
        if call_graph:
            for src, dsts in call_graph.items():
                for dst in dsts:
                    if (src, dst) not in verified:
                        unverified.append((src, dst))

        # 5. 置信度
        if completeness >= 0.85:
            conf = 'HIGH'
        elif completeness >= 0.50:
            conf = 'MEDIUM'
        else:
            conf = 'LOW'

        return CompletenessReport(
            total_potential_flows=total_potential,
            verified_flows=total_verified,
            completeness_ratio=round(completeness, 4),
            data_flow_coverage=round(data_cov, 4),
            control_flow_coverage=round(control_cov, 4),
            unverified_paths=unverified[:20],  # top 20
            confidence_level=conf,
        )

    @staticmethod
    def _count_potential_data_flows(
        data_deps: Dict[str, List[str]]
    ) -> int:
        """数据流上界: 所有声明的数据依赖边"""
        return sum(len(dsts) for dsts in data_deps.values())

    @staticmethod
    def _count_potential_control_flows(
        call_graph: Dict[str, List[str]]
    ) -> int:
        """控制流可能数: 直接调用边 + 传递闭包中的可达对

        使用 Floyd-Warshall 风格的可达性矩阵计算传递闭包
        复杂度 O(N³) 但调用图节点数 < 10³ 可接受
        """
        edge_count = sum(len(callees) for callees in call_graph.values())
        if edge_count == 0:
            return 0

        # 构建可达性传递闭包
        nodes = list(call_graph.keys())
        n = len(nodes)
        if n > 500:  # 大规模调用图回退到简化估计
            depths = InfoflowCompletenessAnalyzer._bfs_depths(call_graph)
            avg_depth = sum(depths.values()) / max(1, len(depths))
            return edge_count + int(edge_count * math.log2(max(2, avg_depth)))

        idx = {name: i for i, name in enumerate(nodes)}
        reachable = [[False] * n for _ in range(n)]
        for caller, callees in call_graph.items():
            ci = idx.get(caller, -1)
            if ci < 0:
                continue
            for callee in callees:
                cj = idx.get(callee, -1)
                if cj >= 0:
                    reachable[ci][cj] = True

        # Floyd-Warshall 传递闭包
        for k in range(n):
            for i in range(n):
                if reachable[i][k]:
                    row_k = reachable[k]
                    row_i = reachable[i]
                    for j in range(n):
                        if row_k[j]:
                            row_i[j] = True

        transitive_pairs = sum(sum(row) for row in reachable)
        return transitive_pairs

    @staticmethod
    def _count_implicit_flows(
        data_deps: Dict[str, List[str]],
        call_graph: Dict[str, List[str]],
    ) -> int:
        """隐式流估计: 每个有数据依赖的源可能通过控制结构影响输出

        简化的 Denning 模型: 每条数据依赖边可能伴随 1 条隐式控制流
        控制流总数: 调用图边数 (每调用点是一个潜在的控制决策点)
        """
        data_edges = sum(len(dsts) for dsts in data_deps.values())
        cg_edges = sum(len(callees) for callees in call_graph.values())
        # 每数据边 + 每调用边可能产生 1 条隐式流
        return data_edges + cg_edges

    @staticmethod
    def _bfs_depths(
        call_graph: Dict[str, List[str]]
    ) -> Dict[str, int]:
        """BFS 计算每节点的调用深度"""
        depths: Dict[str, int] = {}
        # 找入口 (无 caller 的节点)
        has_caller: Set[str] = set()
        for _, callees in call_graph.items():
            has_caller.update(callees)
        entries = [
            n for n in call_graph if n not in has_caller
        ]
        if not entries and call_graph:
            entries = [list(call_graph.keys())[0]]

        for entry in entries:
            queue: deque = deque([(entry, 0)])
            visited: Set[str] = set()
            while queue:
                node, depth = queue.popleft()
                if node in visited:
                    continue
                visited.add(node)
                depths[node] = depth
                for callee in call_graph.get(node, []):
                    if callee not in visited:
                        queue.append((callee, depth + 1))

        return depths
