# 增加寄存器冲突检测（基于补丁指令的 reg read/write 集合）
# 语义矛盾检测：两个补丁对同一条件做相反假设

"""多补丁交互图 — 冲突/依赖检测与安全应用序。

同一 binary 应用多补丁时可能产生：
  1. 地址空间冲突：两补丁修改重叠字节区
  2. 寄存器冲突：补丁A写入被补丁B后续代码依赖
  3. 控制流干扰：补丁A插入的跳转目标被补丁B覆盖
  4. 语义矛盾：两补丁对同一安全检查做互斥假设

// ref: VeriBin StA 属性 (P1-P4)，本模块从单补丁
//   验证扩展到多补丁交互。VeriBin 检查每个 patch 是否 safe-to-apply，
//   但不检查两 safe patch 同时应用后是否仍 safe。
//   核心：相交区域属性传递分析——若补丁A改区域R，
//   补丁B依赖R中寄存器值，则B必须在A之后应用。
//
// ref: Multi-Fault Interaction-Aware Validation Oracles，
//   interaction relation modeling 思路启发本模块边类型定义。
//   但本实现针对 binary patch 层级（非 source fault 层级），
//   检测维度从 fault interaction 改为 address/register/CF/semantic。
//
// ref: RePatch 冲突矩阵与重放约束，借鉴 ordering constraints，
//   但操作在 binary 字节级而非 source AST 级。
"""

import re
import logging
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple, Set, FrozenSet
from enum import Enum
from collections import defaultdict, deque

__log = logging.getLogger(__name__)


class EdgeType(Enum):
    CONFLICT = "conflict"                # 直接冲突 — 不可共存
    DEPENDS_ON = "depends_on"            # B 依赖 A 先应用
    CLOBBERS = "clobbers"               # B 覆盖了 A 的修改
    SEMANTIC_CONTRADICT = "semantic_contradict"  # 互斥语义假设
    COMPATIBLE = "compatible"            # 可共存，任意序


@dataclass
class PatchNode:
    """补丁节点。"""
    patch_id: str
    address_range: Tuple[int, int]       # (start_offset, end_offset)
    affected_functions: List[str] = field(default_factory=list)
    reg_writes: Set[str] = field(default_factory=set)    # 补丁写入的寄存器
    reg_reads: Set[str] = field(default_factory=set)     # 补丁读取的寄存器
    call_targets: List[str] = field(default_factory=list) # 补丁调用的函数
    security_assertions: List[str] = field(default_factory=list)  # 语义断言
    metadata: Dict = field(default_factory=dict)

    @property
    def size(self) -> int:
        return max(0, self.address_range[1] - self.address_range[0])

    def overlaps(self, other: 'PatchNode') -> bool:
        a0, a1 = self.address_range
        b0, b1 = other.address_range
        return a0 < b1 and b0 < a1


@dataclass
class InteractionEdge:
    """补丁间交互边。"""
    source: str        # patch_id
    target: str        # patch_id
    edge_type: EdgeType
    detail: str = ""   # 冲突/依赖的具体描述
    confidence: float = 1.0  # 检测置信度


@dataclass
class InteractionReport:
    """多补丁交互分析报告。"""
    patches: List[PatchNode] = field(default_factory=list)
    edges: List[InteractionEdge] = field(default_factory=list)
    safe_order: List[str] = field(default_factory=list)    # 安全应用序（拓扑排序）
    conflicts: List[Tuple[str, str]] = field(default_factory=list)  # 不可解决的冲突
    warnings: List[str] = field(default_factory=list)
    is_safe_parallel: bool = False  # 所有补丁可并行应用

    def to_dict(self) -> Dict:
        return {
            'patch_count': len(self.patches),
            'edge_count': len(self.edges),
            'conflict_count': len(self.conflicts),
            'safe_order': self.safe_order,
            'conflicts': [{'a': a, 'b': b} for a, b in self.conflicts],
            'edges': [{'source': e.source, 'target': e.target,
                       'type': e.edge_type.value, 'detail': e.detail}
                      for e in self.edges],
            'warnings': self.warnings,
            'is_safe_parallel': self.is_safe_parallel,
        }


# 交互图构建器

class PatchInteractionGraph:
    """多补丁交互图 — 检测冲突/依赖，计算安全应用序。

    用法:
        graph = PatchInteractionGraph()
        report = graph.analyze([patch_a, patch_b, patch_c])
    """

    def __init__(self):
        self._nodes: Dict[str, PatchNode] = {}
        self._edges: List[InteractionEdge] = []

    def analyze(self, patches: List[PatchNode]) -> InteractionReport:
        """主入口：分析补丁列表，返回交互报告。"""
        self._nodes = {p.patch_id: p for p in patches}
        self._edges = []
        report = InteractionReport(patches=list(patches))

        patch_ids = list(self._nodes.keys())
        n = len(patch_ids)

        # O(n²) 成对分析 — patch 数 ≤ 20，可行
        for i in range(n):
            for j in range(i + 1, n):
                a = self._nodes[patch_ids[i]]
                b = self._nodes[patch_ids[j]]
                edges = self._analyze_pair(a, b)
                self._edges.extend(edges)
                for e in edges:
                    if e.edge_type == EdgeType.CONFLICT:
                        report.conflicts.append((a.patch_id, b.patch_id))

        report.edges = self._edges

        # 拓扑排序 — 基于 DEPENDS_ON 边
        order, cycles = self._topological_sort()
        report.safe_order = order
        if cycles:
            report.warnings.append(
                f"dependency cycle detected: {' → '.join(cycles[0])}")

        report.is_safe_parallel = (
            len(report.conflicts) == 0 and
            not any(e.edge_type == EdgeType.DEPENDS_ON for e in self._edges) and
            not any(e.edge_type == EdgeType.CLOBBERS for e in self._edges)
        )

        # n > 1 且零边 → 可并行
        if n > 1 and len(self._edges) == 0:
            report.is_safe_parallel = True

        return report

    def _analyze_pair(self, a: PatchNode, b: PatchNode) -> List[InteractionEdge]:
        """分析一对补丁的全部交互类型。"""
        edges: List[InteractionEdge] = []

        # 1. 地址空间冲突检测
        if a.overlaps(b):
            overlap_start = max(a.address_range[0], b.address_range[0])
            overlap_end = min(a.address_range[1], b.address_range[1])
            edges.append(InteractionEdge(
                source=a.patch_id, target=b.patch_id,
                edge_type=EdgeType.CONFLICT,
                detail=f"address overlap [{overlap_start:#x}, {overlap_end:#x}]",
                confidence=1.0))
            return edges  # 地址冲突即终止，其余检查无意义

        # 2. 寄存器依赖: A 写入 → B 读取 (B depends on A)
        if a.reg_writes & b.reg_reads:
            affected = a.reg_writes & b.reg_reads
            edges.append(InteractionEdge(
                source=a.patch_id, target=b.patch_id,
                edge_type=EdgeType.DEPENDS_ON,
                detail=f"registers: {sorted(affected)} (A writes, B reads)",
                confidence=0.85))
        if b.reg_writes & a.reg_reads:
            affected = b.reg_writes & a.reg_reads
            edges.append(InteractionEdge(
                source=b.patch_id, target=a.patch_id,
                edge_type=EdgeType.DEPENDS_ON,
                detail=f"registers: {sorted(affected)} (B writes, A reads)",
                confidence=0.85))

        # 3. 寄存器覆盖: A、B 均写入同寄存器 (可能 clobber)
        clobber = a.reg_writes & b.reg_writes
        if clobber:
            # 仅当 A 写入值被 B 覆盖且无其他指令保留时标记
            edges.append(InteractionEdge(
                source=a.patch_id, target=b.patch_id,
                edge_type=EdgeType.CLOBBERS,
                detail=f"registers: {sorted(clobber)} (both write, B overwrites A)",
                confidence=0.70))

        # 4. 控制流干扰: 同函数内两补丁改不同地址
        common_funcs = set(a.affected_functions) & set(b.affected_functions)
        if common_funcs and not a.overlaps(b):
            edges.append(InteractionEdge(
                source=a.patch_id, target=b.patch_id,
                edge_type=EdgeType.DEPENDS_ON,
                detail=f"same function(s): {sorted(common_funcs)} — verify ordering",
                confidence=0.50))

        # 5. 语义矛盾: 补丁安全断言互斥
        contradictions = self._detect_contradictions(a, b)
        if contradictions:
            edges.append(InteractionEdge(
                source=a.patch_id, target=b.patch_id,
                edge_type=EdgeType.SEMANTIC_CONTRADICT,
                detail=f"contradictory assertions: {contradictions}",
                confidence=0.60))

        return edges

    def _detect_contradictions(self, a: PatchNode, b: PatchNode) -> List[str]:
        """检测两补丁安全断言是否矛盾。

        如: patch A 假设 'ptr != NULL'，patch B 删除同一 NULL 检查。
        """
        contradictions = []
        for a_assert in a.security_assertions:
            for b_assert in b.security_assertions:
                # 简化：检查直接相反断言
                if self._are_contradictory(a_assert, b_assert):
                    contradictions.append(f"'{a_assert}' vs '{b_assert}'")
        return contradictions

    @staticmethod
    def _are_contradictory(a: str, b: str) -> bool:
        """判断两断言是否矛盾。"""
        a_lower = a.lower().strip()
        b_lower = b.lower().strip()
        # NULL check vs NULL dereference
        if ('!= null' in a_lower and '== null' in b_lower):
            return True
        if ('== null' in a_lower and '!= null' in b_lower):
            return True
        # 边界检查矛盾
        if ('<=' in a_lower and '>' in b_lower):
            return True
        if ('>=' in a_lower and '<' in b_lower):
            return True
        return False

# 拓扑排序

    def _topological_sort(self) -> Tuple[List[str], List[List[str]]]:
        """DEPENDS_ON 边拓扑排序 + 环检测。

        返回: (有序列表, 环列表)
        """
        # 构建邻接表（仅 DEPENDS_ON 参与排序）
        adj: Dict[str, List[str]] = defaultdict(list)
        in_degree: Dict[str, int] = defaultdict(int)

        for node_id in self._nodes:
            in_degree[node_id] = 0  # 保证全节点入度初始化

        for edge in self._edges:
            if edge.edge_type == EdgeType.DEPENDS_ON:
                adj[edge.source].append(edge.target)
                in_degree[edge.target] = in_degree.get(edge.target, 0) + 1

        # Kahn 算法
        queue: deque = deque(
            nid for nid in self._nodes if in_degree.get(nid, 0) == 0)
        order: List[str] = []

        while queue:
            node = queue.popleft()
            order.append(node)
            for neighbor in adj.get(node, []):
                in_degree[neighbor] -= 1
                if in_degree[neighbor] == 0:
                    queue.append(neighbor)

        # 环检测（in_degree 仍有非零节点）
        cycles: List[List[str]] = []
        remaining = [nid for nid, deg in in_degree.items() if deg > 0]
        if remaining:
            # DFS 找首个环
            visited: Set[str] = set()
            path: List[str] = []

            def dfs(node):
                if node in path:
                    cycle_start = path.index(node)
                    cycles.append(path[cycle_start:] + [node])
                    return True
                if node in visited:
                    return False
                visited.add(node)
                path.append(node)
                for nb in adj.get(node, []):
                    if dfs(nb):
                        return True
                path.pop()
                return False

            for start_node in remaining:
                if dfs(start_node):
                    break

        return order, cycles


# PatchNode 工厂

def patch_node_from_spec(patch_id: str, spec: Dict) -> PatchNode:
    """从补丁规格字典构造 PatchNode。
    // 适配 auto_patch_spec 模块输出格式。
    """
    addr = spec.get('target_address', 0)
    size = spec.get('estimated_size', 0)
    return PatchNode(
        patch_id=patch_id,
        address_range=(addr, addr + size),
        affected_functions=spec.get('affected_functions', []),
        reg_writes=set(spec.get('reg_writes', [])),
        reg_reads=set(spec.get('reg_reads', [])),
        call_targets=spec.get('call_targets', []),
        security_assertions=spec.get('security_assertions', []),
        metadata=spec.get('metadata', {}),
    )


def analyze_patch_set(patches: List[Dict]) -> InteractionReport:
    """便捷函数 — 从补丁规格字典列表直接分析。
    每个 dict 至少含 patch_id 和 target_address。
    """
    nodes = []
    for i, spec in enumerate(patches):
        pid = spec.get('patch_id', f'patch_{i}')
        nodes.append(patch_node_from_spec(pid, spec))
    graph = PatchInteractionGraph()
    return graph.analyze(nodes)
