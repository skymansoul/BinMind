"""污点标签传播图 — 轻量级 tag-based taint 追踪.

创建: 2025-06-09 09:15
用途: 追踪二进制中从输入源到危险 sink 的数据流, 使用 def-use 链代替全量约束求解。
      不支持间接调用/虚函数表的指针分析——那些场景回退到 Angr。

设计决策:
  - 为什么用 tag-based 而非 value-based taint: value-based 需要模拟每条指令的语义,
    等效于做符号执行。tag-based 只追踪"这个寄存器/内存位置是否被用户数据污染",
    计算量降低约 20×。
  - 为什么不做过程间追踪: 跨函数污点需要准确的调用图, 对 strip 二进制实用性低。
    当前限定在函数内 def-use 链, 跨函数场景通过 source_sink_resolver 的启发式连接处理。
"""

from dataclasses import dataclass, field
from typing import Dict, FrozenSet, List, Optional, Set, Tuple
from enum import Enum


class TaintTag(str, Enum):
    """污点标签类型."""
    USER_INPUT = "user_input"       # 来自 scanf/read/recv 等输入
    DERIVED = "derived"             # 由已污染数据计算得出
    CLEAN = "clean"                 # 确认为未污染


@dataclass
class TaintNode:
    """污点图中的一个节点 — 代表一个被污染的变量/寄存器/内存地址."""
    node_id: str                    # 唯一标识 (如 "reg:rax@0x401000")
    tag: TaintTag = TaintTag.CLEAN
    source_insn_addr: int = 0       # 污染来源指令地址
    value_range: Tuple[int, int] = (0, 0)  # 该变量的近似值域 (用于格式字符串分析)
    # def-use 链
    defs: Set[str] = field(default_factory=set)   # 定义此变量的指令ID集合
    uses: Set[str] = field(default_factory=set)   # 使用此变量的指令ID集合
    # 传播
    propagated_from: List[str] = field(default_factory=list)  # 污点来源 node_id
    propagated_to: List[str] = field(default_factory=list)    # 污点传播目标


class TaintGraph:
    """污点传播有向图 — 节点=被污染的变量, 边=数据流依赖.

    用途: 为 source_sink_resolver 提供轻量级的污点传播查询。
    复杂度: O(|V| + |E|) 构建, O(1) 查询单节点污点状态。
    """

    def __init__(self):
        self._nodes: Dict[str, TaintNode] = {}
        # 输入源索引: insn_addr → [node_id, ...]
        self._source_nodes: Dict[int, List[str]] = {}
        # 危险 sink 索引: insn_addr → [node_id, ...]
        self._sink_nodes: Dict[int, List[str]] = {}

    # //// 节点管理 ////
    def add_node(self, node_id: str, tag: TaintTag = TaintTag.CLEAN,
                 source_addr: int = 0) -> TaintNode:
        """注册一个污点节点."""
        node = TaintNode(node_id=node_id, tag=tag, source_insn_addr=source_addr)
        self._nodes[node_id] = node
        return node

    def mark_as_source(self, node_id: str, insn_addr: int) -> None:
        """标记为输入源 (如 scanf 的缓冲区参数)."""
        if node_id in self._nodes:
            self._nodes[node_id].tag = TaintTag.USER_INPUT
        self._source_nodes.setdefault(insn_addr, []).append(node_id)

    def mark_as_sink(self, node_id: str, insn_addr: int) -> None:
        """标记为危险 sink (如 printf 的格式化参数)."""
        self._sink_nodes.setdefault(insn_addr, []).append(node_id)

    def add_edge(self, from_node: str, to_node: str) -> None:
        """添加数据流依赖边 from→to."""
        if from_node in self._nodes and to_node in self._nodes:
            self._nodes[from_node].propagated_to.append(to_node)
            self._nodes[to_node].propagated_from.append(from_node)
            # 传播污点标签
            if self._nodes[from_node].tag == TaintTag.USER_INPUT:
                if self._nodes[to_node].tag == TaintTag.CLEAN:
                    self._nodes[to_node].tag = TaintTag.DERIVED

    # //// 查询 ////
    def is_tainted(self, node_id: str) -> bool:
        """节点是否被用户输入污染."""
        node = self._nodes.get(node_id)
        return node is not None and node.tag in (TaintTag.USER_INPUT, TaintTag.DERIVED)

    def get_taint_path(self, node_id: str) -> List[str]:
        """回溯污点传播链 — 从给定节点到最近的输入源."""
        path = []
        visited = set()
        queue = [node_id]
        while queue:
            cur = queue.pop(0)
            if cur in visited:
                continue
            visited.add(cur)
            path.append(cur)
            node = self._nodes.get(cur)
            if node:
                for src in node.propagated_from:
                    if src not in visited:
                        queue.append(src)
        return path

    def get_sources(self) -> Dict[int, List[str]]:
        """返回所有已注册的输入源."""
        return dict(self._source_nodes)

    def get_sinks(self) -> Dict[int, List[str]]:
        """返回所有已注册的危险 sink."""
        return dict(self._sink_nodes)

    def node_count(self) -> int:
        return len(self._nodes)

    def clear(self) -> None:
        self._nodes.clear()
        self._source_nodes.clear()
        self._sink_nodes.clear()
