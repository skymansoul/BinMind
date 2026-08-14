"""
VFG 数据类型 — 值流图的节点/边/图定义.

"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional


class NodeKind(Enum):
    CONSTANT = "constant"        # 字面量: 64, 0x100
    VARIABLE = "variable"        # 编译器恢复的变量: var_10h, p
    ALLOC_CALL = "alloc_call"    # malloc/calloc/realloc 调用
    WRITE_CALL = "write_call"    # memcpy/strcpy 或 [base+off] = val
    EXPRESSION = "expression"    # 算术表达式: a + b, n * 4
    PARAMETER = "parameter"      # 函数参数
    RETURN_VAL = "return_val"    # 函数返回值
    LOOP_BOUND = "loop_bound"    # 循环上界 (从 cmp 指令推断)


@dataclass
class VFGNode:
    """值流图节点 — 单个值定义点。"""
    node_id: int
    kind: NodeKind
    name: str = ''               # 变量名或表达式文本
    value: Optional[int] = None  # 已知常量值 (NodeKind.CONSTANT)
    line_idx: int = -1           # 源IR行索引
    text: str = ''               # 原始IR行文本
    # 对于 ALLOC_CALL: (func_name, size_arg_expr)
    # 对于 WRITE_CALL: (base_var, offset_expr, size_expr)
    call_info: tuple = field(default_factory=tuple)

    def __hash__(self):
        return hash(self.node_id)

    def __eq__(self, other):
        if not isinstance(other, VFGNode):
            return False
        return self.node_id == other.node_id


@dataclass
class VFGEdge:
    """值流边 — 数据从源定义流向目标使用。"""
    source: VFGNode
    target: VFGNode
    relation: str = ''  # 'identity' | 'add' | 'mul' | 'cmp_bound'


@dataclass
class ValueFlowGraph:
    """函数反编译输出的完整值流图。"""
    nodes: List[VFGNode] = field(default_factory=list)
    edges: List[VFGEdge] = field(default_factory=list)
    function_name: str = ''

    # 快速查找索引
    _node_by_name: Dict[str, List[VFGNode]] = field(default_factory=dict)
    _node_by_kind: Dict[NodeKind, List[VFGNode]] = field(default_factory=dict)

    def add_node(self, node: VFGNode):
        self.nodes.append(node)
        self._node_by_name.setdefault(node.name, []).append(node)
        self._node_by_kind.setdefault(node.kind, []).append(node)

    def add_edge(self, src: VFGNode, tgt: VFGNode, rel: str = 'identity'):
        self.edges.append(VFGEdge(src, tgt, rel))

    def get_nodes_by_kind(self, kind: NodeKind) -> List[VFGNode]:
        return self._node_by_kind.get(kind, [])

    def get_nodes_by_name(self, name: str) -> List[VFGNode]:
        return self._node_by_name.get(name, [])

    def get_alloc_nodes(self) -> List[VFGNode]:
        return self.get_nodes_by_kind(NodeKind.ALLOC_CALL)

    def get_write_nodes(self) -> List[VFGNode]:
        return self.get_nodes_by_kind(NodeKind.WRITE_CALL)

    def predecessors(self, node: VFGNode) -> List[VFGNode]:
        return [e.source for e in self.edges if e.target.node_id == node.node_id]

    def successors(self, node: VFGNode) -> List[VFGNode]:
        return [e.target for e in self.edges if e.source.node_id == node.node_id]


__all__ = [
    'NodeKind',
    'VFGNode',
    'VFGEdge',
    'ValueFlowGraph',
]
