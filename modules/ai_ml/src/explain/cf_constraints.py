# 二进制CFG图编辑的语义保持约束
# 确保反事实搜索生成的图编辑在程序语义上是合法的

from __future__ import annotations

from typing import Dict, List, Optional, Set, Tuple, Any
from dataclasses import dataclass, field
from enum import Enum


class GraphEditOp(Enum):
    """图编辑操作类型-限定于二进制CFG的合法变换。

    EDGE_DROP: 删除控制流边（对应分支裁剪/死代码消除）
    EDGE_ADD: 添加合法控制流边（对应函数内联展开的逆操作）
    FEATURE_PERTURB: 扰动节点特征（对应寄存器重分配、指令重排）
    NODE_MASK: 屏蔽节点（对应无用基本块消除）
    """
    EDGE_DROP = 'edge_drop'
    EDGE_ADD = 'edge_add'
    FEATURE_PERTURB = 'feature_perturb'
    NODE_MASK = 'node_mask'


@dataclass
class GraphEdit:
    """单次图编辑操作的记录"""
    op: GraphEditOp
    src_node: int
    dst_node: int = -1
    feature_idx: int = -1
    old_value: float = 0.0
    new_value: float = 0.0
    cost: float = 1.0


class BinarySemanticConstraints:
    """二进制CFG编辑的合法性约束。

    约束来源:
      1. 控制流完整性: 不能删除关键边（循环回边、异常处理边）
      2. 调用图封闭性: call指令目标节点不可失联
      3. 入口/出口不可变性: entry block和exit block不可修改

    strict_mode=True（默认）时执行全部约束，
    strict_mode=False允许部分边界情况（用于探索性分析）。
    """

    def __init__(self, cfg_metadata: Optional[Dict[str, Any]] = None,
                 strict_mode: bool = True):
        self.cfg_meta = cfg_metadata or {}
        self.strict = strict_mode
        self._critical_edges: Set[Tuple[int, int]] = set()
        self._call_targets: Set[int] = set()
        self._entry_nodes: Set[int] = set()
        self._exit_nodes: Set[int] = set()
        self._loop_backedges: Set[Tuple[int, int]] = set()

    def load_from_cfg(self,
                      adjacency: List[List[int]],
                      node_types: Optional[List[str]] = None,
                      loop_edges: Optional[List[Tuple[int, int]]] = None):
        """从CFG结构提取约束元数据。

        node_types的识别标签:
          'entry'/'entry_block' → 入口节点
          'exit'/'exit_block'/'ret_block' → 出口节点
          'call_block' → call指令所在基本块
        """
        n = len(adjacency)
        if node_types is None:
            node_types = ['basic_block'] * n

        for i, ntype in enumerate(node_types):
            if ntype in ('entry', 'entry_block'):
                self._entry_nodes.add(i)
            if ntype in ('exit', 'exit_block', 'ret_block'):
                self._exit_nodes.add(i)
            if ntype in ('call_block',):
                for j in range(n):
                    if adjacency[i][j]:
                        self._call_targets.add(j)

        if loop_edges:
            for u, v in loop_edges:
                self._loop_backedges.add((u, v))

    def is_edit_allowed(self, edit: GraphEdit,
                        adjacency: List[List[int]],
                        node_features: Optional[List[List[float]]] = None
                        ) -> Tuple[bool, str]:
        """判断图编辑操作是否违反语义约束。"""
        if edit.op == GraphEditOp.EDGE_DROP:
            return self._check_edge_drop(edit, adjacency)
        elif edit.op == GraphEditOp.EDGE_ADD:
            return self._check_edge_add(edit, adjacency)
        elif edit.op == GraphEditOp.NODE_MASK:
            return self._check_node_mask(edit)
        return True, ""

    def _check_edge_drop(self, edit: GraphEdit,
                         adjacency: List[List[int]]) -> Tuple[bool, str]:
        u, v = edit.src_node, edit.dst_node
        if (u, v) in self._loop_backedges:
            return False, "循环回边不可删除-破坏自然循环结构"
        if v in self._call_targets and u in self._call_targets:
            return False, "call目标基本块不可失联-破坏调用图封闭性"
        if self.strict and v in self._entry_nodes:
            return False, "入口节点入边不可删除"
        # 删除后节点完全不可达检查
        remaining_in = sum(1 for i in range(len(adjacency))
                         if adjacency[i][v] and i != u)
        if remaining_in == 0 and v not in self._entry_nodes and self.strict:
            return False, "删除后节点完全不可达-产生孤立节点"
        return True, ""

    def _check_edge_add(self, edit: GraphEdit,
                        adjacency: List[List[int]]) -> Tuple[bool, str]:
        u, v = edit.src_node, edit.dst_node
        if u == v and self.strict:
            return False, "CFG自环破坏控制流语义-基本块不应跳转到自身"
        if v in self._entry_nodes:
            return False, "不可添加边指向入口节点"
        return True, ""

    def _check_node_mask(self, edit: GraphEdit) -> Tuple[bool, str]:
        if edit.src_node in self._entry_nodes:
            return False, "入口节点不可屏蔽"
        if edit.src_node in self._exit_nodes and self.strict:
            return False, "出口节点不可屏蔽"
        return True, ""
