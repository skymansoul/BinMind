# 协议响应解析树差分分析 —— 加权树编辑距离+分歧子树定位。
#
# 字节级差分(如Round 1的differential_oracle)无法区分"语义等价但
# 语法不同"与"真正的语义分歧"。例如两个HTTP实现的响应:
#   A: HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello
#   B: HTTP/1.1 200 OK\r\nContent-Length: 5\r\nX-Via: proxy\r\n\r\nhello
# 字节级比较标记为"分歧"(多了一个X-Via头), 但语义层两者等价。
#
# 本模块将响应解析为通用树结构, 计算加权树编辑距离:
#   节点删除/插入 = 1.0 (结构差异)
#   节点值修改 = 0.3 (值差异, 权重低——如timestamp总变)
#   节点重命名 = 0.7 (类型差异)
# 编辑脚本→分歧子树→结构差异评分。
#
# 与现有工作的差异:
#   - ChangeDistiller (IEEE TSE 2025)/GumTree (ICSE 2024):
#     树编辑距离应用于源代码AST, 非协议响应树
#   - 本模块: 轻量通用树(非语言特定AST)+协议响应感知权重

from __future__ import annotations

import math
from collections import deque
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Dict, List, Optional, Set, Tuple


class EditOp(Enum):
    MATCH  = auto()  # 节点匹配(零成本)
    INSERT = auto()  # 在目标树中插入节点
    DELETE = auto()  # 从源树中删除节点
    UPDATE = auto()  # 节点值修改
    RENAME = auto()  # 节点类型/名称变更


@dataclass
class TreeNode:
    """通用协议响应树节点 —— 协议无关的键值树表示。"""
    tag: str                  # 节点标签(如 "status_line", "header", "field")
    value: Any = None         # 可选值(字符串/整数/字节)
    children: List[TreeNode] = field(default_factory=list)
    attr: Dict[str, Any] = field(default_factory=dict)
    # 元数据: 在原始响应中的位置
    offset: int = 0
    length: int = 0

    def add_child(self, child: TreeNode) -> None:
        self.children.append(child)

    def size(self) -> int:
        """子树节点总数(含自身)"""
        return 1 + sum(c.size() for c in self.children)


@dataclass
class EditScript:
    """树编辑操作序列"""
    operations: List[Tuple[EditOp, str, str]] = field(default_factory=list)
    # (op, source_node_path, target_node_path)
    total_cost: float = 0.0
    matched_nodes: int = 0
    total_nodes_source: int = 0
    total_nodes_target: int = 0


@dataclass
class TreeDiffResult:
    """树差分完整结果"""
    source_size: int
    target_size: int
    edit_script: EditScript
    similarity_score: float     # [0,1] 0=完全不同的树, 1=同构
    diverging_subtrees: List[Tuple[str, float]]  # [(路径, 局部差异得分)]
    structural_divergence: float  # 仅结构差异(排除值修改)


class TreeEditDistance:
    """加权树编辑距离计算器。

    使用递归顶向下匹配(非Zhang-Shasha通用算法)。
    协议响应树通常<100节点且结构规整(header→fields, body→chunks),
    递归匹配在O(n×m)时间内完成且产出可解释的编辑脚本。

    权重设计:
      - 结构操作(插入/删除): 1.0 —— 语义差异
      - 值修改: 0.3 —— 低权重(版本号/时间戳常变)
      - 标签变更: 0.7 —— 中权重(可能为协议版本差异)
    """

    def __init__(self, insert_cost: float = 1.0,
                 delete_cost: float = 1.0,
                 update_cost: float = 0.3,
                 rename_cost: float = 0.7,
                 structural_threshold: float = 0.3):
        self._w_ins = insert_cost
        self._w_del = delete_cost
        self._w_upd = update_cost
        self._w_ren = rename_cost
        self._struct_thresh = structural_threshold

    def compute(self, source: TreeNode,
                target: TreeNode) -> TreeDiffResult:
        """计算两棵树之间的加权编辑距离。"""
        script = EditScript(
            total_nodes_source=source.size(),
            total_nodes_target=target.size(),
        )
        self._match_trees(source, target, "", script)

        # 相似度 = 1 - 归一化编辑代价
        max_cost = max(source.size(), target.size()) * max(
            self._w_ins, self._w_del, self._w_ren)
        if max_cost < 1e-6:
            sim = 1.0
        else:
            sim = max(0.0, 1.0 - script.total_cost / max_cost)

        # 分歧子树: 编辑代价>阈值的子路径
        diverging = self._find_diverging_subtrees(source, target, "")

        # 结构差异: 仅计插入/删除, 不计值修改
        struct_cost = sum(
            self._w_ins if op == EditOp.INSERT else
            self._w_del if op == EditOp.DELETE else
            self._w_ren if op == EditOp.RENAME else 0.0
            for op, _, _ in script.operations
        )
        struct_div = min(struct_cost / max(
            max(source.size(), target.size()), 1), 1.0)

        return TreeDiffResult(
            source_size=source.size(),
            target_size=target.size(),
            edit_script=script,
            similarity_score=round(sim, 4),
            diverging_subtrees=diverging[:5],
            structural_divergence=round(struct_div, 4),
        )

    def _match_trees(self, a: TreeNode, b: TreeNode,
                      path: str, script: EditScript) -> None:
        """递归匹配两棵子树, 累积编辑操作。"""
        # 标签不同 → 重命名
        if a.tag != b.tag:
            script.operations.append(
                (EditOp.RENAME, f"{path}/{a.tag}", f"{path}/{b.tag}"))
            script.total_cost += self._w_ren
        else:
            script.matched_nodes += 1

        # 值比较
        if a.value is not None and b.value is not None:
            if str(a.value) != str(b.value):
                script.operations.append(
                    (EditOp.UPDATE, f"{path}/{a.tag}", f"{path}/{b.tag}"))
                script.total_cost += self._w_upd

        # 子节点匹配: 贪心最佳匹配
        a_children = list(a.children)
        b_children = list(b.children)
        matched_b = set()

        for ac in a_children:
            best_j = -1
            best_score = -1.0
            for j, bc in enumerate(b_children):
                if j in matched_b:
                    continue
                s = self._node_similarity(ac, bc)
                if s > best_score:
                    best_score = s
                    best_j = j
            if best_j >= 0 and best_score > 0.3:
                matched_b.add(best_j)
                child_path = f"{path}/{a.tag}"
                self._match_trees(ac, b_children[best_j],
                                  child_path, script)
            else:
                # a的子节点在b中无匹配 → 删除
                script.operations.append(
                    (EditOp.DELETE, f"{path}/{a.tag}/{ac.tag}", ""))
                script.total_cost += self._w_del

        # b中未匹配的子节点 → 插入
        for j, bc in enumerate(b_children):
            if j not in matched_b:
                script.operations.append(
                    (EditOp.INSERT, "", f"{path}/{b.tag}/{bc.tag}"))
                script.total_cost += self._w_ins

    def _node_similarity(self, a: TreeNode, b: TreeNode) -> float:
        """两节点相似度: 标签匹配(0.5)+值匹配(0.3)+子节点数接近(0.2)"""
        score = 0.0
        if a.tag == b.tag:
            score += 0.5
        elif a.tag.lower() == b.tag.lower():
            score += 0.3
        if a.value is not None and b.value is not None:
            if str(a.value) == str(b.value):
                score += 0.3
        len_diff = abs(len(a.children) - len(b.children))
        score += max(0.0, 0.2 - len_diff * 0.05)
        return score

    def _find_diverging_subtrees(self, a: TreeNode, b: TreeNode,
                                  path: str) -> List[Tuple[str, float]]:
        """BFS遍历, 标记局部差异得分>阈值的子树。"""
        results: List[Tuple[str, float]] = []
        queue = deque([(a, b, f"{path}/{a.tag}")])
        while queue:
            na, nb, p = queue.popleft()
            if na.tag != nb.tag:
                results.append((p, 1.0))
                continue
            local_score = self._local_divergence(na, nb)
            if local_score > self._struct_thresh:
                results.append((p, round(local_score, 3)))
            for ca, cb in zip(na.children, nb.children):
                queue.append((ca, cb, f"{p}/{ca.tag}"))
        results.sort(key=lambda x: -x[1])
        return results

    def _local_divergence(self, a: TreeNode, b: TreeNode) -> float:
        """局部结构差异: 子节点数差异+标签集合差异"""
        a_tags = {c.tag for c in a.children}
        b_tags = {c.tag for c in b.children}
        if not a_tags and not b_tags:
            return 0.0
        jaccard = len(a_tags & b_tags) / max(len(a_tags | b_tags), 1)
        size_diff = abs(len(a.children) - len(b.children)) / max(
            max(len(a.children), len(b.children)), 1)
        return (1.0 - jaccard) * 0.6 + size_diff * 0.4


def build_http_response_tree(status_code: int,
                              headers: Dict[str, str],
                              body: bytes = b"") -> TreeNode:
    """从HTTP响应构建通用解析树 —— 示例解析器。

    实际使用中可替换为TLS/DNS/Modbus等协议的专用解析器。
    """
    root = TreeNode(tag="http_response")
    root.add_child(TreeNode(tag="status_line", value=f"HTTP/1.1 {status_code}"))

    hdr_node = TreeNode(tag="headers")
    for k, v in sorted(headers.items()):
        hdr_node.add_child(TreeNode(tag="header_field",
                                    value=f"{k}: {v}",
                                    attr={"name": k}))
    root.add_child(hdr_node)

    if body:
        body_node = TreeNode(tag="body", value=body,
                            attr={"length": len(body)})
        root.add_child(body_node)

    return root


def diff_responses(source: TreeNode,
                   target: TreeNode) -> TreeDiffResult:
    """便捷入口: 两棵协议响应树→加权编辑距离→TreeDiffResult。"""
    ted = TreeEditDistance()
    return ted.compute(source, target)


__all__ = [
    "EditOp", "TreeNode", "EditScript", "TreeDiffResult",
    "TreeEditDistance", "build_http_response_tree", "diff_responses",
]
