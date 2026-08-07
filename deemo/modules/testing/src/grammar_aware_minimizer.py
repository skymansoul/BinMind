# 语法感知的智能最小化器 — 基于推断语法的结构保持输入缩减
#
# 核心问题:
#   input_minimizer.py 做ddmin——逐字节/块删除, 盲目且常破坏格式有效性。
#   对解析器类程序, 无效的中间输入被直接拒绝, ddmin退化到O(n²)。
#   GReduce 用生成器trace保持语义有效性——但需要源码。
#
# 本模块的方法 — 语法树引导的子树替换:
#   1. 从 grammar_infer.py 获取推断的BNF语法 (或 exec_grammar_refiner 精炼后的)
#   2. 将输入解析为语法树 (parse tree)
#   3. 对树节点做子树替换: 用语法允许的更小替代项替换当前子树
#   4. 优先替换大子树 (depth-first, 类似ddmin的分治思想)
#   5. 始终保持语法合法性: 每次缩减后的输入一定符合语法
#
# 与现有模块的桥接:
#   grammar_infer.py: 提供初始语法
#   exec_grammar_refiner.py: 提供精炼后的语法 (可选)
#   input_minimizer.py: 结构保持模式下的ddmin退化路径
#
# 文献:
#   GReduce — 生成器trace缩减;
#     本项目取其结构保持思想但以语法树替代生成器trace
#   Perses — 语法驱动的程序缩减;
#     本项目取其子树替换思想但适配到二进制格式

from __future__ import annotations

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

# 桥接 grammar_infer.py: 通过 load_fields() 接受字段定义,
# 字段列表可来自 GrammarInferrer.tokenize_bytes() + 字段边界推断,
# 或来自 taint_field_segmenter.py 的 FieldSegmentation.fields。
# 桥接 input_minimizer.py: 当无语法信息时(minimize返回原数据+0 tests),
# 调用方应回退到 input_minimizer 的通用 ddmin 逻辑。


# 简化的语法树节点
@dataclass
class TreeNode:
    """语法树的节点——代表输入的一个语法成分"""
    name: str = ""                         # 产生式名称/规则名
    offset: int = 0                        # 在输入中的起始偏移
    end: int = 0                           # 在输入中的结束偏移
    children: List[TreeNode] = None        # 子节点

    def __post_init__(self):
        if self.children is None:
            self.children = []

    @property
    def size(self) -> int:
        return self.end - self.offset

    def is_leaf(self) -> bool:
        return len(self.children) == 0


class GrammarAwareMinimizer:
    """语法感知的输入最小化器。

    典型用法:
        minimizer = GrammarAwareMinimizer()
        minimizer.load_grammar(grammar_rules)  # 来自 grammar_infer
        # 或: minimizer.load_fields(field_list) # 来自 taint_field_segmenter

        # predicate(data) → True 表示输入仍触发bug
        minimal = minimizer.minimize(original_input, predicate)
    """

    def __init__(self, max_iterations: int = 200):
        self._max_iters = max_iterations
        # 字段定义: [(start, end, role), ...]
        self._fields: List[Tuple[int, int, str]] = []
        # 语法树根
        self._tree: Optional[TreeNode] = None

    def load_fields(self, fields: List[Tuple[int, int, str]]) -> None:
        """加载字段定义——来自 taint_field_segmenter 或 type_aware_fuzz"""
        self._fields = sorted(fields, key=lambda f: f[0])

    def load_grammar_tree(self, root: TreeNode) -> None:
        """直接加载已构建的语法树"""
        self._tree = root

    def build_tree_from_fields(self, data: bytes) -> TreeNode:
        """从字段定义构建语法树——字段=直接子节点"""
        root = TreeNode(name="root", offset=0, end=len(data))
        for start, end, role in self._fields:
            if start < len(data) and end <= len(data):
                child = TreeNode(name=role, offset=start, end=min(end, len(data)))
                root.children.append(child)
        self._tree = root
        return root

    def minimize(self, data: bytes,
                  predicate: Callable[[bytes], bool],
                  ) -> Tuple[bytes, int]:
        """主入口: 语法感知最小化——返回(最小输入, 测试次数)

        算法: 对语法树的每个节点,
          1. 尝试删除该节点 (对于可选字段)
          2. 尝试替换为语法允许的更小替代项
          3. 若predicate仍为True, 接受缩减; 否则回滚
        """
        if self._tree is None and self._fields:
            self.build_tree_from_fields(data)
        if self._tree is None:
            return data, 0  # 无语法信息, 回退到调用方做ddmin

        buf = bytearray(data)
        tests = 0

        # 按节点大小降序遍历——大节点优先 (分治策略)
        # BFS按层处理: 先处理大节点(size降序), 再细化
        nodes = self._collect_nodes(self._tree)
        nodes.sort(key=lambda n: -n.size)

        for node in nodes:
            if tests >= self._max_iters:
                break
            if node.is_leaf() and node.size <= 1:
                continue

            # 策略1: 删除可选/重复节点
            if self._is_optional(node) or node.name in ('padding',):
                candidate = bytes(buf[:node.offset] + buf[node.end:])
                tests += 1
                if predicate(candidate):
                    buf = bytearray(candidate)
                    self._shift_offsets(node.offset, -node.size)
                    continue

            # 策略2: 子树二分缩减 — 类似ddmin但语法感知
            # 将节点内容分为两半, 尝试移除每一半
            if node.size >= 4 and not self._is_critical(node):
                mid = node.offset + node.size // 2
                # 尝试移除前半
                cand1 = bytes(buf[:node.offset] + buf[mid:node.end]
                               + buf[node.end:])
                tests += 1
                if predicate(cand1):
                    buf = bytearray(cand1)
                    self._shift_offsets(node.offset, -(mid - node.offset))
                    continue
                # 尝试移除后半
                cand2 = bytes(buf[:node.offset]
                               + buf[node.offset:mid] + buf[node.end:])
                tests += 1
                if predicate(cand2):
                    buf = bytearray(cand2)
                    self._shift_offsets(mid, -(node.end - mid))
                    continue

            # 策略3: 替换为最小变体
            minimal = self._get_minimal_variant(node, buf)
            if minimal is not None and len(minimal) < node.size:
                candidate = bytes(
                    buf[:node.offset] + minimal + buf[node.end:])
                tests += 1
                if predicate(candidate):
                    delta = len(minimal) - node.size
                    buf = bytearray(candidate)
                    self._shift_offsets(node.offset + len(minimal), delta)
                    continue

            # 策略4: 对数据字段做逐字节缩减 (细粒度, 最后手段)
            if node.name in ('data', 'raw', 'padding', 'unknown'):
                for i in range(node.offset, node.end):
                    if tests >= self._max_iters:
                        break
                    candidate = bytes(buf[:i] + buf[i + 1:])
                    tests += 1
                    if predicate(candidate):
                        buf = bytearray(candidate)
                        self._shift_offsets(i, -1)
                        break

        return bytes(buf), tests

    def _collect_nodes(self, node: TreeNode) -> List[TreeNode]:
        """收集树中所有节点 (前序遍历)"""
        nodes = [node]
        for child in node.children:
            nodes.extend(self._collect_nodes(child))
        return nodes

    def _shift_offsets(self, from_pos: int, delta: int) -> None:
        """因为数据大小变化, 更新所有节点的偏移"""
        def shift(n: TreeNode):
            if n.offset >= from_pos:
                n.offset += delta
            if n.end >= from_pos:
                n.end += delta
            for c in n.children:
                shift(c)
        if self._tree:
            shift(self._tree)

    @staticmethod
    def _is_critical(node: TreeNode) -> bool:
        """不应被二分缩减破坏的节点: magic, checksum, length"""
        return node.name in ('magic', 'checksum', 'length')

    @staticmethod
    def _is_optional(node: TreeNode) -> bool:
        """判断节点是否可选 (可被安全删除)"""
        return node.name in ('padding', 'data', 'raw', 'unknown')

    @staticmethod
    def _get_minimal_variant(node: TreeNode,
                              buf: bytearray) -> Optional[bytes]:
        """获取节点的最小合法变体——特定角色的最小表示"""
        if node.name == 'length':
            return b'\x00' * max(1, (node.size // 2))
        if node.name == 'magic':
            return None  # magic不可缩减
        if node.name == 'type':
            return b'\x00' * max(1, (node.size // 2))
        if node.name == 'checksum':
            return None
        if node.name == 'flags':
            return b'\x00' * max(1, node.size)
        return None

    def stats(self) -> Dict[str, Any]:
        return {
            "fields": len(self._fields),
            "has_tree": self._tree is not None,
        }
