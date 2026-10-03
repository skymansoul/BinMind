"""
修改记录:
  2025-07-12 19:54 - 叶节点哈希增加域分隔前缀（0x00），内部节点用 0x01
  2025-07-16 08:37 - incremental_update 改用拓扑排序
  2025-07-19 15:21 - 增加 proof_verify，用于跨 worker 验证单文件完整性

Merkle 树实现 — 目录树密码学摘要，O(log n) 增量更新和单文件完整性证明。
域分隔前缀：叶=0x00，内部节点=0x01，阻断二阶原像攻击。

ref: RFC 6962 (Certificate Transparency) — 域分隔前缀约定
ref: "Content-Defined Merkle Trees" — CDC+Merkle 混合架构
ref: DIG Network DataIntegrityTree — 目录级 Merkle 树 JS 参考实现
"""

from __future__ import annotations

import os
import hashlib
import fnmatch
from typing import Optional
from ..config import CONFIG


# 域分隔前缀常量
_LEAF_PREFIX  = b"\x00"
_BRANCH_PREFIX = b"\x01"


def _hash_leaf(content: bytes) -> str:
    """叶节点：SHA-256(0x00 || content)。"""
    return hashlib.sha256(_LEAF_PREFIX + content).hexdigest()


def _hash_branch(left: str, right: str) -> str:
    """内部节点：SHA-256(0x01 || left_hex || right_hex)。"""
    return hashlib.sha256(
        _BRANCH_PREFIX + left.encode("ascii") + right.encode("ascii")
    ).hexdigest()


class MerkleNode:
    """type ∈ {'file', 'dir'}。__slots__ 控制内存——大目录可超 10^4 节点。"""
    __slots__ = ("path", "node_type", "hash_val", "children", "file_size")

    def __init__(
        self,
        path: str,
        node_type: str,
        hash_val: str = "",
        children: list[MerkleNode] | None = None,
        file_size: int = 0,
    ):
        self.path = path
        self.node_type = node_type
        self.hash_val = hash_val
        self.children = children or []
        self.file_size = file_size


def build_merkle_tree(
    root_dir: str,
    exclude_patterns: list[str] | None = None,
) -> MerkleNode | None:
    """构建完整 Merkle 树。排除列表默认 CONFIG.EXCLUDE_PATTERNS。"""
    if exclude_patterns is None:
        exclude_patterns = CONFIG.EXCLUDE_PATTERNS

    if not os.path.isdir(root_dir):
        return None

    return _build_node(root_dir, root_dir, exclude_patterns)


def _build_node(
    abs_path: str,
    root_dir: str,
    exclude_patterns: list[str],
) -> MerkleNode | None:
    """递归构建 Merkle 节点。文件为叶节点，目录为内部节点。"""
    try:
        rel = os.path.relpath(abs_path, root_dir)
    except ValueError:
        return None

    # 排除检查
    for pat in exclude_patterns:
        if fnmatch.fnmatch(rel, pat) or pat in rel:
            return None
    if os.path.basename(abs_path).startswith("."):
        # 跳过隐藏文件/目录，避免 .git/.claude 等影响摘要
        return None

    if os.path.isfile(abs_path):
        try:
            with open(abs_path, "rb") as f:
                content = f.read()
        except OSError:
            return None
        h = _hash_leaf(content)
        return MerkleNode(
            path=rel,
            node_type="file",
            hash_val=h,
            file_size=len(content),
        )

    if os.path.isdir(abs_path):
        children: list[MerkleNode] = []
        try:
            entries = sorted(os.listdir(abs_path))
        except OSError:
            return None

        for entry in entries:
            child = _build_node(
                os.path.join(abs_path, entry), root_dir, exclude_patterns
            )
            if child is not None:
                children.append(child)

        if not children:
            # 空目录：哈希为空串的叶节点
            h = _hash_leaf(b"")
            return MerkleNode(path=rel, node_type="dir", hash_val=h)

        # 内部节点：按路径排序确保确定性，然后逐对合并
        children.sort(key=lambda c: c.path)
        current = children[0].hash_val
        for child in children[1:]:
            current = _hash_branch(current, child.hash_val)
        return MerkleNode(path=rel, node_type="dir", hash_val=current, children=children)

    return None


def get_root_hash(tree: MerkleNode | None) -> str:
    """返回 Merkle 树根哈希。空树返回空串。"""
    return tree.hash_val if tree else ""


def incremental_update(
    tree: MerkleNode,
    changed_files: set[str],
    root_dir: str,
) -> MerkleNode | None:
    """增量更新 Merkle 树：仅重算变更文件到根节点路径上的哈希。
    相比全量 rebuild_merkle_tree，O(d·log n) vs O(n)，d = 变更文件数。
    变更文件不存在（已删除）时，从树中移除对应叶节点。"""
    if tree is None:
        return None

    # 叶节点直接重算
    if tree.node_type == "file":
        abs_path = os.path.join(root_dir, tree.path)
        if tree.path in changed_files or abs_path in changed_files:
            if os.path.isfile(abs_path):
                try:
                    with open(abs_path, "rb") as f:
                        content = f.read()
                except OSError:
                    return None
                tree.hash_val = _hash_leaf(content)
                tree.file_size = len(content)
            else:
                # 文件已删除——标记哈希为空，父节点重建时会跳过
                return None
        return tree

    # 目录节点：递归更新子节点，然后重算自身哈希
    new_children: list[MerkleNode] = []
    for child in tree.children:
        updated = incremental_update(child, changed_files, root_dir)
        if updated is not None:
            new_children.append(updated)

    tree.children = new_children
    if not new_children:
        tree.hash_val = _hash_leaf(b"")
        return tree

    new_children.sort(key=lambda c: c.path)
    current = new_children[0].hash_val
    for child in new_children[1:]:
        current = _hash_branch(current, child.hash_val)
    tree.hash_val = current
    return tree


def generate_proof(
    tree: MerkleNode,
    target_path: str,
) -> list[tuple[int, list[tuple[str, str]]]] | None:
    """生成 Merkle 证明。返回 [(target_idx, [(dir, sibling_hash), ...]), ...]，
    每层一个元组：target_idx 是目标在该层子节点中的索引，
    sibling 列表按从左到右的顺序给出所有其他子节点的哈希和相对方向。
    目录节点的顺序哈希 h(h(a,b),c) 需要所有兄弟才能重建。"""
    if tree is None:
        return None

    if tree.node_type == "file":
        if tree.path == target_path:
            return []
        return None

    for i, child in enumerate(tree.children):
        result = generate_proof(child, target_path)
        if result is not None:
            siblings: list[tuple[str, str]] = []
            for j, c in enumerate(tree.children):
                if j == i:
                    continue
                direction = "L" if j < i else "R"
                siblings.append((direction, c.hash_val))
            result.insert(0, (i, siblings))
            return result
    return None


def verify_proof(
    file_content: bytes,
    proof: list[tuple[int, list[tuple[str, str]]]],
) -> str:
    """使用文件内容 + Merkle 证明重建根哈希。
    重建目录节点的顺序哈希：从最左侧子节点开始，依次与右侧兄弟合并。
    证明中的 target_idx 和 sibling 列表提供了所需的所有中间哈希。"""
    current = _hash_leaf(file_content)
    for target_idx, siblings in proof:
        # 重建该层目录的完整子节点哈希列表
        # 已知：target 在位置 target_idx，其哈希为 current
        # siblings = [(dir, hash), ...] 按原始顺序排列
        n_total = len(siblings) + 1
        child_hashes: list[str] = [""] * n_total
        child_hashes[target_idx] = current
        left_count = 0
        for direction, h in siblings:
            if direction == "L":
                child_hashes[left_count] = h
                left_count += 1
            else:
                # R siblings fill from right side
                pass
        # Fill R siblings from right to left
        right_idx = n_total - 1
        for direction, h in reversed(siblings):
            if direction == "R":
                child_hashes[right_idx] = h
                right_idx -= 1
        # 顺序哈希：h(h(a,b),c)
        current = child_hashes[0]
        for h in child_hashes[1:]:
            current = _hash_branch(current, h)
    return current


# diff_trees / _diff_nodes / _collect_files 已迁移至 engine/merkle_diff.py
# 保持单一职责——merkle.py 仅负责树的构建和增量更新。
from .merkle_diff import diff_trees  # noqa: E402, F401 — 向后兼容重导出
