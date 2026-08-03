"""
修改记录:
  2025-07-17 11:33 - _diff_nodes 增加同哈希短路，对一个目录下多文件未变场景将比较次数降至 O(1)

Merkle 树差异比较 — 利用树结构在 O(log n) 层级上短路，仅递归哈希不同的分支。
核心假设：两个树的结构相同（相同目录树、不同时间点的快照）；结构变化（新增/删除
文件）也可正确处理，但树拓扑不变时性能最优。

依赖于 engine/merkle.py 中的 MerkleNode 和域分隔前缀约定。
"""

from __future__ import annotations

from parallel_deep_dev.engine.merkle import MerkleNode


def diff_trees(
    old_tree: MerkleNode | None,
    new_tree: MerkleNode | None,
) -> tuple[set[str], set[str], set[str]]:
    """比较两棵树，返回 (added, modified, deleted) 文件路径集合。
    根哈希相同 → 整棵树无变化，直接返回空集合——这是递归短路的核心。
    对于 1000+ 文件目录，短路可将比较从 1000 次哈希对比降至数十次。"""
    added: set[str] = set()
    modified: set[str] = set()
    deleted: set[str] = set()

    if old_tree is None and new_tree is None:
        return added, modified, deleted

    if old_tree is None:
        _collect_files(new_tree, added)
        return added, modified, deleted

    if new_tree is None:
        _collect_files(old_tree, deleted)
        return added, modified, deleted

    if (old_tree.hash_val == new_tree.hash_val
            and old_tree.node_type == new_tree.node_type):
        return added, modified, deleted

    _diff_nodes(old_tree, new_tree, added, modified, deleted)
    return added, modified, deleted


def _diff_nodes(
    old: MerkleNode,
    new: MerkleNode,
    added: set[str],
    modified: set[str],
    deleted: set[str],
) -> None:
    """递归比较两个节点。同哈希短路在递归每一层生效。
    两个节点类型不同时（如文件变目录），旧节点全标记删除，新节点全标记新增。"""
    if old.node_type == "file" and new.node_type == "file":
        if old.hash_val != new.hash_val:
            modified.add(new.path)
        return

    if old.node_type == "file":
        deleted.add(old.path)
        if new.node_type == "dir":
            _collect_files(new, added)
        else:
            added.add(new.path)
        return

    if new.node_type == "file":
        _collect_files(old, deleted)
        added.add(new.path)
        return

    # 两个都是目录：按路径对齐比较
    old_map = {c.path: c for c in old.children}
    new_map = {c.path: c for c in new.children}

    for path, old_child in old_map.items():
        if path not in new_map:
            _collect_files(old_child, deleted)
        elif old_child.hash_val != new_map[path].hash_val:
            _diff_nodes(old_child, new_map[path], added, modified, deleted)

    for path, new_child in new_map.items():
        if path not in old_map:
            _collect_files(new_child, added)


def _collect_files(node: MerkleNode | None, result: set[str]) -> None:
    """收集节点下所有文件路径。叶节点直接添加，目录节点递归收集。"""
    if node is None:
        return
    if node.node_type == "file":
        result.add(node.path)
    else:
        for child in node.children:
            _collect_files(child, result)
