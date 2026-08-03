"""
证据链 Merkle 树 — 密码学完整性绑定层。

设计依据:
  RFC 6962 (Certificate Transparency) Merkle Tree Hash 方案，
  适配为安全审计证据链的防篡改数据结构。
  每个 EvidenceNode 作为叶节点，双 SHA-256 构造内部节点哈希，
  根哈希可发布至审计日志或区块链锚定以达成不可否认性。

  区别于 CT: 叶节点不存时间戳，存储证据节点哈希 + 来源模块签名，
  支持事后验证任一中间结果是否被篡改。

修改记录:
  2025-07-15 09:52 - 追加 inclusion_proof 构造，支持选择性披露验证
  2025-07-15 15:03 - 内部节点改用 SHA-256(0x01 || left || right) 防二阶原像攻击
"""

import hashlib
from typing import List, Optional, Tuple


def _leaf_hash(data: bytes) -> bytes:
    """叶节点哈希: SHA-256(0x00 || data)。前缀 0x00 区分叶/内部节点。"""
    return hashlib.sha256(b'\x00' + data).digest()


def _node_hash(left: bytes, right: bytes) -> bytes:
    """内部节点哈希: SHA-256(0x01 || left || right)，防二阶原像攻击。"""
    return hashlib.sha256(b'\x01' + left + right).digest()


def build_merkle_tree(leaves: List[bytes]) -> Tuple[Optional[bytes], List[List[bytes]]]:
    """
    自底向上构造 Merkle 树，返回 (root_hash, levels)。

    levels[0] = 叶层 (已哈希)，levels[-1] = [root_hash]。
    空列表 → (None, [])。
    复杂度: O(n)，单次遍历构建全部层。
    """
    if not leaves:
        return None, []

    hashed_leaves = [_leaf_hash(leaf) for leaf in leaves]
    levels = [hashed_leaves]
    current = hashed_leaves

    while len(current) > 1:
        next_level = []
        for i in range(0, len(current), 2):
            left = current[i]
            # 奇数层: 末节点自复制为右兄弟
            right = current[i + 1] if i + 1 < len(current) else left
            next_level.append(_node_hash(left, right))
        levels.append(next_level)
        current = next_level

    return levels[-1][0], levels


def generate_inclusion_proof(leaf_index: int, leaves: List[bytes]) -> List[Tuple[bytes, bool]]:
    """
    为指定叶节点构造 Merkle inclusion proof (叶→根路径)。

    返回 [(sibling_hash, is_right), ...]。
    is_right = True 表示兄弟在右侧 (本节点为左子)。

    校验序: 从 leaf_hash 逐层:
      is_right → h = _node_hash(h, sibling)
      !is_right → h = _node_hash(sibling, h)
    最终 h 应等于 root_hash。
    """
    if not leaves or leaf_index < 0 or leaf_index >= len(leaves):
        return []

    hashed = [_leaf_hash(leaf) for leaf in leaves]
    proof = []
    idx = leaf_index

    while len(hashed) > 1:
        if idx % 2 == 0:
            # 当前节点为左子
            sibling_idx = idx + 1 if idx + 1 < len(hashed) else idx
            proof.append((hashed[sibling_idx], True))
        else:
            proof.append((hashed[idx - 1], False))
        idx //= 2

        # 折叠当前层 → 上一层
        next_level = []
        for i in range(0, len(hashed), 2):
            left = hashed[i]
            right = hashed[i + 1] if i + 1 < len(hashed) else left
            next_level.append(_node_hash(left, right))
        hashed = next_level

    return proof


def verify_inclusion_proof(leaf_data: bytes, proof: List[Tuple[bytes, bool]], root_hash: bytes) -> bool:
    """从叶数据出发逐层哈希至根，与给定 root_hash 比对。"""
    h = _leaf_hash(leaf_data)
    for sibling, is_right in proof:
        if is_right:
            h = _node_hash(h, sibling)
        else:
            h = _node_hash(sibling, h)
    return h == root_hash


def evidence_to_leaf_bytes(finding_id: str, source_module: str,
                          evidence_type: str, confidence: float,
                          extra_data: bytes = b'') -> bytes:
    """
    证据节点关键字段 → Merkle 叶规范字节序列。

    格式: finding_id || \x00 || source_module || \x00 || evidence_type
           || \x00 || confidence_str || \x00 || extra_data

    分隔符 \x00: 前提为 ID/模块名不含空字节，否则需转义。
    """
    conf_str = f"{confidence:.6f}"
    return (finding_id.encode('utf-8') + b'\x00' +
            source_module.encode('utf-8') + b'\x00' +
            evidence_type.encode('utf-8') + b'\x00' +
            conf_str.encode('utf-8') + b'\x00' +
            extra_data)
