# 创建: 2026-05-21 14:05
# 修改: 2026-05-21 — SHA-256 Merkle 树 + inclusion proof + 选择性披露
"""
加密 Merkle SBOM — 内容寻址防篡改 + 选择性披露.

Merkle 树封装 SBOM, 支持两个关键属性:
  (a) 防篡改性 — 每条目内容寻址 (SHA-256), 根哈希作为完整性锚点.
  (b) 选择性披露 — inclusion proof 证明某条目在 SBOM 中,
      无需暴露其他条目, 验证方仅需 root hash + proof path.

设计依据:
  1. 内容寻址: 每个 SBOM 条目 = SHA-256(name|version|purl|checksum).
  2. Merkle 根: 签名并发布, 任何条目篡改都会改变根哈希.
  3. Merkle proof 选择性披露: O(log N) inclusion proof,
     链式哈希需要 O(N) 遍历, 对万级组件 SBOM 不可行.

参考标准: Certificate Transparency (RFC 6962) inclusion proof 格式.

创建: 2024-10-11  初始版本, Merkle 树 SBOM + inclusion proof
修改: 2024-10-11  移除未验证的外部引用, 改为 RFC 6962 标准依据
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class SBOMEntry:
    """单个 SBOM 条目——组件或依赖。"""
    name: str
    version: str
    purl: str = ''             # Package URL
    checksum: str = ''         # SHA-256
    entry_hash: str = ''       # 内容哈希 = SHA-256(name|version|purl|checksum)
    children: list[int] = field(default_factory=list)  # 子条目索引


def _hash_entry(entry: SBOMEntry) -> str:
    """条目的内容哈希——作为 Merkle 树叶节点的输入。"""
    if entry.entry_hash:
        return entry.entry_hash
    data = f'{entry.name}|{entry.version}|{entry.purl}|{entry.checksum}'
    entry.entry_hash = hashlib.sha256(data.encode()).hexdigest()
    return entry.entry_hash


# Merkle 树构建

@dataclass
class MerkleProof:
    """Merkle inclusion proof——证明某条目在 SBOM 中。"""
    entry_index: int
    entry_hash: str
    proof_path: list[tuple[str, bool]]  # [(sibling_hash, is_left), ...]
    root_hash: str
    tree_size: int


class MerkleSBOM:
    """Merkle 树封装的 SBOM。

    所有条目哈希后构建二叉树, 根哈希作为完整性锚点。
    支持 inclusion proof 生成与验证——选择性披露。"""

    __slots__ = ('_entries', '_tree', '_root_hash', '_signed_root')

    def __init__(self):
        self._entries: list[SBOMEntry] = []
        self._tree: list[list[str]] = []  # tree[level][index] = hash
        self._root_hash: str = ''
        self._signed_root: str = ''       # root + 签名 (简化: HMAC)

    def add_entry(self, entry: SBOMEntry) -> int:
        idx = len(self._entries)
        self._entries.append(entry)
        return idx

    def build(self) -> str:
        """构建 Merkle 树, 返回 root hash。"""
        if not self._entries:
            self._root_hash = ''
            return ''

        # 叶节点: 每个条目的内容哈希
        leaves = [_hash_entry(e) for e in self._entries]
        # 补齐到 2 的幂
        while len(leaves) & (len(leaves) - 1):
            leaves.append(leaves[-1])  # 用最后一个叶节点填充

        self._tree = [leaves]
        level = leaves

        while len(level) > 1:
            next_level = []
            for i in range(0, len(level), 2):
                left = level[i]
                right = level[i + 1] if i + 1 < len(level) else left
                combined = left + right
                next_level.append(hashlib.sha256(combined.encode()).hexdigest())
            self._tree.append(next_level)
            level = next_level

        self._root_hash = level[0]
        return self._root_hash

    def root_hash(self) -> str:
        return self._root_hash

    def sign(self, secret: str) -> str:
        """用 HMAC 签名 root hash——生产环境替换为 Ed25519。"""
        import hmac
        self._signed_root = hmac.new(
            secret.encode(), self._root_hash.encode(), 'sha256'
        ).hexdigest()
        return self._signed_root

    def verify_signature(self, secret: str) -> bool:
        import hmac
        expected = hmac.new(
            secret.encode(), self._root_hash.encode(), 'sha256'
        ).hexdigest()
        return hmac.compare_digest(self._signed_root, expected)

    def get_proof(self, entry_index: int) -> MerkleProof | None:
        """为 entry_index 生成 Merkle inclusion proof。"""
        if entry_index < 0 or entry_index >= len(self._entries):
            return None
        if not self._tree:
            self.build()

        entry_hash = _hash_entry(self._entries[entry_index])
        proof_path = []
        idx = entry_index

        for level in range(len(self._tree) - 1):
            sibling_idx = idx ^ 1  # 翻转最低位
            is_left = (idx & 1) == 0
            if sibling_idx < len(self._tree[level]):
                proof_path.append((self._tree[level][sibling_idx], is_left))
            idx >>= 1

        return MerkleProof(
            entry_index=entry_index,
            entry_hash=entry_hash,
            proof_path=proof_path,
            root_hash=self._root_hash,
            tree_size=len(self._entries),
        )

    @staticmethod
    def verify_proof(proof: MerkleProof) -> bool:
        """验证 Merkle inclusion proof——不需要完整 SBOM。"""
        current = proof.entry_hash
        for sibling_hash, is_left in proof.proof_path:
            if is_left:
                combined = current + sibling_hash
            else:
                combined = sibling_hash + current
            current = hashlib.sha256(combined.encode()).hexdigest()
        return current == proof.root_hash

    def to_json(self) -> str:
        entries_json = [
            {'name': e.name, 'version': e.version, 'purl': e.purl,
             'checksum': e.checksum, 'entry_hash': _hash_entry(e),
             'children': e.children}
            for e in self._entries
        ]
        return json.dumps({
            'root_hash': self._root_hash,
            'signed_root': self._signed_root,
            'entries': entries_json,
        }, indent=2)

    def stats(self) -> dict:
        return {
            'entries': len(self._entries),
            'tree_depth': len(self._tree),
            'root_hash': self._root_hash[:16] + '...',
            'signed': bool(self._signed_root),
        }


# 选择性披露适配器
# 组织 A 想向组织 B 证明"组件 X 在我们的 SBOM 中"但不暴露其他组件。
# 发送: (entry X, MerkleProof) → B 用已发布的 root hash 验证 proof。

def selective_disclosure(sbom: MerkleSBOM, entry_indices: list[int],
                         secret: str = '') -> dict:
    """为指定条目生成选择性披露包。包含条目 + Merkle proof + 签名 root。"""
    if not sbom.root_hash():
        sbom.build()
    if secret and not sbom._signed_root:
        sbom.sign(secret)

    disclosures = []
    for idx in entry_indices:
        proof = sbom.get_proof(idx)
        if proof:
            entry = sbom._entries[idx]
            disclosures.append({
                'entry': {
                    'name': entry.name,
                    'version': entry.version,
                    'purl': entry.purl,
                    'checksum': entry.checksum,
                },
                'proof': {
                    'root_hash': proof.root_hash,
                    'proof_path': [[h, side] for h, side in proof.proof_path],
                    'tree_size': proof.tree_size,
                },
            })

    return {
        'root_hash': sbom.root_hash(),
        'signed_root': sbom._signed_root,
        'disclosures': disclosures,
    }


__all__ = [
    'SBOMEntry', 'MerkleProof', 'MerkleSBOM',
    'selective_disclosure',
]
