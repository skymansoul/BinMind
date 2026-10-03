# 初始实现：内容寻址的补丁身份 + Merkle-DAG 节点
# 引入带盐哈希，防止预计算攻击对补丁身份的碰撞伪造
# edge 类型新增 "replaces" 关系，支撑补丁废弃链

"""Patch Provenance Chain — 二进制补丁的密码学来源追踪。

问题：现有工具验证补丁安全性但不验证来源。一个经过安全验证的补丁
仍可能是恶意行为者构造的。本模块提供内容寻址的补丁身份、
Merkle-DAG 血缘图和可独立验证的证明链。

技术路线：
  1. Content-addressable patch identity: SHAKE256 XOF 输出，长度可配置
  2. Merkle-DAG 节点：每个补丁节点有输入边（依赖/前驱）和输出边（后继/替代）
  3. 每个节点携带创建者签名和可选的 TEE 证明（如 Intel SGX/TDX quote）
  4. 验证者仅需信任根公钥即可独立验证整条链

与 VeriBin 的差异：
  VeriBin 验证"补丁是否安全可应用"（StA 属性 P1-P4）。
  本模块验证"补丁来自声称的创建者且在传递过程中未被篡改"。
  两者正交且互补。

// 设计依据：
//   - CRDT 社区使用 Merkle-DAG 实现无冲突复制数据类型，借鉴其 DAG 拓扑
//   - Sigstore/rekor 使用 Merkle tree 做软件供应链透明度日志
//   - 本实现的不同：操作在二进制补丁字节级而非容器镜像级；
//     每个节点同时是 Merkle-DAG 节点和内容寻址 blob
"""

import os
import json
import time
import hashlib
import struct
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple, Set
from collections import OrderedDict
from enum import Enum


# 内容寻址哈希
# SHAKE256 可变长度输出，默认 256-bit。
# 长度可配：256/384/512 bit，应对不同安全级别的场景。
# 盐值绑定到补丁创建者身份，防预计算碰撞。

def content_id(data: bytes, salt: bytes = b"", out_bytes: int = 32) -> str:
    """对任意字节序列生成内容寻址标识符。
    out_bytes: 输出字节数 (32 → 256-bit, 48 → 384-bit, 64 → 512-bit)。
    """
    h = hashlib.shake_256(salt + data)
    return h.hexdigest(out_bytes)


def content_id_file(path: str, salt: bytes = b"", out_bytes: int = 32) -> str:
    """对文件内容生成内容寻址标识符。"""
    with open(path, 'rb') as f:
        return content_id(f.read(), salt, out_bytes)


# 边类型

class EdgeKind(str, Enum):
    DERIVED_FROM = "derived_from"     # B 衍生自 A（如补丁迭代）
    REPLACES = "replaces"             # B 替代 A（A 标记为废弃）
    DEPENDS_ON = "depends_on"         # B 依赖 A 先应用
    ATTESTED_BY = "attested_by"       # 节点被某证明者签名
    MERGED_FROM = "merged_from"       # 合并自多个前驱


# 证明负载

@dataclass
class AttestationPayload:
    """单条证明：证明者对补丁节点的密码学签名。

    支持两种证明模式：
      - 裸签名 (Ed25519/ECDSA)：轻量，适用 CI/CD pipeline
      - TEE 证明 (SGX/TDX/SEV quote)：硬件级可信执行环境背书
    """
    signer_id: str                    # 证明者标识符
    signature_algorithm: str = "ed25519"  # ed25519 | ecdsa-p256 | tee-quote
    signature_bytes: bytes = b""      # 签名原始字节
    tee_quote: bytes = b""            # TEE quote（若适用）
    signed_at: float = 0.0            # POSIX 时间戳
    signed_claims: Dict[str, str] = field(default_factory=dict)
    # claims 示例: {"reviewed": "true", "test_passed": "21/21"}

    def to_dict(self) -> Dict:
        return {
            'signer_id': self.signer_id,
            'alg': self.signature_algorithm,
            'sig': self.signature_bytes.hex() if self.signature_bytes else '',
            'tee_quote': self.tee_quote.hex() if self.tee_quote else '',
            'at': self.signed_at,
            'claims': dict(self.signed_claims),
        }

    @classmethod
    def from_dict(cls, d: Dict) -> 'AttestationPayload':
        return cls(
            signer_id=d['signer_id'],
            signature_algorithm=d.get('alg', 'ed25519'),
            signature_bytes=bytes.fromhex(d['sig']) if d.get('sig') else b'',
            tee_quote=bytes.fromhex(d['tee_quote']) if d.get('tee_quote') else b'',
            signed_at=d.get('at', 0.0),
            signed_claims=d.get('claims', {}),
        )


# Merkle-DAG 节点

@dataclass
class ProvenanceNode:
    """补丁来源图中的节点。

    每个节点：
      - 内容寻址：node_id = content_id(patch_bytes + metadata_hash)
      - 携带创建者签名
      - 有向边指向前驱/后继节点
      - 可累积多个证明（多签名 → 信任去中心化）
    """
    node_id: str = ""                 # 内容寻址标识符（填充后）
    patch_id: str = ""                # 人类可读补丁标识
    patch_content_hash: str = ""      # 补丁二进制字节的哈希
    patch_metadata_hash: str = ""     # 补丁元数据的哈希
    creator_id: str = ""              # 创建者标识符
    creator_signature: bytes = b""    # 创建者对 node_id 的签名
    created_at: float = 0.0
    edges_out: List[Tuple[str, EdgeKind]] = field(default_factory=list)
    # edges_out: [(target_node_id, edge_kind), ...]
    attestations: List[AttestationPayload] = field(default_factory=list)
    metadata: Dict = field(default_factory=dict)

    def compute_id(self, salt: bytes = b"") -> str:
        """从补丁内容和元数据计算节点 ID。
        同时覆盖边信息 → 对图拓扑敏感。
        """
        edge_data = json.dumps(
            [[tgt, ek.value] for tgt, ek in self.edges_out],
            sort_keys=True).encode()
        combined = (self.patch_content_hash.encode() +
                    self.patch_metadata_hash.encode() +
                    edge_data +
                    self.creator_id.encode())
        self.node_id = content_id(combined, salt)
        return self.node_id

    def add_edge(self, target_id: str, kind: EdgeKind):
        if (target_id, kind) not in self.edges_out:
            self.edges_out.append((target_id, kind))

    def add_attestation(self, att: AttestationPayload):
        self.attestations.append(att)

    def to_dict(self) -> Dict:
        return {
            'node_id': self.node_id,
            'patch_id': self.patch_id,
            'patch_content_hash': self.patch_content_hash,
            'patch_metadata_hash': self.patch_metadata_hash,
            'creator_id': self.creator_id,
            'creator_sig': self.creator_signature.hex(),
            'created_at': self.created_at,
            'edges_out': [[tgt, ek.value] for tgt, ek in self.edges_out],
            'attestations': [a.to_dict() for a in self.attestations],
            'metadata': self.metadata,
        }

    @classmethod
    def from_dict(cls, d: Dict) -> 'ProvenanceNode':
        node = cls(
            node_id=d.get('node_id', ''),
            patch_id=d.get('patch_id', ''),
            patch_content_hash=d.get('patch_content_hash', ''),
            patch_metadata_hash=d.get('patch_metadata_hash', ''),
            creator_id=d.get('creator_id', ''),
            creator_signature=bytes.fromhex(d.get('creator_sig', '')),
            created_at=d.get('created_at', 0.0),
            edges_out=[(tgt, EdgeKind(ek)) for tgt, ek in d.get('edges_out', [])],
            metadata=d.get('metadata', {}),
        )
        for att_dict in d.get('attestations', []):
            node.attestations.append(AttestationPayload.from_dict(att_dict))
        return node


# Merkle-DAG 存储层

class ProvenanceStore:
    """内容寻址的节点存储。

    O(1) 按 node_id 查找，支持批量导入/导出。
    存储后端可插拔：内存（测试）、LMDB（生产）、SQLite（便携）。
    """

    def __init__(self):
        self._nodes: Dict[str, ProvenanceNode] = {}
        self._index_by_patch_id: Dict[str, str] = {}  # patch_id → node_id

    def put(self, node: ProvenanceNode):
        if not node.node_id:
            node.compute_id()
        self._nodes[node.node_id] = node
        if node.patch_id:
            self._index_by_patch_id[node.patch_id] = node.node_id

    def get(self, node_id: str) -> Optional[ProvenanceNode]:
        return self._nodes.get(node_id)

    def get_by_patch_id(self, patch_id: str) -> Optional[ProvenanceNode]:
        nid = self._index_by_patch_id.get(patch_id)
        return self._nodes.get(nid) if nid else None

    def children_of(self, node_id: str) -> List[ProvenanceNode]:
        """返回以此节点为源的所有后继节点。"""
        node = self._nodes.get(node_id)
        if not node:
            return []
        result = []
        for tgt_id, _ in node.edges_out:
            tgt = self._nodes.get(tgt_id)
            if tgt:
                result.append(tgt)
        return result

    def lineage(self, node_id: str) -> List[ProvenanceNode]:
        """DFS 沿 derived_from 边回溯，返回从根到当前节点的血缘链。"""
        chain = []
        visited: Set[str] = set()
        current = self._nodes.get(node_id)
        while current and current.node_id not in visited:
            visited.add(current.node_id)
            chain.append(current)
            # 找第一个 derived_from 前驱
            parent = None
            for tgt_id, ek in current.edges_out:
                if ek == EdgeKind.DERIVED_FROM:
                    parent = self._nodes.get(tgt_id)
                    break
            if parent is None:
                # 尝试从入边找（其他节点指向当前节点的 derived_from 边）
                for nid, node in self._nodes.items():
                    for tgt, ek in node.edges_out:
                        if tgt == current.node_id and ek == EdgeKind.DERIVED_FROM:
                            parent = node
                            break
                    if parent:
                        break
            current = parent
        chain.reverse()
        return chain

    def export_json(self, path: str):
        data = {'nodes': [n.to_dict() for n in self._nodes.values()]}
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)

    @classmethod
    def import_json(cls, path: str) -> 'ProvenanceStore':
        store = cls()
        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        for nd in data.get('nodes', []):
            node = ProvenanceNode.from_dict(nd)
            store.put(node)
        return store

    def __len__(self):
        return len(self._nodes)
