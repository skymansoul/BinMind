# 初始实现：离线验证器 + 透明度日志摘要
# 增加冲突检测：两个节点声称同一 patch_id 但内容不同

"""Provenance Verifier — 补丁来源独立验证器。

不依赖创建者的基础设施，仅需：
  1. 补丁节点（及其完整 DAG 上下文）
  2. 可信根公钥集
  3. 验证策略

即可独立完成整条补丁来源链的验证。适用场景：
  - 供应链审计：第三方对发布的 binary patch 做来源追溯
  - 合规检查：确认所有补丁来源满足 M-of-N 签名策略
  - 事件响应：确认某补丁是否来自声称的创建者

与 Attestor 的差异：
  Attestor 创建签名和证明。
  Verifier 仅消费它们 —— 不需要私钥，可完全离线运行。

透明性保证：
  每个验证操作输出结构化摘要，摘要本身可被进一步签名并
  发布到透明度日志（如 rekor），形成不可否认的验证记录。
"""

import json
import time
import hashlib
import logging
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple, Set
from enum import Enum

from .patch_provenance import (
    ProvenanceNode, ProvenanceStore, EdgeKind, content_id,
)
from .provenance_attestor import (
    AttestationPolicy, AttestationPayload, Ed25519Signer,
)

_log = logging.getLogger(__name__)


class VerificationStatus(str, Enum):
    PASSED = "passed"               # 所有检查通过
    FAILED_SELF_CONSISTENCY = "failed_self_consistency"
    FAILED_SIGNATURE = "failed_signature"
    FAILED_POLICY = "failed_policy"
    FAILED_CHAIN_INTEGRITY = "failed_chain_integrity"
    FAILED_ID_CONFLICT = "failed_id_conflict"  # 同 patch_id 异内容
    FAILED_MISSING_KEY = "failed_missing_key"


@dataclass
class VerificationEntry:
    """单节点的验证结果条目。"""
    node_id: str
    patch_id: str
    status: VerificationStatus
    reason: str = ""
    attestation_count: int = 0
    valid_attestations: int = 0
    chain_depth: int = 0
    verified_at: float = 0.0


@dataclass
class VerificationSummary:
    """整次验证运行的摘要。"""
    run_id: str = ""                # 验证运行的唯一标识
    total_nodes: int = 0
    passed: int = 0
    failed: int = 0
    entries: List[VerificationEntry] = field(default_factory=list)
    conflict_pairs: List[Tuple[str, str]] = field(default_factory=list)
    verified_at: float = 0.0
    verifier_version: str = "1.0.0"
    # 摘要哈希 — 可发布到透明度日志
    summary_hash: str = ""

    def compute_hash(self) -> str:
        raw = json.dumps({
            'total': self.total_nodes,
            'passed': self.passed,
            'failed': self.failed,
            'conflicts': [[a, b] for a, b in self.conflict_pairs],
            'at': self.verified_at,
        }, sort_keys=True)
        self.summary_hash = hashlib.sha256(raw.encode()).hexdigest()
        return self.summary_hash

    def to_dict(self) -> Dict:
        return {
            'run_id': self.run_id,
            'total_nodes': self.total_nodes,
            'passed': self.passed,
            'failed': self.failed,
            'entries': [
                {'node_id': e.node_id, 'patch_id': e.patch_id,
                 'status': e.status.value, 'reason': e.reason,
                 'attestation_count': e.attestation_count,
                 'valid_attestations': e.valid_attestations,
                 'chain_depth': e.chain_depth}
                for e in self.entries
            ],
            'conflicts': [[a, b] for a, b in self.conflict_pairs],
            'verified_at': self.verified_at,
            'summary_hash': self.summary_hash,
        }


# 独立验证器

class ProvenanceVerifier:
    """补丁来源独立验证器 —— 不依赖私钥，纯消费侧。

    用法:
        verifier = ProvenanceVerifier(trusted_pubkeys)
        summary = verifier.verify_store(store, policy)
        print(f"通过率: {summary.passed}/{summary.total_nodes}")
    """

    def __init__(self, trusted_pubkeys: Dict[str, bytes] = None):
        # trusted_pubkeys: {signer_id → raw Ed25519 public key bytes (32 bytes)}
        self._trusted_pubkeys: Dict[str, bytes] = trusted_pubkeys or {}
        self._last_summary: Optional[VerificationSummary] = None

    def register_key(self, signer_id: str, pubkey_raw: bytes):
        """注册可信公钥（Ed25519 raw 格式，32 bytes）。"""
        if len(pubkey_raw) != 32:
            _log.warning("公钥长度异常：%d bytes (预期 32)", len(pubkey_raw))
        self._trusted_pubkeys[signer_id] = pubkey_raw

    def load_keys_from_json(self, path: str):
        """从 JSON 文件加载可信公钥集。"""
        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        for sid, hex_key in data.items():
            self._trusted_pubkeys[sid] = bytes.fromhex(hex_key)
        _log.info("加载 %d 个可信公钥", len(data))

# 核心验证流程

    def verify_store(self, store: ProvenanceStore,
                     policy: AttestationPolicy = None,
                     max_depth: int = 100) -> VerificationSummary:
        """对存储中所有节点执行完整验证。

        流程：
          1. 检查所有节点的自洽性（node_id 计算验证）
          2. 按 patch_id 分组，检测 ID 冲突（同 ID 异内容）
          3. 对每个节点验证其证明签名
          4. 验证 DAG 拓扑完整性（边引用的目标是否都存在）
          5. 检查每个节点的证明是否满足策略要求
        """
        policy = policy or AttestationPolicy(required_signatures=1)
        now = time.time()
        run_id = hashlib.sha256(f"{now}:{len(store)}".encode()).hexdigest()[:16]

        summary = VerificationSummary(
            run_id=run_id,
            verified_at=now,
        )
        entries: List[VerificationEntry] = []
        conflicts: List[Tuple[str, str]] = []

        # 收集所有节点
        all_nodes = list(store._nodes.values())
        summary.total_nodes = len(all_nodes)

        # 第 1 步：patch_id 冲突检测
        pid_map: Dict[str, List[str]] = {}  # patch_id → [node_id, ...]
        for node in all_nodes:
            if node.patch_id:
                pid_map.setdefault(node.patch_id, []).append(node.node_id)

        for pid, nids in pid_map.items():
            if len(nids) < 2:
                continue
            # 检查内容哈希是否一致
            nodes = [store.get(nid) for nid in nids]
            content_hashes = set(n.patch_content_hash for n in nodes if n)
            if len(content_hashes) > 1:
                for i in range(len(nids)):
                    for j in range(i + 1, len(nids)):
                        conflicts.append((nids[i], nids[j]))

        summary.conflict_pairs = conflicts

        # 统计冲突节点
        conflict_nids: Set[str] = set()
        for a, b in conflicts:
            conflict_nids.add(a)
            conflict_nids.add(b)

        # 第 2 步：逐节点验证
        for node in all_nodes:
            if node.node_id in conflict_nids:
                entries.append(VerificationEntry(
                    node_id=node.node_id, patch_id=node.patch_id,
                    status=VerificationStatus.FAILED_ID_CONFLICT,
                    reason="同一 patch_id 存在内容冲突",
                    attestation_count=len(node.attestations),
                    verified_at=now,
                ))
                continue

            entry = self._verify_single_node(node, policy, now)
            entries.append(entry)

        # 第 3 步：DAG 拓扑完整性
        all_nids: Set[str] = {n.node_id for n in all_nodes}
        for node in all_nodes:
            for tgt_id, _ in node.edges_out:
                if tgt_id not in all_nids:
                    # 悬挂引用 → 在对应条目标记
                    for e in entries:
                        if e.node_id == node.node_id:
                            if e.status == VerificationStatus.PASSED:
                                e.status = VerificationStatus.FAILED_CHAIN_INTEGRITY
                                e.reason = f"边指向不存在的节点: {tgt_id[:16]}"
                            break

        # 汇总
        summary.entries = entries
        summary.passed = sum(1 for e in entries
                            if e.status == VerificationStatus.PASSED)
        summary.failed = summary.total_nodes - summary.passed
        summary.compute_hash()
        self._last_summary = summary
        return summary

    def _verify_single_node(self, node: ProvenanceNode,
                            policy: AttestationPolicy,
                            now: float) -> VerificationEntry:
        """验证单个节点。返回结构化条目而非 raw tuple。"""
        entry = VerificationEntry(
            node_id=node.node_id,
            patch_id=node.patch_id,
            status=VerificationStatus.PASSED,
            attestation_count=len(node.attestations),
            verified_at=now,
        )

        # 自洽性
        if not self._check_self_consistency(node):
            entry.status = VerificationStatus.FAILED_SELF_CONSISTENCY
            entry.reason = "node_id 自洽性检查失败"
            return entry

        # 创建者签名验证
        if node.creator_signature:
            pk = self._trusted_pubkeys.get(node.creator_id)
            if pk is None:
                entry.status = VerificationStatus.FAILED_MISSING_KEY
                entry.reason = f"找不到创建者 {node.creator_id} 的公钥"
                return entry
            if not self._verify_ed25519_raw(
                pk, node.node_id.encode(), node.creator_signature):
                entry.status = VerificationStatus.FAILED_SIGNATURE
                entry.reason = "创建者签名验证失败"
                return entry

        # 每条证明的签名验证
        valid_count = 0
        for att in node.attestations:
            pk = self._trusted_pubkeys.get(att.signer_id)
            if pk is None:
                continue  # 未知签名者 → 跳过（不计入有效签名）
            claims_json = json.dumps(att.signed_claims, sort_keys=True).encode()
            msg = node.node_id.encode() + b'::' + claims_json
            if self._verify_ed25519_raw(pk, msg, att.signature_bytes):
                valid_count += 1

        entry.valid_attestations = valid_count

        # 策略检查
        ok, reason = policy.is_satisfied(node.attestations)
        if not ok:
            entry.status = VerificationStatus.FAILED_POLICY
            entry.reason = reason
            return entry

        return entry

# 工具方法

    @staticmethod
    def _check_self_consistency(node: ProvenanceNode) -> bool:
        """检查 node_id 是否与节点当前内容一致。"""
        edge_data = json.dumps(
            [[tgt, ek.value] for tgt, ek in node.edges_out],
            sort_keys=True).encode()
        combined = (node.patch_content_hash.encode() +
                    node.patch_metadata_hash.encode() +
                    edge_data +
                    node.creator_id.encode())
        recalc = content_id(combined)
        return recalc == node.node_id

    @staticmethod
    def _verify_ed25519_raw(pubkey_raw: bytes, message: bytes,
                            signature: bytes) -> bool:
        """用 32-byte raw Ed25519 公钥验证签名。

        Ed25519 签名算法：
          - 私钥 32 bytes，公钥 32 bytes，签名 64 bytes
          - 使用 SHA-512 作为内部哈希

        依赖 cryptography 库。无库时返回 False 以拒绝验证。
        """
        if len(pubkey_raw) != 32:
            return False
        if len(signature) != 64:
            return False
        try:
            from cryptography.hazmat.primitives.asymmetric import ed25519
            from cryptography.exceptions import InvalidSignature

            pubkey = ed25519.Ed25519PublicKey.from_public_bytes(pubkey_raw)
            pubkey.verify(signature, message)
            return True
        except ImportError:
            _log.error("cryptography 库不可用 — Ed25519 验证失败，拒绝签名")
            return False
        except InvalidSignature:
            return False

    @property
    def last_summary(self) -> Optional[VerificationSummary]:
        return self._last_summary

    def export_summary(self, path: str):
        """导出验证摘要为 JSON，包含摘要哈希。"""
        if not self._last_summary:
            _log.warning("没有可导出的验证摘要")
            return
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(self._last_summary.to_dict(), f, indent=2)


# 透明度日志摘要

def produce_transparency_log_entry(summary: VerificationSummary,
                                   signer: Ed25519Signer = None) -> Dict:
    """将验证摘要打包为透明度日志条目。

    内容：
      - 验证摘要哈希
      - 时间戳
      - 可选签名（若提供 signer）
    可用于发布到 rekor 或自建透明度日志。
    """
    entry = {
        'kind': 'binmind.patch.provenance',
        'apiVersion': '0.1.0',
        'spec': {
            'summary': summary.to_dict(),
            'summary_hash': summary.summary_hash,
        },
    }
    if signer:
        sig = signer.sign(summary.summary_hash.encode())
        entry['spec']['signature'] = sig.hex()
    return entry
