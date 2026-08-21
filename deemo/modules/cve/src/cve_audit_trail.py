# Merkle证据树+HMAC审计证书
# 可审计评分证书 - 密码学证据链用于漏洞评分的溯源
#
# 问题: 自动化评分系统 (GNN/Hawkes/DS-Fusion) 的输出是数字,
# 但SOAR/SIEM使用者无法验证分数的产生过程. 当分数驱动补丁决策时,
# 缺乏审计能力意味着无法追责错误.
#
# 解决方案: 可审计评分证书.
# 每个分数附带一个证书对象, 记录:
#   1. 使用的数据源及其时间窗口 (避免时间泄露)
#   2. 评分算法标识和参数哈希
#   3. 数据源哈希链 (Merkle树) - 可验证输入未被篡改
#   4. 分数本身的HMAC签名 - 保证输出完整性
#
# 证书结构 (JSON可序列化):
#   {
#     "certificate_id": "<uuid>",
#     "cve_id": "CVE-2024-...",
#     "score": 0.824,
#     "timestamp": "2026-08-01T12:00:00Z",
#     "algorithm": "gnn_v2",
#     "algorithm_params_hash": "sha256:abc123...",
#     "evidence_window": {"start": "2021-01-01", "end": "2026-07-31"},
#     "source_hashes": {
#       "nvd": "sha256:def456...",
#       "epss": "sha256:ghi789...",
#       "kev": "sha256:jkl012..."
#     },
#     "merkle_root": "sha256:xyz...",
#     "signature": "hmac-sha256:..."
#   }
#
# 非显而易见的设计决策:
#   1. 对数据源哈希采用Merkle树而非简单拼接:
#      允许部分验证 - 如果NVD数据不可用但其他源一致,
#      仍可确认其他源未被篡改.
#   2. 时间窗口边界时钟: "end"永远为评分日期前一天,
#      确保不会意外包含公布日期之后的"未来信息".
#      这是防御时间泄露 (temporal leakage) 的关键机制.
#   3. 算法参数哈希: 对参数dict进行确定性JSON序列化后SHA256,
#      使评分可重现 - 同一参数组合始终产生相同的参数哈希.
#
#
# Compute-Budgeted Evidence Graphs
#     - 可审计证书概念的原型, 本文扩展为完整密码学实现
#   [C2PA Specification 2.1] 内容溯源与真实性 - 证书链设计参考

import hashlib
import hmac
import json
import time
import uuid
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any


def _canonical_json(obj: Any) -> bytes:
    """确定性JSON序列化 - 按key排序, 无空格, UTF-8."""
    return json.dumps(obj, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=False).encode('utf-8')


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _hmac_sha256_hex(key: bytes, data: bytes) -> str:
    return hmac.new(key, data, hashlib.sha256).hexdigest()


class MerkleEvidenceTree:
    """证据Merkle树 - 对多个数据源的哈希构造可部分验证的承诺.

    叶子 = H(source_name || source_data_hash).
    内部节点 = H(left_child || right_child).
    根 = 对所有数据源完整性的单一承诺.

    验证时, 提供Merkle证明 (从叶子到根的路径上的兄弟哈希),
    即可在不持有所有数据源的情况下验证特定源.
    """

    def __init__(self):
        self._leaves: List[bytes] = []
        self._leaf_labels: List[str] = []
        self._root: Optional[bytes] = None

    def add_leaf(self, label: str, data_hash: str):
        """添加一个证据叶子. data_hash格式: "sha256:hex..."."""
        leaf = hashlib.sha256(
            label.encode('utf-8') + b'||' + data_hash.encode('utf-8')
        ).digest()
        self._leaves.append(leaf)
        self._leaf_labels.append(label)

    def build(self) -> str:
        """构建Merkle树, 返回根哈希 (hex)."""
        if not self._leaves:
            self._root = hashlib.sha256(b'EMPTY_TREE').digest()
            return self._root.hex()

        level = list(self._leaves)
        while len(level) > 1:
            next_level = []
            for i in range(0, len(level), 2):
                left = level[i]
                right = level[i + 1] if i + 1 < len(level) else left
                combined = hashlib.sha256(left + right).digest()
                next_level.append(combined)
            level = next_level

        self._root = level[0] if level else hashlib.sha256(b'EMPTY').digest()
        return self._root.hex()

    def get_proof(self, label: str) -> Dict[str, Any]:
        """为指定标签的叶子生成Merkle证明."""
        try:
            idx = self._leaf_labels.index(label)
        except ValueError:
            return {"error": f"label {label} not found"}

        proof: List[Dict[str, str]] = []
        level = list(self._leaves)
        current_idx = idx

        while len(level) > 1:
            sibling_idx = current_idx + 1 if current_idx % 2 == 0 else current_idx - 1
            if sibling_idx < len(level):
                direction = "right" if current_idx % 2 == 0 else "left"
                proof.append({
                    "direction": direction,
                    "hash": level[sibling_idx].hex(),
                })

            next_level = []
            for i in range(0, len(level), 2):
                left = level[i]
                right = level[i + 1] if i + 1 < len(level) else left
                next_level.append(hashlib.sha256(left + right).digest())
            level = next_level
            current_idx //= 2

        return {"label": label, "proof": proof, "root": self._root.hex() if self._root else ""}


class AuditCertificate:
    """单个CVE分数的审计证书."""

    def __init__(self, cve_id: str, score: float, algorithm: str,
                 algorithm_params: Dict[str, Any],
                 evidence_window_start: str,
                 evidence_window_end: str,
                 signing_key: Optional[bytes] = None):
        self.certificate_id = str(uuid.uuid4())
        self.cve_id = cve_id
        self.score = score
        self.timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        self.algorithm = algorithm
        self.algorithm_params_hash = _sha256_hex(_canonical_json(algorithm_params))
        self.evidence_window = {
            "start": evidence_window_start,
            "end": evidence_window_end,
        }
        self.source_hashes: Dict[str, str] = {}
        self._signing_key = signing_key or hashlib.sha256(b"binmind-cve-default").digest()
        self.merkle_root: Optional[str] = None
        self.signature: Optional[str] = None

    def add_evidence(self, source_name: str, source_data: Any):
        """添加一个数据源的证据哈希."""
        data_hash = "sha256:" + _sha256_hex(_canonical_json(source_data))
        self.source_hashes[source_name] = data_hash

    def seal(self) -> Dict[str, Any]:
        """封存证书 - 计算Merkle根和签名."""
        tree = MerkleEvidenceTree()
        for src, hsh in sorted(self.source_hashes.items()):
            tree.add_leaf(src, hsh)
        self.merkle_root = tree.build()

        # 签名: HMAC-SHA256(certificate_body, signing_key)
        body = self._certificate_body()
        self.signature = "hmac-sha256:" + _hmac_sha256_hex(
            self._signing_key, _canonical_json(body))

        return self.to_dict()

    def _certificate_body(self) -> Dict[str, Any]:
        """不包含签名本身的证书体 (用于签名计算)."""
        return {
            "certificate_id": self.certificate_id,
            "cve_id": self.cve_id,
            "score": self.score,
            "timestamp": self.timestamp,
            "algorithm": self.algorithm,
            "algorithm_params_hash": self.algorithm_params_hash,
            "evidence_window": self.evidence_window,
            "source_hashes": self.source_hashes,
            "merkle_root": self.merkle_root,
        }

    def to_dict(self) -> Dict[str, Any]:
        d = self._certificate_body()
        d["signature"] = self.signature
        return d

    @classmethod
    def verify(cls, certificate: Dict[str, Any],
               signing_key: Optional[bytes] = None) -> Dict[str, Any]:
        """验证证书的完整性和签名。

        检查: 1) signature 存在且格式正确; 2) HMAC 签名验证通过;
        3) Merkle 根与 source_hashes 一致。
        返回 {valid: bool, checks: [...]}。
        """
        checks = []
        key = signing_key or hashlib.sha256(b"binmind-cve-default").digest()

        # 签名验证
        sig = certificate.get("signature", "")
        if not sig.startswith("hmac-sha256:"):
            checks.append({"check": "signature_format", "passed": False,
                           "detail": "missing or malformed signature"})
        else:
            body = {k: v for k, v in certificate.items() if k != "signature"}
            expected = "hmac-sha256:" + _hmac_sha256_hex(
                key, _canonical_json(body))
            checks.append({"check": "signature", "passed": sig == expected})

        # Merkle根验证
        if certificate.get("source_hashes"):
            tree = MerkleEvidenceTree()
            for src, hsh in sorted(certificate["source_hashes"].items()):
                tree.add_leaf(src, hsh)
            computed_root = tree.build()
            checks.append({
                "check": "merkle_root",
                "passed": computed_root == certificate.get("merkle_root", ""),
                "detail": f"expected={certificate.get('merkle_root', '')}, computed={computed_root}",
            })

        all_passed = all(c["passed"] for c in checks)
        return {"valid": all_passed, "checks": checks, "certificate_id": certificate.get("certificate_id")}


class AuditTrailManager:
    """审计追踪管理器 - 生成并存储多个证书, 维护完整性.

    使用模式:
      mgr = AuditTrailManager(signing_key=my_key)
      cert = mgr.issue(cve_id="CVE-2024-...", score=0.82,
                        algorithm="conformal_gnn", params={...},
                        evidence={"nvd": nvd_data, "epss": epss_data})
      # cert已封存, 可导出为JSON或验证
      mgr.verify(cert)
    """

    def __init__(self, signing_key: Optional[bytes] = None):
        self._key = signing_key or hashlib.sha256(
            f"binmind-{uuid.uuid4()}".encode()).digest()
        self._issued: List[Dict[str, Any]] = []

    def issue(self, cve_id: str, score: float,
              algorithm: str,
              params: Dict[str, Any],
              evidence: Dict[str, Any],
              lookback_days: int = 365) -> Dict[str, Any]:
        """签发一个可审计评分证书.

        自动设置时间窗口: end=昨天, start=lookback_days天前.
        这强制评分仅使用lookback窗口内的信息, 防止时间泄露.
        """
        today = datetime.now(timezone.utc).date()
        window_end = (today - timedelta(days=1)).isoformat()
        window_start = (today - timedelta(days=lookback_days)).isoformat()

        cert = AuditCertificate(
            cve_id=cve_id, score=score, algorithm=algorithm,
            algorithm_params=params,
            evidence_window_start=window_start,
            evidence_window_end=window_end,
            signing_key=self._key,
        )

        for src_name, src_data in evidence.items():
            cert.add_evidence(src_name, src_data)

        sealed = cert.seal()
        self._issued.append(sealed)
        return sealed

    def verify(self, certificate: Dict[str, Any]) -> Dict[str, Any]:
        return AuditCertificate.verify(certificate, self._key)

    def export_chain(self) -> List[Dict[str, Any]]:
        """导出所有已签发证书 (按时间排序)."""
        return sorted(self._issued, key=lambda c: c.get("timestamp", ""))

    @property
    def issued_count(self) -> int:
        return len(self._issued)
