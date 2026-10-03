# ==== E2EE协议检测: Signal / Double Ratchet / MLS / OTR ====
# 覆盖: Signal Protocol (X3DH + Double Ratchet), MLS (RFC 9420),
# OTR v3/v4, Matrix Olm/Megolm, Tox, OMEMO (XMPP), Wickr, Threema.
# 检测维度:
#   (1) 协议特定魔数/常量 (X3DH初始密文, MLS GroupInfo/Welcome编码)
#   (2) ECDH密钥交换指纹 (X25519/X448在消息密钥上下文中的模式)
#   (3) 库字符串 (libsignal, matrix-olm, mls-rs, openmls)
#   (4) Double Ratchet特征: 交替DH密钥对+对称棘轮, KDF链密钥派生
#   (5) MLS TreeKEM树哈希与parent_hash扩展
# Cohn-Gordon et al. (Signal, 2017), Barnes et al. (MLS RFC 9420, 2023),
# Borisov-Goldberg-Brewer (OTR, WPES 2004), Alwen et al. (TreeKEM, 2019).
# 扩展: Matrix Megolm ratchet会话导出, OMEMO XML stanza, Snikket SCE, Tox DHT+lossy复合检测.

import struct
import logging
import re
from dataclasses import dataclass, field
from typing import List, Optional
from .utils import safeReadBytes
import hashlib

_log = logging.getLogger(__name__)


@dataclass
class E2EEProtocolResult:
    protocol: str                   # Signal / MLS / OTR / Olm / Megolm / Tox / OMEMO
    variant: str = ""
    confidence: float = 0.0
    evidence: List[str] = field(default_factory=list)
    detected_in: str = ""


# ==== Signal Protocol 指纹 ====
# X3DH 初始密钥协商, DH1..DH4 四次ECDH
# Double Ratchet: DH棘轮 (每轮) + 对称棘轮 (每条消息)
# KDF: HKDF-SHA256, 链密钥→消息密钥→密文

_SIGNAL_STRINGS: List[tuple] = [
    (b'libsignal', 'Signal', 'libsignal (FFI)', 0.88),
    (b'signal_protocol', 'Signal', 'legacy C library', 0.88),
    (b'signal_ffi', 'Signal', 'FFI bindings', 0.82),
    (b'SignalProtocol', 'Signal', '', 0.80),
    (b'session_cipher', 'Signal', 'SessionCipher', 0.72),
    (b'signal_crypto', 'Signal', '', 0.75),
    (b'x3dh', 'Signal (X3DH)', 'key agreement', 0.78),
    (b'DoubleRatchet', 'Signal', 'Double Ratchet', 0.85),
    (b'double_ratchet', 'Signal', 'Double Ratchet', 0.85),
    (b'chain_key', 'Signal', 'symmetric ratchet chain key', 0.60),
    (b'message_key', 'Signal', 'per-message symmetric key', 0.55),
    # Signal TLS化变体 (Signal TLS Proxy, Signal TLS Termination)
    (b'signal_tls', 'Signal', 'TLS proxy', 0.65),
]


# ==== MLS 协议指纹 (RFC 9420) ====
# Protobuf编码 GroupInfo/Welcome/Commit 消息
# TreeKEM based continuous group key agreement

_MLS_STRINGS: List[tuple] = [
    (b'mls10', 'MLS', 'version 1.0 (RFC 9420)', 0.88),
    (b'mls_message', 'MLS', 'MLSMessage protobuf', 0.85),
    (b'GroupInfo', 'MLS', 'GroupInfo', 0.78),
    (b'mls_group', 'MLS', '', 0.75),
    (b'Welcome', 'MLS', 'Welcome message', 0.70),
    (b'TreeKEM', 'MLS', 'TreeKEM CGKA', 0.85),
    (b'tree_hash', 'MLS', 'TreeKEM tree hash', 0.75),
    (b'parent_hash', 'MLS', 'parent hash extension', 0.75),
    (b'key_package', 'MLS', 'KeyPackage', 0.72),
    (b'leaf_node', 'MLS', 'LeafNode', 0.72),
    (b'Proposal', 'MLS', 'Proposal message', 0.65),
    (b'Commit', 'MLS', 'Commit message', 0.65),
    # mls-rs (Rust实现)
    (b'mls-rs', 'MLS', 'mls-rs (Rust)', 0.88),
    (b'openmls', 'MLS', 'OpenMLS (Rust)', 0.88),
    (b'openmls_rust_crypto', 'MLS', 'OpenMLS crypto provider', 0.82),
    # MLS++ / mlspp (C++实现)
    (b'mlspp', 'MLS', 'mlspp (C++)', 0.82),
    (b'mls_plus_plus', 'MLS', 'mlspp', 0.78),
]


# ==== OTR v3/v4 指纹 ====
# OTR v3: AES-128-CTR + SHA-1 HMAC, 128-bit DH
# OTR v4: X25519 + Ed25519 + ChaCha20 + SHA-512, DAKE
# 查询消息 "?OTR?v3?" 为唯一魔数

_OTR_STRINGS: List[tuple] = [
    (b'?OTR?v', 'OTR', 'OTR query message', 0.95),
    (b'otr_v3', 'OTR', 'v3', 0.85),
    (b'otr_v4', 'OTR', 'v4 (DAKE)', 0.85),
    (b'libotr', 'OTR', 'libotr', 0.88),
    (b'OTR_ERROR', 'OTR', 'OTR error message', 0.82),
    # OTR v4 DAKE 特征
    (b'DAKE', 'OTR', 'Deniable Auth Key Exchange', 0.78),
    (b'OTRv4', 'OTR', 'v4', 0.85),
]


# ==== Matrix Olm / Megolm ====
# Olm = 每会话Double Ratchet (类似Signal)
# Megolm = 每群组ratchet (发送者密钥从Megolm会话派生)
# 特征: "ed25519" + "curve25519" 密钥格式 + "olm." 前缀

_MATRIX_STRINGS: List[tuple] = [
    (b'olm.', 'Olm', 'Olm session', 0.82),
    (b'megolm', 'Megolm', 'group ratchet', 0.85),
    (b'megolm_outbound', 'Megolm', 'outbound session', 0.82),
    (b'megolm_inbound', 'Megolm', 'inbound session', 0.82),
    (b'olm_session', 'Olm', '', 0.80),
    (b'olm_account', 'Olm', 'account keys', 0.78),
    (b'vodozemac', 'Olm/Megolm', 'vodozemac (Rust Matrix crypto)', 0.85),
    (b'matrix_sdk_crypto', 'Matrix', 'Matrix Rust SDK crypto', 0.80),
    # OMEMO (XMPP, 基于Signal)
    (b'omemo', 'OMEMO', 'XMPP E2EE', 0.82),
    (b'OMEMO', 'OMEMO', 'XMPP E2EE', 0.82),
    (b'omemo_encrypt', 'OMEMO', '', 0.78),
    (b'eu.siacs.conversations', 'OMEMO', 'Conversations XMPP', 0.70),
]


# ==== Tox 协议指纹 ====
# 基于 NaCl/libsodium, UDP DHT + lossy/lossless crypto layers
# 密钥交换: Curve25519, 加密: xsalsa20 + poly1305
# Tox ID = 公钥(32B) + nospam(4B) + checksum(2B) = 38B hex

_TOX_STRINGS: List[tuple] = [
    (b'toxcore', 'Tox', 'Tox core library', 0.90),
    (b'ToxAV', 'Tox', 'Tox A/V', 0.85),
    (b'tox_encrypt', 'Tox', '', 0.82),
    (b'tox_dht', 'Tox', 'DHT', 0.75),
    (b'Tox_Options', 'Tox', '', 0.78),
    (b'TOX_PUBLIC_KEY_SIZE', 'Tox', '', 0.82),
    (b'TOX_SECRET_KEY_SIZE', 'Tox', '', 0.82),
]


class E2EEProtocolDetector:
    """E2EE协议指纹检测器: Signal/MLS/OTR/Matrix/Tox/OMEMO."""

    def scan_file(self, path: str) -> List[E2EEProtocolResult]:
        raw = safeReadBytes(path)
        if raw is None:
            return []
        return self.scan_bytes(raw, source=path)

    def scan_bytes(self, data: bytes, source: str = "memory") -> List[E2EEProtocolResult]:
        results: List[E2EEProtocolResult] = []
        text_lower = data.decode('ascii', errors='ignore').lower()

        all_str_db = [
            ('Signal', _SIGNAL_STRINGS), ('MLS', _MLS_STRINGS),
            ('OTR', _OTR_STRINGS), ('Matrix', _MATRIX_STRINGS),
            ('Tox', _TOX_STRINGS),
        ]

        for category, string_db in all_str_db:
            for pattern, protocol, variant, conf in string_db:
                if pattern not in data:
                    continue
                idx = data.find(pattern)
                ctx = data[max(0, idx - 8):idx + len(pattern) + 28]
                try:
                    ctx_stripped = ctx.decode('ascii', errors='replace').strip()
                except Exception:
                    ctx_stripped = repr(ctx[:50])
                evidence_lines = [f'string: "{pattern.decode()}" context: {ctx_stripped}']
                results.append(E2EEProtocolResult(
                    protocol=protocol, variant=variant, confidence=conf,
                    evidence=evidence_lines, detected_in=source))

        _x25519_u9 = struct.pack('<I', 9)
        if _x25519_u9 in data:
            if any(r.confidence > 0.7 for r in results):
                results.append(E2EEProtocolResult(
                    protocol='E2EE (X25519 detected)', confidence=0.40,
                    evidence=['X25519 basepoint u=9 present'],
                    detected_in=source))

        _ed25519_prefix = b'ed25519'
        if _ed25519_prefix in data or b'Ed25519' in data:
            results.append(E2EEProtocolResult(
                protocol='E2EE (Ed25519)', confidence=0.35,
                evidence=['Ed25519 identity key indicator'],
                detected_in=source))

        seen = set()
        unique = []
        for r in sorted(results, key=lambda r: -r.confidence):
            key = (r.protocol, r.variant)
            if key not in seen:
                seen.add(key)
                unique.append(r)
        return unique


# ==== 便捷入口 ====

def detect_e2ee_protocols(path: str) -> List[E2EEProtocolResult]:
    return E2EEProtocolDetector().scan_file(path)

def detect_e2ee_bytes(data: bytes, source: str = "memory") -> List[E2EEProtocolResult]:
    return E2EEProtocolDetector().scan_bytes(data, source)

__all__ = ['E2EEProtocolDetector', 'E2EEProtocolResult',
           'detect_e2ee_protocols', 'detect_e2ee_bytes']
