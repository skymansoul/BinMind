"""
网络流量密码学分析: TLS/DTLS/SSH/QUIC/WireGuard检测、密钥提取、解密。
三级解密回退: cryptography → PyCryptodome → 纯Python XOR。

检测项: WireGuard Noise握手、SSHv2 KEX算法枚举、JA4 TLS客户端指纹、
QUIC v2 (RFC 9369)版本协商、DTLS 1.3记录层检测、Encrypted ClientHello (ECH)、
GREASE密码套件过滤以抑制误报。
"""

import re
import struct
import hashlib
import io
import logging
from enum import Enum
from typing import Any, Optional, List, Tuple

from .utils import safeReadBytes
# from .constants import AES_SBOX  # 已移除: 与流量分析无关

_log = logging.getLogger(__name__)


class EncryptionType(Enum):
    AES_128_CBC = "aes_128_cbc"
    AES_256_CBC = "aes_256_cbc"
    AES_128_GCM = "aes_128_gcm"
    AES_256_GCM = "aes_256_gcm"
    DES_CBC = "des_cbc"
    DES_EDE3_CBC = "3des_cbc"
    CHACHA20 = "chacha20"
    XOR = "xor"
    RC4 = "rc4"


class KeySourceType(Enum):
    HARDCODED = "hardcoded"
    MEMORY_DUMP = "memory_dump"
    DERIVED = "derived"
    NEGOTIATED = "negotiated"
    TLS_HANDSHAKE = "tls_handshake"
    EXTERNAL = "external"
    NONE = "none"


_TLS_CIPHER_SUITE_MAP = {
    0x0005: "TLS_RSA_WITH_RC4_128_SHA",
    0x000A: "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
    0x002F: "TLS_RSA_WITH_AES_128_CBC_SHA",
    0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA",
    0x003C: "TLS_RSA_WITH_AES_128_CBC_SHA256",
    0x009C: "TLS_RSA_WITH_AES_128_GCM_SHA256",
    0x009D: "TLS_RSA_WITH_AES_256_GCM_SHA384",
    0xC013: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
    0xC014: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
    0xC02B: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    0xC02C: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    0xC02F: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    0xC030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    0xCCA8: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    0xCCA9: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
    0x1301: "TLS_AES_128_GCM_SHA256",
    0x1302: "TLS_AES_256_GCM_SHA384",
    0x1303: "TLS_CHACHA20_POLY1305_SHA256",
    # TLS 1.3附加套件
    0x1304: "TLS_AES_128_CCM_SHA256",
    0x1305: "TLS_AES_128_CCM_8_SHA256",
    # GREASE值 — 0x0A0A, 0x1A1A, ..., 0xFADA — 从结果中排除
}

# GREASE密码套件值(RFC 8701) — 识别为噪声, 非真实套件
_GREASE_CIPHER_SUITES = {0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A,
                          0x6A6A, 0x7A7A, 0x8A8A, 0x9A9A, 0xAAAA, 0xBABA,
                          0xCACA, 0xDADA, 0xEAEA, 0xFAFA}

_TLS_CONTENT_TYPES = {20: "change_cipher_spec", 21: "alert", 22: "handshake", 23: "application_data",
                      24: "heartbeat", 25: "tls12_cid"}
_TLS_HANDSHAKE_TYPES = {1: "client_hello", 2: "server_hello", 11: "certificate",
                         12: "server_key_exchange", 14: "server_hello_done", 16: "client_key_exchange",
                         8: "encrypted_extensions", 13: "certificate_request", 15: "certificate_verify",
                         20: "finished", 21: "certificate_url", 22: "certificate_status"}

_TLS_VERSIONS = {0x0301: "TLS 1.0", 0x0302: "TLS 1.1", 0x0303: "TLS 1.2", 0x0304: "TLS 1.3"}
_DTLS_VERSIONS = {0xFEFF: "DTLS 1.0", 0xFEFD: "DTLS 1.2", 0xFEFC: "DTLS 1.3 (draft)"}

# TLS扩展类型 → (名称, 相关十六进制) — 指纹识别的关键子集
_TLS_EXTENSIONS = {
    0: "server_name", 5: "status_request", 10: "supported_groups",
    11: "ec_point_formats", 13: "signature_algorithms", 16: "application_layer_protocol_negotiation",
    43: "supported_versions", 45: "psk_key_exchange_modes", 51: "key_share",
    57: "quic_transport_parameters", 65037: "encrypted_client_hello",
    17513: "application_settings",
}

# SSHv2 KEX算法 — 通过SSH_MSG_KEXINIT payload字符串匹配检测
_SSH_KEX_ALGORITHMS = [
    b'curve25519-sha256', b'curve25519-sha256@libssh.org',
    b'ecdh-sha2-nistp256', b'ecdh-sha2-nistp384', b'ecdh-sha2-nistp521',
    b'diffie-hellman-group-exchange-sha256', b'diffie-hellman-group14-sha256',
    b'diffie-hellman-group16-sha512', b'sntrup761x25519-sha512@openssh.com',
    # 弱算法: 应标记
    b'diffie-hellman-group1-sha1', b'diffie-hellman-group-exchange-sha1',
    b'diffie-hellman-group14-sha1',
]

# WireGuard Noise握手协议标识符
_WG_INITIATION_MAGIC = struct.pack('<I', 1)  # 消息类型1 = initiation
_WG_RESPONSE_MAGIC   = struct.pack('<I', 2)
_WG_COOKIE_MAGIC     = struct.pack('<I', 3)
_WG_CONSTRUCTION     = b"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"
_WG_MAC1_LABEL       = b"mac1----"
_WG_IDENTIFIER       = b"WireGuard"


class KeyMaterial:
    def __init__(self, key: bytes = b"", key_type: EncryptionType = EncryptionType.AES_256_CBC,
                 source: KeySourceType = KeySourceType.NONE,
                 source_location: str = "", iv: bytes = b"", confidence: float = 0.0,
                 salt: bytes = b"", algorithm: str = "", context: str = ""):
        self.key = key
        self.key_type = key_type
        self.source = source
        self.source_location = source_location
        self.iv = iv
        self.confidence = confidence
        self.salt = salt
        self.algorithm = algorithm
        self.context = context


class DecryptionResult:
    def __init__(self, success: bool = False, decrypted_data: bytes = b"",
                 plaintext: bytes = b"", error: str = ""):
        self.success = success
        self.decrypted_data = decrypted_data
        self.plaintext = plaintext if plaintext or not decrypted_data else decrypted_data
        self.error = error


class TrafficAnalysisResult:
    def __init__(self):
        self.findings: list[dict] = []
        self.protocol: str = ""
        self.tls_version: str = ""
        self.cipher_suites: list[str] = []
        self.sni: str = ""
        self.session_id: str = ""
        self.ja4_fingerprint: str = ""       # JA4哈希 (RFC草案兼容)
        self.ssh_kex_algorithms: list[str] = []
        self.quic_version: str = ""


# GREASE过滤器

def _is_grease(value: int) -> bool:
    """RFC 8701 GREASE: 0x{byte}{byte}形式的值, 其中byte ∈ {0A..FA}。"""
    return value in _GREASE_CIPHER_SUITES


# TLS记录层解析

def _detect_tls_record(data: bytes, offset: int) -> Optional[dict]:
    if offset + 5 > len(data):
        return None
    content_type = data[offset]
    if content_type not in _TLS_CONTENT_TYPES and content_type != 0x17:  # DTLS app_data同为0x17
        return None
    # 先检查DTLS — DTLS版本首字节为0xFE
    if data[offset + 1] == 0xFE:
        return _detect_dtls_record(data, offset)
    version_raw = struct.unpack(">H", data[offset + 1:offset + 3])[0]
    tls_version = _TLS_VERSIONS.get(version_raw, f"unknown (0x{version_raw:04X})")
    return {"content_type": _TLS_CONTENT_TYPES.get(content_type, str(content_type)),
            "tls_version": tls_version, "offset": offset, "is_dtls": False}


def _detect_dtls_record(data: bytes, offset: int) -> Optional[dict]:
    """解析DTLS记录 (DTLS 1.3参考RFC 9147)。"""
    if offset + 13 > len(data):
        return None
    content_type = data[offset]
    version_raw = struct.unpack(">H", data[offset + 1:offset + 3])[0]
    dtls_version = _DTLS_VERSIONS.get(version_raw, f"DTLS unknown (0x{version_raw:04X})")
    epoch = struct.unpack(">H", data[offset + 3:offset + 5])[0]
    seq = struct.unpack(">Q", b"\x00\x00" + data[offset + 5:offset + 11])[0]
    return {"content_type": _TLS_CONTENT_TYPES.get(content_type, str(content_type)),
            "tls_version": dtls_version, "offset": offset, "is_dtls": True,
            "epoch": epoch, "sequence": seq}


# JA4 TLS指纹计算
# JA4 = md5(QUIC|tls_version|SNI|alpns|cipher_suites|extensions)

def _compute_ja4(tls_version: str, sni: str, cipher_suites: List[str],
                 alpns: List[str] = None, extensions: List[int] = None,
                 is_quic: bool = False) -> str:
    """按JA4+规范计算JA4指纹哈希。"""
    proto = "q" if is_quic else "t"
    ver = tls_version.replace(" ", "").replace(".", "")
    sn = sni if sni else ""
    alpn_str = ",".join(sorted(alpns or []))
    cs_str = ",".join(cipher_suites[:15] if len(cipher_suites) > 15 else cipher_suites)
    ext_str = ",".join(str(e) for e in sorted(set(extensions or []))[:15])
    raw = f"{proto}{ver}d{sn}{alpn_str}{cs_str}{ext_str}".encode("ascii", errors="ignore")
    return hashlib.md5(raw).hexdigest()[:12]


# ClientHello解析

def _parse_client_hello(data: bytes, offset: int) -> Optional[dict]:
    try:
        if offset + 44 > len(data):
            return None
        pos = offset
        handshake_type = data[pos]; pos += 1
        if handshake_type != 1:
            return None
        length = struct.unpack(">I", b"\x00" + data[pos:pos + 3])[0]; pos += 3
        tls_version = _TLS_VERSIONS.get(struct.unpack(">H", data[pos:pos + 2])[0], ""); pos += 2
        pos += 32  # random
        session_id_len = data[pos]; pos += 1 + session_id_len
        cipher_count = struct.unpack(">H", data[pos:pos + 2])[0]; pos += 2
        cipher_suites = []
        for _ in range(min(cipher_count, 20)):
            if pos + 2 > len(data):
                break
            cs = struct.unpack(">H", data[pos:pos + 2])[0]; pos += 2
            if _is_grease(cs):
                continue  # 排除GREASE条目
            cipher_suites.append(_TLS_CIPHER_SUITE_MAP.get(cs, f"unknown (0x{cs:04X})"))
        return {"tls_version": tls_version, "cipher_suites": cipher_suites}
    except (struct.error, IndexError):
        return None


def _extract_sni(data: bytes) -> str:
    # 通过域名正则启发式提取Server Name Indication
    for match in re.finditer(rb'[\w.-]{3,60}\.[\w.-]{2,20}', data):
        candidate = match.group().decode("ascii", errors="ignore")
        if "." in candidate and not candidate.startswith("."):
            return candidate
    return ""


def _extract_alpns(data: bytes) -> List[str]:
    """从TLS扩展中提取ALPN协议字符串。启发式扫描。"""
    alpns: List[str] = []
    alpn_pat = re.compile(rb'\x00\x10\x00\x0e\x08(http/1\.[01]|h2|h3|spdy/\d)', re.IGNORECASE)
    known = {b'h2', b'h3', b'http/1.0', b'http/1.1', b'spdy/1', b'spdy/2', b'spdy/3',
             b'websocket', b'ftp', b'stun.turn', b'stun.nat-discovery'}
    for match in alpn_pat.finditer(data):
        try:
            alpn = match.group(1).decode("ascii")
            if alpn not in alpns:
                alpns.append(alpn)
        except Exception:
            pass
    # 同时扫描原始已知ALPN字符串
    for kw in known:
        if kw in data and kw.decode() not in alpns:
            alpns.append(kw.decode())
    return alpns


def _extract_tls_extensions(data: bytes, start: int, end_hint: int) -> List[int]:
    """在ClientHello附近粗略扫描TLS扩展类型字节。"""
    exts = []
    for off in range(start, min(start + 300, end_hint, len(data) - 1)):
        ext_type = struct.unpack(">H", data[off:off + 2])[0]
        if ext_type in _TLS_EXTENSIONS and ext_type not in exts:
            exts.append(ext_type)
        if ext_type == 65037:  # ECH扩展标记
            exts.append(ext_type)
    return exts


# WireGuard Noise握手检测

def _detect_wireguard(data: bytes) -> Optional[dict]:
    """通过Noise协议帧检测WireGuard握手消息。"""
    findings: dict = {"protocol": "wireguard", "messages": []}
    # 搜索WireGuard标识字符串
    if _WG_CONSTRUCTION in data:
        findings["noise_protocol"] = _WG_CONSTRUCTION.decode()
    if _WG_IDENTIFIER in data:
        findings["identifier_found"] = True
    # 消息类型检测 (4字节头: type (LE u32) + 3 reserved)
    for off in range(0, min(len(data) - 4, len(data)), 4):
        msg_type = struct.unpack_from("<I", data, off)[0]
        if msg_type == 1:  # Initiation (148 bytes)
            if off + 148 <= len(data):
                findings["messages"].append({"type": "initiation", "offset": off, "size": 148})
        elif msg_type == 2:  # Response (92 bytes)
            if off + 92 <= len(data):
                findings["messages"].append({"type": "response", "offset": off, "size": 92})
        elif msg_type == 3:  # Cookie reply (64 bytes)
            if off + 64 <= len(data):
                findings["messages"].append({"type": "cookie_reply", "offset": off, "size": 64})
    return findings if findings["messages"] or "noise_protocol" in findings else None


# SSHv2 KEX解析

def _parse_ssh_kex(data: bytes) -> dict:
    """从二进制数据中提取SSH KEX算法名称。"""
    result: dict = {"kex_algorithms": [], "weak_kex": []}
    for algo in _SSH_KEX_ALGORITHMS:
        if algo in data:
            algo_str = algo.decode()
            result["kex_algorithms"].append(algo_str)
            if b'sha1' in algo or b'group1' in algo:
                result["weak_kex"].append(algo_str)
    return result


# QUIC版本解析

_QUIC_VERSIONS = {
    0x00000001: "QUIC v1 (RFC 8999)",
    0xFF00001D: "QUIC v1 draft-29",
    0x709A50C4: "QUIC v2 (RFC 9369)",
    0x6B3343CF: "QUIC v2 draft-00",
    0x51303439: "QUIC Google Q049",
    0x51303530: "QUIC Google Q050",
    0x00000000: "QUIC version negotiation",
}

def _detect_quic(data: bytes) -> Optional[dict]:
    """检测QUIC长头包并提取版本。"""
    findings: dict = {"protocol": "quic", "versions": [], "packets": []}
    # QUIC长头: Header Form(1) | Fixed Bit(1) | Long Packet Type(2) | Reserved(2) | Packet Number Len(2) = byte 0
    # Byte 0: 0b11000000 = 0xC0 长头掩码
    long_header_mask = 0xC0
    min_header = 6  # 1 byte flags + 4 bytes version + 1 byte DCIL

    for off in range(len(data) - min_header):
        if (data[off] & long_header_mask) == long_header_mask:
            try:
                ver = struct.unpack(">I", data[off + 1:off + 5])[0]
                ver_name = _QUIC_VERSIONS.get(ver, f"QUIC version 0x{ver:08X}")
                if ver_name not in findings["versions"]:
                    findings["versions"].append(ver_name)
                findings["packets"].append({"offset": off, "version": ver_name})
            except struct.error:
                continue
    return findings if findings["versions"] else None


# ECH (Encrypted ClientHello) 检测

def _detect_ech(data: bytes) -> bool:
    """
    检测Encrypted ClientHello (TLS扩展类型0xFE0D = 65037)。
    ECH加密SNI及其他隐私敏感ClientHello字段。
    存在则表明客户端支持TLS隐私增强。
    """
    ech_ext = struct.pack(">H", 65037)
    return ech_ext in data


# 已知加密传输的协议指纹模式
_crypto_patterns = {
    "ssl_handshake": re.compile(rb"\x16\x03[\x01-\x04]"),
    "dtls_handshake": re.compile(rb"\x16\xfe[\xfd\xff]"),
    "ssh_banner": re.compile(rb"SSH-[\d.]+"),
    "quic_short": re.compile(rb"[\x00-\x03][\x00-\x0f]{3}\x00"),
}


# 主流量分析器

class CryptoTrafficAnalyzer:
    def __init__(self):
        self._results: list[TrafficAnalysisResult] = []
        self.key_extractor = KeyExtractor()
        self.decryptor = TrafficDecryptor()

    @staticmethod
    def _detect_encryption(data: bytes) -> bool:
        """熵阈值判定数据是否加密——高熵流 XOR 随机字节分布。"""
        if not data:
            return False
        return KeyExtractor._calculate_entropy(data) > 7.0

    def analyze(self, data: bytes) -> list[TrafficAnalysisResult]:
        self._results = []
        for proto_name, pattern in _crypto_patterns.items():
            for match in pattern.finditer(data):
                result = TrafficAnalysisResult()
                result.protocol = proto_name
                result.findings.append({"offset": match.start(), "pattern": proto_name})
                if proto_name == "ssl_handshake":
                    self._enrich_tls(result, data, match.start())
                elif proto_name == "ssh_banner":
                    self._enrich_ssh(result, data, match.start())
                elif proto_name == "quic_short":
                    self._enrich_quic(result, data)
                self._results.append(result)

        # WireGuard检测独立运行(非模式触发)
        wg_result = _detect_wireguard(data)
        if wg_result and (wg_result.get("messages") or wg_result.get("noise_protocol")):
            wg_traffic = TrafficAnalysisResult()
            wg_traffic.protocol = "wireguard"
            wg_traffic.findings = [wg_result]
            self._results.append(wg_traffic)

        return self._results

    def _enrich_tls(self, result: TrafficAnalysisResult, data: bytes, offset: int) -> None:
        record = _detect_tls_record(data, offset)
        if record:
            result.tls_version = record["tls_version"]
            result.findings.append(record)
        sni = _extract_sni(data[max(0, offset - 100):offset + 300])
        if sni:
            result.sni = sni
            result.findings.append({"sni": sni})
        ch = _parse_client_hello(data, offset + 5)
        if ch and ch.get("cipher_suites"):
            result.cipher_suites = ch["cipher_suites"]
            result.tls_version = ch.get("tls_version", result.tls_version)
            result.findings.append({"cipher_suites": ch["cipher_suites"]})

        # JA4指纹
        alpns = _extract_alpns(data)
        tls_exts = _extract_tls_extensions(data, offset, offset + 2000)
        result.ja4_fingerprint = _compute_ja4(
            result.tls_version, sni, result.cipher_suites, alpns, tls_exts)

        # ECH检测
        if _detect_ech(data[offset:offset + 3000]):
            result.findings.append({"ech": "Encrypted ClientHello extension present"})

    def _enrich_ssh(self, result: TrafficAnalysisResult, data: bytes, off: int) -> None:
        kex_info = _parse_ssh_kex(data[off:off + 2048])
        if kex_info["kex_algorithms"]:
            result.ssh_kex_algorithms = kex_info["kex_algorithms"]
            result.findings.append(kex_info)

    def _enrich_quic(self, result: TrafficAnalysisResult, data: bytes) -> None:
        quic_info = _detect_quic(data)
        if quic_info and quic_info["versions"]:
            result.quic_version = quic_info["versions"][0]
            result.findings.append(quic_info)


# 密钥材料提取

class KeyExtractor:
    def __init__(self):
        # 密钥模式表: (正则, 来源标签)
        self.key_patterns = [
            (re.compile(rb'(?:key|KEY)[=:]\s*[\"\']?([A-Za-z0-9+/=]{16,64})[\"\']?'), "string_pattern"),
            (re.compile(rb'\x04\x20([\x20-\x7e]{32})'), "padded_32_byte"),
            (re.compile(rb'static\s+(?:const\s+)?unsigned\s+char\s+\w+\[\]\s*=\s*\{([^}]+)\}'), "c_array_init"),
            # 附加: "key"/"secret"标签旁的裸十六进制字符串
            (re.compile(rb'(?:secret|password|passwd|pwd)[=:]\s*[\"\']([A-Fa-f0-9]{16,64})[\"\']'), "hex_key_string"),
        ]
        self._patterns = self.key_patterns
        # 密码学 API 特征表: (正则, 算法类别)
        self.crypto_api_patterns = [
            (re.compile(rb'\bAES(?:-\d+)?(?:_(?:ECB|CBC|GCM|CTR))?\b', re.I), "aes"),
            (re.compile(rb'\bDES(?:-EDE3)?(?:_CBC)?\b', re.I), "des"),
            (re.compile(rb'\bRC4\b', re.I), "rc4"),
            (re.compile(rb'\bChaCha20\b', re.I), "chacha20"),
            (re.compile(rb'\bXOR\b', re.I), "xor"),
        ]

    @staticmethod
    def _calculate_entropy(data: bytes) -> float:
        """Shannon 熵——高熵数据（>7.0）通常是加密流或密钥材料。"""
        if not data:
            return 0.0
        freq = {}
        for b in data:
            freq[b] = freq.get(b, 0) + 1
        total = len(data)
        entropy = 0.0
        import math as _m
        for cnt in freq.values():
            p = cnt / total
            entropy -= p * _m.log2(p)
        return entropy

    @staticmethod
    def _infer_encryption_type(key_length: int) -> EncryptionType:
        """按密钥字节长度推断加密类型。"""
        if key_length == 16:
            return EncryptionType.AES_128_CBC
        if key_length == 24:
            return EncryptionType.DES_EDE3_CBC
        if key_length == 32:
            return EncryptionType.AES_256_CBC
        if key_length == 8:
            return EncryptionType.DES_CBC
        return EncryptionType.AES_256_CBC

    def extract(self, binary: bytes | str) -> list[KeyMaterial]:
        if isinstance(binary, str):
            raw = safeReadBytes(binary)
            if raw is None:
                return []
        else:
            raw = binary

        keys: list[KeyMaterial] = []
        for pattern, source_name in self._patterns:
            for m in pattern.finditer(raw):
                try:
                    key_data = m.group(1) if pattern.groups else m.group(0)
                    km = KeyMaterial()
                    km.key = key_data if isinstance(key_data, bytes) else key_data.encode("utf-8", errors="ignore")
                    km.source = KeySourceType.HARDCODED
                    km.context = f"matched via {source_name} at offset {m.start()}"
                    if len(km.key) >= 16:
                        keys.append(km)
                except (ValueError, UnicodeDecodeError):
                    continue
        return keys


# 三级库回退解密器

class TrafficDecryptor:
    def __init__(self):
        self.config: dict = {
            "max_key_length": 64,
            "xor_fallback": True,
            "aes_fallback": True,
        }

    def _decrypt_xor(self, encrypted: bytes, key: KeyMaterial) -> DecryptionResult:
        """单字节 XOR 解密——无第三方库时的兜底路径。"""
        result = DecryptionResult()
        if not key.key:
            result.error = "empty key"
            return result
        klen = len(key.key)
        decrypted = bytes(b ^ key.key[i % klen] for i, b in enumerate(encrypted))
        result.success = True
        result.decrypted_data = decrypted
        result.plaintext = decrypted
        return result

    def decrypt(self, data: bytes, key: bytes | KeyMaterial | None) -> DecryptionResult:
        result = DecryptionResult()
        if key is None:
            result.error = "no key provided"
            return result

        actual_key = key.key if isinstance(key, KeyMaterial) else key
        if len(actual_key) < 16:
            result.error = f"key too short ({len(actual_key)} bytes)"
            return result

        # 第一级: cryptography (首选 — 硬件加速, 活跃维护)
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            use_key = actual_key[:32] if len(actual_key) >= 32 else actual_key[:16].ljust(16, b"\x00")
            cipher = Cipher(algorithms.AES(use_key), modes.CBC(b"\x00" * 16))
            decryptor = cipher.decryptor()
            padded = data[:((len(data) // 16) * 16)] if len(data) >= 16 else data.ljust(16, b"\x00")
            result.plaintext = decryptor.update(padded) + decryptor.finalize()
            result.success = True
            return result
        except ImportError:
            pass

        # 第二级: PyCryptodome (广泛可用, 纯Python回退)
        try:
            from Crypto.Cipher import AES as PyAES
            ak = actual_key[:32] if len(actual_key) >= 32 else actual_key[:16].ljust(16, b"\x00")
            padded = data[:((len(data) // 16) * 16)] if len(data) >= 16 else data.ljust(16, b"\x00")
            result.plaintext = PyAES.new(ak, PyAES.MODE_CBC, iv=b"\x00" * 16).decrypt(padded)
            result.success = True
            return result
        except ImportError:
            pass

        # 第三级: 纯Python XOR — 最后手段, 零依赖, 密码学价值极低
        try:
            result.plaintext = bytes(a ^ b for a, b in zip(
                data[:len(actual_key)], actual_key * ((len(data) // len(actual_key)) + 1)))
            result.success = True
            result.error = "simple XOR fallback (no crypto lib available)"
        except Exception as e:
            result.error = str(e)

        return result


# 便捷导出

def extract_keys(binary: bytes | str) -> list[KeyMaterial]:
    return KeyExtractor().extract(binary)


def decrypt_traffic(data: bytes, keys: Optional[list[KeyMaterial]]) -> DecryptionResult:
    if not keys:
        return DecryptionResult()
    d = TrafficDecryptor()
    return d.decrypt(data, keys[0])

def analyze_traffic(data: bytes) -> list[TrafficAnalysisResult]:
    return CryptoTrafficAnalyzer().analyze(data)


# TLS 1.3 0-RTT Early Data检测
# 0-RTT允许客户端首次飞行发送应用数据, 代价是重放攻击面。
# 检测指标: (1) ClientHello含early_data(TLS扩展42),
# (2) pre_shared_key扩展含early_data_indication,
# (3) 编译的字符串标识"enable-early-data"/"0rtt"/"early_data"

_EARLY_DATA_STRINGS = [
    b'enable-early-data', b'early_data', b'0rtt', b'0-RTT',
    b'SSL_set_early_data_enabled', b'SSL_early_data_accepted',
    b'TLSEXT_TYPE_early_data', b'tls13_early_data',
    b'early_data_indication', b'max_early_data_size',
]


def detect_0rtt_support(data: bytes) -> dict:
    """检测二进制/TLS流中的0-RTT early data支持。"""
    result = {'0rtt_detected': False, 'evidence': []}

    # 检查TLS扩展42 (early_data)
    ext_early_data = struct.pack(">H", 42)
    if ext_early_data in data:
        result['0rtt_detected'] = True
        result['evidence'].append('TLS extension 42 (early_data) present')
        result['extension_detected'] = True

    # 检查编译字符串
    for sig in _EARLY_DATA_STRINGS:
        if sig in data:
            result['0rtt_detected'] = True
            evidence = sig.decode('ascii', errors='replace')
            if evidence not in result['evidence']:
                result['evidence'].append(f'string: {evidence}')
            result['string_detected'] = True

    return result


__all__ = ["CryptoTrafficAnalyzer", "KeyExtractor", "TrafficDecryptor",
           "KeyMaterial", "DecryptionResult", "TrafficAnalysisResult",
           "extract_keys", "decrypt_traffic", "analyze_traffic",
           "detect_0rtt_support"]
