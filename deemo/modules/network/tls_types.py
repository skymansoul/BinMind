"""TLS指纹识别：常量、数据结构与密码套件评分。

Mozilla四等级分类标准映射、IANA密码套件数值映射表、
CertInfo/TlsFingerprint数据结构、密码套件评分函数。
"""
import hashlib
from dataclasses import dataclass, field
from typing import List, Dict, Any, Tuple

# 密码套件评分映射——参照 Mozilla SSL Configuration Generator 分级标准
CIPHER_SUITE_SCORES: Dict[str, int] = {}

_MODERN = {
    "TLS_AES_128_GCM_SHA256": 100,
    "TLS_AES_256_GCM_SHA384": 100,
    "TLS_CHACHA20_POLY1305_SHA256": 100,
}

_INTERMEDIATE = {
    "ECDHE-RSA-AES128-GCM-SHA256": 90,
    "ECDHE-RSA-AES256-GCM-SHA384": 90,
    "ECDHE-ECDSA-AES128-GCM-SHA256": 90,
    "ECDHE-ECDSA-AES256-GCM-SHA384": 90,
    "ECDHE-RSA-CHACHA20-POLY1305": 85,
    "ECDHE-ECDSA-CHACHA20-POLY1305": 85,
    "DHE-RSA-AES128-GCM-SHA256": 80,
    "DHE-RSA-AES256-GCM-SHA384": 80,
    "DHE-RSA-CHACHA20-POLY1305": 75,
    "ECDHE-RSA-AES128-SHA256": 70,
    "ECDHE-ECDSA-AES128-SHA256": 70,
    "ECDHE-RSA-AES256-SHA384": 70,
    "ECDHE-ECDSA-AES256-SHA384": 70,
}

_OLD = {
    "ECDHE-RSA-AES128-SHA": 60,
    "ECDHE-ECDSA-AES128-SHA": 60,
    "ECDHE-RSA-AES256-SHA": 60,
    "ECDHE-ECDSA-AES256-SHA": 60,
    "DHE-RSA-AES128-SHA256": 55,
    "DHE-RSA-AES256-SHA256": 55,
    "DHE-RSA-AES128-SHA": 50,
    "DHE-RSA-AES256-SHA": 50,
    "AES128-GCM-SHA256": 45,
    "AES256-GCM-SHA384": 45,
    "AES128-SHA256": 40,
    "AES256-SHA256": 40,
}

_INSECURE = {
    "RSA-AES128-GCM-SHA256": 30,
    "RSA-AES256-GCM-SHA384": 30,
    "ECDHE-RSA-DES-CBC3-SHA": 20,
    "ECDHE-ECDSA-DES-CBC3-SHA": 20,
    "DHE-RSA-DES-CBC3-SHA": 15,
    "RSA-DES-CBC3-SHA": 10,
    "RC4-SHA": 5,
    "RC4-MD5": 5,
    "ECDHE-RSA-RC4-SHA": 5,
    "ECDHE-ECDSA-RC4-SHA": 5,
    "EXP-RC4-MD5": 0,
    "EXP-RC2-CBC-MD5": 0,
    "EXP-DES-CBC-SHA": 0,
    "NULL-SHA256": 0,
    "NULL-SHA": 0,
    "NULL-MD5": 0,
    "ECDHE-RSA-NULL-SHA": 0,
    "ECDHE-ECDSA-NULL-SHA": 0,
}

for _d in [_MODERN, _INTERMEDIATE, _OLD, _INSECURE]:
    CIPHER_SUITE_SCORES.update(_d)

# TLS/SSL 协议版本号映射表
TLS_VERSIONS = {
    0x0301: "TLSv1.0", 0x0302: "TLSv1.1",
    0x0303: "TLSv1.2", 0x0304: "TLSv1.3",
}
SSL_VERSIONS = {0x300: "SSLv3", 0x301: "TLSv1.0", 0x302: "TLSv1.1", 0x303: "TLSv1.2"}

# IANA密码套件数值映射
CIPHER_DECIMAL_MAP: Dict[str, int] = {
    "TLS_AES_128_GCM_SHA256": 0x1301,
    "TLS_AES_256_GCM_SHA384": 0x1302,
    "TLS_CHACHA20_POLY1305_SHA256": 0x1303,
    "TLS_AES_128_CCM_SHA256": 0x1304,
    "TLS_AES_128_CCM_8_SHA256": 0x1305,
    "ECDHE-ECDSA-AES128-GCM-SHA256": 0xC02B,
    "ECDHE-RSA-AES128-GCM-SHA256": 0xC02F,
    "ECDHE-ECDSA-AES256-GCM-SHA384": 0xC02C,
    "ECDHE-RSA-AES256-GCM-SHA384": 0xC030,
    "ECDHE-ECDSA-CHACHA20-POLY1305": 0xCCA9,
    "ECDHE-RSA-CHACHA20-POLY1305": 0xCCA8,
    "DHE-RSA-AES128-GCM-SHA256": 0x009E,
    "DHE-RSA-AES256-GCM-SHA384": 0x009F,
    "ECDHE-ECDSA-AES128-SHA256": 0xC023,
    "ECDHE-RSA-AES128-SHA256": 0xC027,
    "ECDHE-ECDSA-AES256-SHA384": 0xC024,
    "ECDHE-RSA-AES256-SHA384": 0xC028,
    "ECDHE-ECDSA-AES128-SHA": 0xC009,
    "ECDHE-RSA-AES128-SHA": 0xC013,
    "ECDHE-ECDSA-AES256-SHA": 0xC00A,
    "ECDHE-RSA-AES256-SHA": 0xC014,
    "DHE-RSA-AES128-SHA256": 0x0067,
    "DHE-RSA-AES256-SHA256": 0x006B,
    "DHE-RSA-AES128-SHA": 0x0033,
    "DHE-RSA-AES256-SHA": 0x0039,
    "RSA-AES128-GCM-SHA256": 0x009C,
    "RSA-AES256-GCM-SHA384": 0x009D,
    "RSA-AES128-SHA256": 0x003C,
    "RSA-AES256-SHA256": 0x003D,
    "RSA-AES128-SHA": 0x002F,
    "RSA-AES256-SHA": 0x0035,
    "ECDHE-RSA-RC4-SHA": 0xC011,
    "ECDHE-ECDSA-RC4-SHA": 0xC007,
    "RC4-SHA": 0x0005,
    "RC4-MD5": 0x0004,
    "DES-CBC3-SHA": 0x000A,
    "ECDHE-RSA-DES-CBC3-SHA": 0xC012,
    "ECDHE-ECDSA-DES-CBC3-SHA": 0xC008,
    "NULL-SHA": 0x0002,
    "NULL-MD5": 0x0001,
}

CIPHER_DECIMAL_REVERSE: Dict[int, str] = {v: k for k, v in CIPHER_DECIMAL_MAP.items()}


@dataclass
class CertInfo:
    subject: str = ""
    issuer: str = ""
    san: List[str] = field(default_factory=list)
    not_before: float = 0.0
    not_after: float = 0.0
    chain_depth: int = 0
    fingerprint_sha256: str = ""


@dataclass
class TlsFingerprint:
    ja3: str = ""
    ja3_hash: str = ""
    ja4: str = ""
    ciphers: List[str] = field(default_factory=list)
    extensions: List[int] = field(default_factory=list)
    tls_versions_supported: List[str] = field(default_factory=list)
    cert_info: Optional[CertInfo] = None


def score_cipher_suites(ciphers: List[str]) -> Dict[str, Any]:
    """密码套件列表评分——返回各等级数量和平均分。"""
    if not ciphers:
        return {"avg": 0, "min": 0, "count_by_tier": {}, "total": 0, "scores": []}

    _scores = []
    _tiers = {"modern": 0, "intermediate": 0, "old": 0, "insecure": 0}

    for c in ciphers:
        _s = CIPHER_SUITE_SCORES.get(c, None)
        if _s is None:
            _s = _match_cipher_score(c)
        _scores.append(_s)

        if _s >= 90:
            _tiers["modern"] += 1
        elif _s >= 70:
            _tiers["intermediate"] += 1
        elif _s >= 40:
            _tiers["old"] += 1
        else:
            _tiers["insecure"] += 1

    _avg = sum(_scores) / len(_scores) if _scores else 0
    _min = min(_scores) if _scores else 0
    return {"avg": _avg, "min": _min, "count_by_tier": _tiers, "total": len(ciphers), "scores": _scores}


def _match_cipher_score(cipher_name: str) -> int:
    _n = cipher_name.upper()
    if "EXP" in _n or "NULL" in _n:
        return 0
    if "RC4" in _n:
        return 5
    if "DES" in _n and "AES" not in _n:
        return 15
    if "ECDHE" not in _n and "DHE" not in _n:
        if "AES" in _n and "GCM" in _n:
            return 30
        if "AES" in _n:
            return 20
        return 10
    if "DHE" in _n and "ECDHE" not in _n:
        if "GCM" in _n:
            return 80
        return 55
    if "ECDHE" in _n:
        if "GCM" in _n or "CHACHA20" in _n:
            return 90
        if "SHA384" in _n or "SHA256" in _n:
            return 70
        return 60
    return 40


def cipher_to_decimal(cipher: str) -> int:
    _c = CIPHER_DECIMAL_MAP.get(cipher)
    if _c is not None:
        return _c
    _c = CIPHER_DECIMAL_MAP.get(cipher.upper().replace("-", "_"))
    if _c is not None:
        return _c
    return 0x0000


def decimal_to_cipher(val: int) -> str:
    return CIPHER_DECIMAL_REVERSE.get(val, f"UNKNOWN_{val:04X}")


__all__ = [
    "CIPHER_SUITE_SCORES", "CIPHER_DECIMAL_MAP", "CIPHER_DECIMAL_REVERSE",
    "TLS_VERSIONS", "SSL_VERSIONS",
    "CertInfo", "TlsFingerprint",
    "score_cipher_suites", "cipher_to_decimal", "decimal_to_cipher",
]
