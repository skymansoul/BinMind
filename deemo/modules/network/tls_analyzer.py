# 2026-07-18
"""TLS指纹识别与密码套件安全分析——JA3/JA4指纹、证书解析、协议版本探测。"""
import hashlib, logging, socket, ssl, struct
from collections import defaultdict
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple, Any
from datetime import datetime

_log = logging.getLogger(__name__)

# ---- 密码套件评分 —— 参考Mozilla SSL Configuration Generator ----
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

# //// TLS版本映射 ////
_TLS_VERSIONS = {
    0x0301: "TLSv1.0", 0x0302: "TLSv1.1",
    0x0303: "TLSv1.2", 0x0304: "TLSv1.3",
}
_SSL_VERSIONS = {0x300: "SSLv3", 0x301: "TLSv1.0", 0x302: "TLSv1.1", 0x303: "TLSv1.2"}

# ===== 数据结构 =====
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


# //// 密码套件评分 ////
def score_cipher_suites(ciphers: List[str]) -> Dict[str, Any]:
    """对密码套件列表评分，返回各等级数量和平均分。

    按Mozilla四等级分类：modern(100), intermediate(70-90), old(40-60), insecure(0-30)。
    不支持PFS的RSA密钥交换即使用AES-GCM也归入insecure。
    """
    if not ciphers:
        return {"avg": 0, "min": 0, "count_by_tier": {}, "total": 0, "scores": []}

    _scores = []
    _tiers = {"modern": 0, "intermediate": 0, "old": 0, "insecure": 0}

    for c in ciphers:
        _name = c.replace("-", "-").replace("_", "-")
        # 标准化名称
        _name = _name.upper().replace("TLS-", "TLS_").replace("TLS_", "").strip()
        # 尝试匹配已知套件
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
    # EXPORT / NULL → 0
    if "EXP" in _n or "NULL" in _n:
        return 0
    # RC4 → 5
    if "RC4" in _n:
        return 5
    # DES(3DES) → 15
    if "DES" in _n and "AES" not in _n:
        return 15
    # 无ECDHE/DHE → 无PFS，不高于30
    if "ECDHE" not in _n and "DHE" not in _n:
        if "AES" in _n and "GCM" in _n:
            return 30
        if "AES" in _n:
            return 20
        return 10
    # DHE → 中等
    if "DHE" in _n and "ECDHE" not in _n:
        if "GCM" in _n:
            return 80
        return 55
    # ECDHE → 高
    if "ECDHE" in _n:
        if "GCM" in _n or "CHACHA20" in _n:
            return 90
        if "SHA384" in _n or "SHA256" in _n:
            return 70
        return 60
    return 40  # 未知套件保守评分


# ===== JA3指纹生成 =====
def compute_ja3(ciphers: List[str], extensions: List[int],
                curves: List[int], ec_formats: List[int],
                tls_version: int = 0x0303) -> Tuple[str, str]:
    """计算JA3指纹：MD5(TLS_VERSION,CIPHERS,EXTENSIONS,CURVES,EC_FORMATS)。

    ClientHello中各字段的十进制值以'-'分隔，以','连接各组。密码套件按出现顺序排列。
    """
    _ciphers_str = "-".join(str(_cipher_to_decimal(c)) for c in ciphers) if ciphers else ""
    _ext_str = "-".join(str(e) for e in extensions) if extensions else ""
    _curves_str = "-".join(str(c) for c in curves) if curves else ""
    _ec_str = "-".join(str(e) for e in ec_formats) if ec_formats else ""

    _ja3_raw = f"{tls_version},{_ciphers_str},{_ext_str},{_curves_str},{_ec_str}"
    _ja3_hash = hashlib.md5(_ja3_raw.encode()).hexdigest()
    return _ja3_raw, _ja3_hash


# TLS密码套件数值映射（常见套件）
_CIPHER_DECIMAL_MAP: Dict[str, int] = {
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

_CIPHER_DECIMAL_REVERSE: Dict[int, str] = {v: k for k, v in _CIPHER_DECIMAL_MAP.items()}


def _cipher_to_decimal(cipher: str) -> int:
    _c = _CIPHER_DECIMAL_MAP.get(cipher)
    if _c is not None:
        return _c
    # 尝试小写匹配
    _c = _CIPHER_DECIMAL_MAP.get(cipher.upper().replace("-", "_"))
    if _c is not None:
        return _c
    return 0x0000


def _decimal_to_cipher(val: int) -> str:
    return _CIPHER_DECIMAL_REVERSE.get(val, f"UNKNOWN_{val:04X}")


# ===== JA4简化指纹 =====
def compute_ja4(proto: str, ciphers: List[str], extensions: List[int]) -> str:
    """JA4简化指纹：proto_ver + ciphers_hash(truncated 12char SHA256) + extensions_hash。

    取前30个密码套件排序后做SHA256截断12字符。比JA3更紧凑且支持TLS1.3。
    """
    _proto_code = "t"  # TCP默认
    if proto.lower() == "quic":
        _proto_code = "q"

    # 密码套件哈希
    _sorted_ciphers = sorted(ciphers[:30])
    _ciphers_str = ",".join(_sorted_ciphers)
    _ciphers_hash = hashlib.sha256(_ciphers_str.encode()).hexdigest()[:12]

    # 扩展哈希
    _ext_str = ",".join(str(e) for e in sorted(extensions[:30]))
    _ext_hash = hashlib.sha256(_ext_str.encode()).hexdigest()[:12]

    return f"{_proto_code}13{_ciphers_hash}_{_ext_hash}"


# ===== 证书解析 =====
def parse_cert(cert_der: bytes) -> Optional[CertInfo]:
    """解析DER编码的X.509证书，提取主体CN、颁发者、SAN、有效期和链深度。

    尝试用ssl标准库解析，失败后回退到ASN.1手动解析（提取结构化字段）。
    """
    if not cert_der:
        return None
    _info = CertInfo()

    try:
        _cert = ssl.DER_cert_to_PEM_cert(cert_der)
        # 使用ssl标准库
        import tempfile, os as _os
        _tmp = None
        try:
            _tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".pem")
            _tmp.write(_cert.encode() if isinstance(_cert, str) else _cert)
            _tmp.close()
            _parsed = ssl._ssl._test_decode_cert(_tmp.name)
            if _parsed:
                _info.subject = str(_parsed.get("subject", ""))
                _info.issuer = str(_parsed.get("issuer", ""))
                _san_list = _parsed.get("subjectAltName", [])
                _info.san = [str(s) for s in (_san_list if isinstance(_san_list, (list, tuple)) else [])]
                _info.not_before = float(_parsed.get("notBefore", "0").replace("GMT", "").strip(" "))
                _info.not_after = float(_parsed.get("notAfter", "0").replace("GMT", "").strip(" "))
                _info.not_before = _parsed.get("notBefore_ts", _info.not_before)
                _info.not_after = _parsed.get("notAfter_ts", _info.not_after)
            _info.fingerprint_sha256 = hashlib.sha256(cert_der).hexdigest()
        finally:
            if _tmp:
                try:
                    _os.unlink(_tmp.name)
                except Exception:
                    pass
    except Exception:
        # 回退：简单ASN.1解析
        _info = _asn1_fallback_parse(cert_der)
        _info.fingerprint_sha256 = hashlib.sha256(cert_der).hexdigest()

    return _info


def _asn1_fallback_parse(der: bytes) -> CertInfo:
    """手动解析DER编码最低限度提取证书字段"""
    _info = CertInfo()
    _pos = 0
    try:
        # 跳转到序列内部
        if len(der) < 4:
            return _info
        _pos = _skip_tag_len(der, 0)  # Certificate SEQUENCE
        _pos = _skip_tag_len(der, _pos)  # TBSCertificate SEQUENCE
        # 跳版本
        if der[_pos] == 0xA0:
            _pos = _skip_tag_len(der, _pos)
        # 序列号
        if der[_pos] == 0x02:
            _pos = _skip_tag_len(der, _pos)
        # 签名算法
        _pos = _skip_tag_len(der, _pos)
        # 颁发者
        if der[_pos] in (0x30, 0x31):
            _end = _pos + _get_len(der, _pos)
            _info.issuer = _parse_x500_name(der, _pos)
            _pos = _end
        # 有效期
        if der[_pos] == 0x30:
            _pos = _skip_tag_len(der, _pos)
        # 主体
        if der[_pos] in (0x30, 0x31):
            _info.subject = _parse_x500_name(der, _pos)
            _pos = _skip_tag_len(der, _pos)
        # 遍历扩展找SAN
        while _pos < len(der) - 4:
            _tag = der[_pos]
            if _tag == 0xA3:  # extensions
                _ext_pos = _pos + _get_len_bytes(der, _pos)
                _ext_data = der[_ext_pos:_ext_pos + _get_len(der, _pos)]
                _ext_pos = 0
                while _ext_pos < len(_ext_data) - 4:
                    _ext_tag = _ext_data[_ext_pos]
                    _ext_len = _get_len(_ext_data, _ext_pos)
                    _ext_end = _ext_pos + _get_len_bytes(_ext_data, _ext_pos) + _ext_len
                    # 寻找 SAN OID 2.5.29.17
                    if b'\x55\x1d\x11' in _ext_data[_ext_pos:_ext_end]:
                        _san_data = _ext_data[_ext_pos + 2 + _get_len_bytes(_ext_data, _ext_pos):_ext_end]
                        _san_inner = _san_data
                        _san_pos = 0
                        while _san_pos < len(_san_inner) - 2:
                            if _san_inner[_san_pos] == 0x82:
                                _n = _san_inner[_san_pos + 1]
                                if _san_pos + 2 + _n <= len(_san_inner):
                                    _dns = _san_inner[_san_pos + 2:_san_pos + 2 + _n]
                                    try:
                                        _info.san.append(_dns.decode("ascii", errors="replace"))
                                    except Exception:
                                        pass
                                    _san_pos += 2 + _n
                                else:
                                    _san_pos += 1
                            else:
                                _san_pos += 1
                        break
                    _ext_pos = _ext_end
                break
            else:
                _pos = _skip_tag_len(der, _pos)
    except Exception:
        pass
    return _info


def _get_len(data: bytes, pos: int) -> int:
    if data[pos] & 0x80:
        num_bytes = data[pos] & 0x7F
        return int.from_bytes(data[pos+1:pos+1+num_bytes], "big")
    return data[pos]


def _get_len_bytes(data: bytes, pos: int) -> int:
    if data[pos] & 0x80:
        return (data[pos] & 0x7F) + 1
    return 1


def _skip_tag_len(data: bytes, pos: int) -> int:
    return pos + _get_len_bytes(data, pos) + _get_len(data, pos)


def _parse_x500_name(data: bytes, pos: int) -> str:
    """从ASN.1 DER中提取X.500名称"""
    parts: List[str] = []
    length = _get_len(data, pos)
    offset = pos + _get_len_bytes(data, pos)
    end = offset + length
    while offset < end:
        if data[offset] in (0x31, 0x30):
            set_offset = offset + _get_len_bytes(data, offset)
            set_len = _get_len(data, offset)
            set_end = set_offset + set_len
        else:
            set_offset = offset + _get_len_bytes(data, offset)
            set_len = _get_len(data, offset)
            set_end = set_offset + set_len
        inner = set_offset
        while inner < set_end and inner < len(data) - 2:
            if data[inner] in (0x31, 0x30):
                seq_start = inner
                inner_end = inner + _get_len_bytes(data, seq_start) + _get_len(data, inner)
                inner = inner_end
                continue
            # OID
            if data[inner] == 0x06:
                oid_start = inner + _get_len_bytes(data, inner)
                oid_len = _get_len(data, inner)
                oid_end = oid_start + oid_len
            else:
                oid_start, oid_end = inner, inner
            # 值
            inner = oid_end
            if inner < len(data) and data[inner] in (0x0C, 0x13, 0x16):
                val_start = inner + _get_len_bytes(data, inner)
                val_len = _get_len(data, inner)
                if val_start + val_len <= len(data):
                    try:
                        val = data[val_start:val_start+val_len].decode("utf-8", errors="replace")
                        parts.append(val)
                    except Exception:
                        pass
                inner = val_start + val_len
            else:
                inner = _skip_tag_len(data, inner) if inner < len(data) else inner
        offset = set_end
    return "/".join(parts)


# //// TLS版本探测 ////
def _probe_versions(host: str, port: int, timeout: float = 5.0) -> List[str]:
    """探测服务器支持的TLS协议版本。

    分别尝试TLS1.0/1.1/1.2/1.3连接，记录成功版本。TLS1.3使用不同上下文。
    """
    _supported = []
    _test_versions = [
        (ssl.PROTOCOL_TLSv1, "TLSv1.0"),
        (ssl.PROTOCOL_TLSv1_1, "TLSv1.1"),
        (ssl.PROTOCOL_TLSv1_2, "TLSv1.2"),
    ]

    for _proto, _label in _test_versions:
        try:
            _ctx = ssl.SSLContext(_proto)
            _ctx.check_hostname = False
            _ctx.verify_mode = ssl.CERT_NONE
            _ctx.set_ciphers("DEFAULT")
            _sock = socket.create_connection((host, port), timeout=timeout)
            _ssock = _ctx.wrap_socket(_sock, server_hostname=host)
            _ssock.close()
            _supported.append(_label)
        except Exception:
            pass

    # TLS 1.3
    try:
        _ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        _ctx.check_hostname = False
        _ctx.verify_mode = ssl.CERT_NONE
        _sock = socket.create_connection((host, port), timeout=timeout)
        _ssock = _ctx.wrap_socket(_sock, server_hostname=host)
        _ver = _ssock.version()
        _ssock.close()
        if _ver and "1.3" in str(_ver):
            _supported.append("TLSv1.3")
        elif _ver:
            _supported.append(str(_ver))
    except Exception:
        pass

    return _supported


# ===== 完整TLS分析 =====
def analyze(host: str, port: int = 443, timeout: float = 5.0) -> TlsFingerprint:
    """对目标主机端口执行完整TLS分析。

    连接流程：建立TLS连接 → 获取密码套件和证书 → 解析JA3/JA4指纹 →
    探测版本支持 → 评分密码套件。默认5秒超时，超时返回空fingerprint。
    """
    _fp = TlsFingerprint()
    _cert_der = None
    _ciphers_raw = []
    _extensions_raw = []
    _curves_raw = []
    _ec_formats_raw = []
    _tls_ver = 0x0303

    try:
        _ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        _ctx.check_hostname = False
        _ctx.verify_mode = ssl.CERT_NONE
        _ctx.set_ciphers("ALL:COMPLEMENTOFALL")

        _sock = socket.create_connection((host, port), timeout=timeout)
        _ssock = _ctx.wrap_socket(_sock, server_hostname=host)

        # 获取对端证书
        _cert_der = _ssock.getpeercert(binary_form=True)
        _cert_dict = _ssock.getpeercert()
        if _cert_der:
            _fp.cert_info = parse_cert(_cert_der)

        # 密码套件
        _cipher_info = _ssock.cipher()
        if _cipher_info:
            _ciphers_raw = list(_cipher_info)

        # 获取shared ciphers（无法直接从Python ssl获取完整ClientHello列表）
        try:
            _shared = _ssock.shared_ciphers()
            _ciphers_names = [c[0] for c in _shared]
            _fp.ciphers = _ciphers_names
        except Exception:
            pass

        # 获取协议版本
        try:
            _ver = _ssock.version()
            if _ver:
                _tls_label = str(_ver)
                _tls_ver = 0x0303 if "1.2" in _tls_label else (0x0304 if "1.3" in _tls_label else 0x0303)
        except Exception:
            pass

        _ssock.close()
    except Exception as e:
        _log.debug("TLS连接失败 %s:%s: %s", host, port, e)
        # 即使连接失败也尝试版本探测
        try:
            _fp.tls_versions_supported = _probe_versions(host, port, timeout)
        except Exception:
            pass
        return _fp

    # 探测版本支持
    _fp.tls_versions_supported = _probe_versions(host, port, timeout)

    # 生成JA3指纹
    if _fp.ciphers:
        _ja3, _ja3_hash = compute_ja3(_fp.ciphers, _fp.extensions, _curves_raw, _ec_formats_raw, _tls_ver)
        _fp.ja3 = _ja3
        _fp.ja3_hash = _ja3_hash
        _fp.ja4 = compute_ja4("tcp", _fp.ciphers, _fp.extensions)

    return _fp
