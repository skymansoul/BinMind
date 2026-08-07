"""TLS指纹识别与安全分析——JA3/JA4指纹生成、协议版本探测、完整分析入口。

JA3: MD5(TLS_VERSION,CIPHERS,EXTENSIONS,CURVES,EC_FORMATS)
JA4: proto_ver + ciphers_hash + extensions_hash（简化指纹）
analyze: 对目标主机端口执行完整TLS安全分析
"""
import hashlib
import logging
import socket
import ssl
from typing import List, Tuple

from .tls_types import (
    TlsFingerprint, CertInfo,
    CIPHER_DECIMAL_MAP, cipher_to_decimal,
)
from .tls_cert import parse_cert

_log = logging.getLogger(__name__)


def compute_ja3(ciphers: List[str], extensions: List[int],
                curves: List[int], ec_formats: List[int],
                tls_version: int = 0x0303) -> Tuple[str, str]:
    """计算 JA3 指纹：MD5(TLS_VERSION,CIPHERS,EXTENSIONS,CURVES,EC_FORMATS)。

    ClientHello 各字段的十进制值以'-'分隔，以','连接各组。密码套件按出现顺序排列。
    """
    _ciphers_str = "-".join(str(cipher_to_decimal(c)) for c in ciphers) if ciphers else ""
    _ext_str = "-".join(str(e) for e in extensions) if extensions else ""
    _curves_str = "-".join(str(c) for c in curves) if curves else ""
    _ec_str = "-".join(str(e) for e in ec_formats) if ec_formats else ""

    _ja3_raw = f"{tls_version},{_ciphers_str},{_ext_str},{_curves_str},{_ec_str}"
    _ja3_hash = hashlib.md5(_ja3_raw.encode()).hexdigest()
    return _ja3_raw, _ja3_hash


def compute_ja4(proto: str, ciphers: List[str], extensions: List[int]) -> str:
    """JA4简化指纹：proto_ver + ciphers_hash(SHA256截断12字符) + extensions_hash。

    取前30个密码套件排序后SHA256截断12字符。比JA3更紧凑，原生支持TLS 1.3。
    """
    _proto_code = "t"
    if proto.lower() == "quic":
        _proto_code = "q"

    _sorted_ciphers = sorted(ciphers[:30])
    _ciphers_str = ",".join(_sorted_ciphers)
    _ciphers_hash = hashlib.sha256(_ciphers_str.encode()).hexdigest()[:12]

    _ext_str = ",".join(str(e) for e in sorted(extensions[:30]))
    _ext_hash = hashlib.sha256(_ext_str.encode()).hexdigest()[:12]

    return f"{_proto_code}13{_ciphers_hash}_{_ext_hash}"


def _probe_versions(host: str, port: int, timeout: float = 5.0) -> List[str]:
    """探测目标服务器支持的TLS协议版本列表。

    分别尝试TLS 1.0/1.1/1.2连接，再独立测试TLS 1.3（不同SSLContext）。
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

    # TLS 1.3 独立探测
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


def analyze(host: str, port: int = 443, timeout: float = 5.0) -> TlsFingerprint:
    """对目标主机端口执行完整TLS安全分析。

    流程：建立TLS连接 → 获取密码套件和证书 → 生成JA3/JA4指纹 → 探测版本 → 评分。
    默认5秒超时，超时返回空fingerprint结构。
    """
    _fp = TlsFingerprint()
    _cert_der = None
    _curves_raw: List[int] = []
    _ec_formats_raw: List[int] = []
    _tls_ver = 0x0303

    try:
        _ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        _ctx.check_hostname = False
        _ctx.verify_mode = ssl.CERT_NONE
        _ctx.set_ciphers("ALL:COMPLEMENTOFALL")

        _sock = socket.create_connection((host, port), timeout=timeout)
        _ssock = _ctx.wrap_socket(_sock, server_hostname=host)

        _cert_der = _ssock.getpeercert(binary_form=True)
        if _cert_der:
            _fp.cert_info = parse_cert(_cert_der)

        _cipher_info = _ssock.cipher()
        if _cipher_info:
            pass  # 仅协商套件

        try:
            _shared = _ssock.shared_ciphers()
            _ciphers_names = [c[0] for c in _shared]
            _fp.ciphers = _ciphers_names
        except Exception:
            pass

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
        try:
            _fp.tls_versions_supported = _probe_versions(host, port, timeout)
        except Exception:
            pass
        return _fp

    _fp.tls_versions_supported = _probe_versions(host, port, timeout)

    if _fp.ciphers:
        _ja3, _ja3_hash = compute_ja3(_fp.ciphers, _fp.extensions, _curves_raw, _ec_formats_raw, _tls_ver)
        _fp.ja3 = _ja3
        _fp.ja3_hash = _ja3_hash
        _fp.ja4 = compute_ja4("tcp", _fp.ciphers, _fp.extensions)

    return _fp


    if __import__("os").environ.get("BINMIND_DEBUG"):
        print(*a, **kw)


__all__ = [
    "TlsFingerprint", "CertInfo", "compute_ja3", "compute_ja4",
    "parse_cert", "score_cipher_suites", "analyze",
    "cipher_to_decimal", "decimal_to_cipher",
    "CIPHER_SUITE_SCORES", "CIPHER_DECIMAL_MAP",
]
