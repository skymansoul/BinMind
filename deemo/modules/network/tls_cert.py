"""TLS指纹识别：X.509证书解析。

DER编码证书解析——优先ssl标准库，失败回退至ASN.1手动解析。
提取主体/颁发者/SAN/有效期/SHA256指纹。
"""
import hashlib
import ssl
import tempfile
import os as _os
from typing import List, Optional

from .tls_types import CertInfo


def parse_cert(cert_der: bytes) -> Optional[CertInfo]:
    """解析DER编码X.509证书——提取主体、颁发者、SAN、有效期及指纹。

    优先用ssl标准库解析，失败后回退至ASN.1手动解析获取结构化字段。
    """
    if not cert_der:
        return None
    _info = CertInfo()

    try:
        _cert = ssl.DER_cert_to_PEM_cert(cert_der)
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
        _info = _asn1_fallback_parse(cert_der)
        _info.fingerprint_sha256 = hashlib.sha256(cert_der).hexdigest()

    return _info


def _asn1_fallback_parse(der: bytes) -> CertInfo:
    """DER最低限度解析——手动提取X.509证书核心字段"""
    _info = CertInfo()
    _pos = 0
    try:
        if len(der) < 4:
            return _info
        _pos = _skip_tag_len(der, 0)
        _pos = _skip_tag_len(der, _pos)
        if der[_pos] == 0xA0:
            _pos = _skip_tag_len(der, _pos)
        if der[_pos] == 0x02:
            _pos = _skip_tag_len(der, _pos)
        _pos = _skip_tag_len(der, _pos)
        if der[_pos] in (0x30, 0x31):
            _end = _pos + _get_len(der, _pos)
            _info.issuer = _parse_x500_name(der, _pos)
            _pos = _end
        if der[_pos] == 0x30:
            _pos = _skip_tag_len(der, _pos)
        if der[_pos] in (0x30, 0x31):
            _info.subject = _parse_x500_name(der, _pos)
            _pos = _skip_tag_len(der, _pos)
        while _pos < len(der) - 4:
            _tag = der[_pos]
            if _tag == 0xA3:
                _ext_pos = _pos + _get_len_bytes(der, _pos)
                _ext_data = der[_ext_pos:_ext_pos + _get_len(der, _pos)]
                _ext_pos = 0
                while _ext_pos < len(_ext_data) - 4:
                    _ext_tag = _ext_data[_ext_pos]
                    _ext_len = _get_len(_ext_data, _ext_pos)
                    _ext_end = _ext_pos + _get_len_bytes(_ext_data, _ext_pos) + _ext_len
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
    """从ASN.1 DER编码提取X.500可分辨名称"""
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
                inner_end = inner + _get_len_bytes(data, inner) + _get_len(data, inner)
                inner = inner_end
                continue
            if data[inner] == 0x06:
                oid_start = inner + _get_len_bytes(data, inner)
                oid_len = _get_len(data, inner)
                oid_end = oid_start + oid_len
            else:
                oid_start, oid_end = inner, inner
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


__all__ = ["parse_cert"]
