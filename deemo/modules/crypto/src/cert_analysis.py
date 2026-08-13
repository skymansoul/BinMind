# 不依赖pyasn1/OpenSSL，自实现DER解析。覆盖TLS/代码签名中常见OID。
# 自签名检测用于发现嵌入式根证书；弱密钥/弱哈希检测覆盖PCI-DSS和NIST SP 800-131A。
# SAN解析支持DNS/URI/IP，覆盖CAB Forum基线要求。

from dataclasses import dataclass, field
from typing import List, Optional, Tuple
from enum import Enum
from datetime import datetime
import re
import base64


class CertWeaknessSeverity(Enum):
    INFO = 0
    WARNING = 1
    CRITICAL = 2


@dataclass
class CertInfo:
    """解析后的X.509证书信息"""
    subject: str
    issuer: str
    serial: str
    valid_from: str
    valid_to: str
    pubkey_alg: str
    key_size: int
    sans: List[str] = field(default_factory=list)
    is_ca: bool = False
    sig_alg: str = ""
    raw_der: bytes = b""


# ASN.1 DER 基础解析
def _read_tag(data: bytes, offset: int) -> Tuple[int, int, int, int]:
    """解析DER TLV: 返回 (tag, length, value_offset, next_offset)"""
    _tag = data[offset]
    _len = data[offset + 1]
    if _len < 0x80:
        return _tag, _len, offset + 2, offset + 2 + _len

    _len_bytes = _len & 0x7F
    _val_len = 0
    for _i in range(_len_bytes):
        _val_len = (_val_len << 8) | data[offset + 2 + _i]
    _vo = offset + 2 + _len_bytes
    return _tag, _val_len, _vo, _vo + _val_len


# OID -> 短名称映射
_OID_MAP = {
    '2.5.4.3': 'CN', '2.5.4.6': 'C', '2.5.4.7': 'L',
    '2.5.4.8': 'ST', '2.5.4.10': 'O', '2.5.4.11': 'OU',
    '2.5.4.5': 'serialNumber', '1.2.840.113549.1.9.1': 'emailAddress',
    '2.5.4.4': 'SN', '2.5.4.12': 'title', '2.5.4.42': 'GN',
    '2.5.4.43': 'initials', '2.5.4.9': 'street',
    '2.5.4.13': 'description', '2.5.4.97': 'organizationIdentifier',
    '2.5.29.17': 'subjectAltName', '2.5.29.19': 'basicConstraints',
    '2.5.29.15': 'keyUsage', '2.5.29.14': 'subjectKeyIdentifier',
    '2.5.29.37': 'extKeyUsage', '2.5.29.32': 'certificatePolicies',
    '1.2.840.113549.1.1.1': 'RSA', '1.2.840.113549.1.1.11': 'SHA256-RSA',
    '1.2.840.113549.1.1.5': 'SHA1-RSA', '1.2.840.113549.1.1.13': 'SHA512-RSA',
    '1.2.840.10045.2.1': 'EC', '1.2.840.10045.4.3.2': 'ECDSA-SHA256',
    '1.2.840.10045.4.3.3': 'ECDSA-SHA384',
    '1.3.132.0.34': 'secp384r1', '1.3.132.0.35': 'secp521r1',
    '1.2.840.10045.3.1.7': 'secp256r1',
    '1.3.6.1.5.5.7.3.1': 'serverAuth', '1.3.6.1.5.5.7.3.2': 'clientAuth',
    '1.3.6.1.5.5.7.3.3': 'codeSigning',
    '1.2.840.113549.1.9.3': 'contentType',
    '2.5.29.35': 'authorityKeyIdentifier',
    '1.3.6.1.4.1.11129.2.4.2': 'SCT_list',
}


def _read_oid(data: bytes, offset: int, length: int) -> str:
    _parts = []
    _v = data[offset]
    _parts.append(str(_v // 40))
    _parts.append(str(_v % 40))
    _i = offset + 1
    _end = offset + length
    while _i < _end:
        _acc = 0
        while _i < _end:
            _b = data[_i]
            _i += 1
            _acc = (_acc << 7) | (_b & 0x7F)
            if not (_b & 0x80):
                break
        _parts.append(str(_acc))
    return '.'.join(_parts)


def _oid_to_name(oid: str) -> str:
    return _OID_MAP.get(oid, oid)


def _read_dn(data: bytes, offset: int, length: int) -> str:
    _end = offset + length
    _parts = []
    _pos = offset
    while _pos < _end:
        _tag, _tlen, _vo, _next = _read_tag(data, _pos)
        if _tag != 0x30:  # SEQUENCE (SET OF)
            _pos = _next
            continue
        # Inner SEQUENCE: OID + value
        if _vo < _end:
            _itag, _ilen, _ivo, _inext = _read_tag(data, _vo)
            if _itag == 0x30:
                _otid = _read_oid_from_seq(data, _ivo, _ilen)
                # value follows
                if _inext < _end:
                    _vtag, _vlen, _vvo, _vnext = _read_tag(data, _inext)
                    _val_str = _read_string_value(data, _vtag, _vvo, _vlen)
                    _short = _oid_to_name(_otid)
                    _parts.append('{}={}'.format(_short, _val_str))
        _pos = _next
    return ', '.join(_parts)


def _read_oid_from_seq(data: bytes, offset: int, length: int) -> str:
    # SEQUENCE内定位OID
    _pos = offset
    _end = offset + length
    while _pos < _end:
        _tag, _tlen, _vo, _next = _read_tag(data, _pos)
        if _tag == 0x06:  # OID
            return _read_oid(data, _vo, _tlen)
        _pos = _next
    return 'unknown'


def _read_string_value(data: bytes, tag: int, offset: int, length: int) -> str:
    _raw = data[offset:offset + length]
    if tag in (0x0C, 0x13, 0x16, 0x1E):  # UTF8String, Printable, IA5, BMP
        try:
            return _raw.decode('utf-8')
        except UnicodeDecodeError:  # 修复: bare except → UnicodeDecodeError
            try:
                return _raw.decode('latin-1')
            except UnicodeDecodeError:  # 修复: bare except → UnicodeDecodeError
                return _raw.hex()
    if tag == 0x02:  # INTEGER
        _v = 0
        for _b in _raw:
            _v = (_v << 8) | _b
        return str(_v)
    return _raw.hex()


def _read_time(data: bytes, offset: int, length: int) -> str:
    _s = data[offset:offset + length].decode('ascii', errors='replace')
    if len(_s) == 13:  # UTCTime: YYMMDDHHMMSSZ
        return '20{}-{}-{}T{}:{}:{}Z'.format(_s[:2], _s[2:4], _s[4:6],
                                              _s[6:8], _s[8:10], _s[10:12])
    if len(_s) == 15:  # GeneralizedTime: YYYYMMDDHHMMSSZ
        return '{}-{}-{}T{}:{}:{}Z'.format(_s[:4], _s[4:6], _s[6:8],
                                            _s[8:10], _s[10:12], _s[12:14])
    return _s


# 扩展解析
def _parse_san_extension(data: bytes, offset: int, length: int) -> List[str]:
    _sans = []
    _pos = offset
    _end = offset + length
    while _pos < _end:
        _tag, _tlen, _vo, _next = _read_tag(data, _pos)
        if _tag == 0x82:  # dNSName
            _sans.append(data[_vo:_vo + _tlen].decode('ascii', errors='replace'))
        elif _tag == 0x86:  # uniformResourceIdentifier
            _sans.append('URI:' + data[_vo:_vo + _tlen].decode('ascii', errors='replace'))
        elif _tag == 0x87:  # iPAddress
            _ip = data[_vo:_vo + _tlen]
            if len(_ip) == 4:
                _sans.append('.'.join(str(_b) for _b in _ip))
            else:
                _sans.append(':'.join(_ip.hex()[_i:_i+4] for _i in range(0, len(_ip.hex()), 4)))
        _pos = _next
    return _sans


# 主解析
def _parse_tbscert(data: bytes, offset: int, length: int) -> dict:
    _res = {'version': 1, 'serial': '', 'sig_alg': '', 'issuer': '',
            'valid_from': '', 'valid_to': '', 'subject': '',
            'pubkey_alg': '', 'key_size': 0, 'is_ca': False, 'sans': []}
    _pos = offset
    _end = offset + length

    # 版本 (context [0] EXPLICIT)
    if _pos < _end and data[_pos] == 0xA0:
        _, _tlen, _vo, _pos = _read_tag(data, _pos)
        _vtag, _vlen, _vvo, _ = _read_tag(data, _vo)
        _res['version'] = data[_vvo] + 1

    # 序列号
    if data[_pos] == 0x02:
        _, _tlen, _vo, _pos = _read_tag(data, _pos)
        _res['serial'] = data[_vo:_vo + _tlen].hex()

    # 签名算法OID
    if data[_pos] == 0x30:
        _, _tlen, _vo, _pos = _read_tag(data, _pos)
        _oid = _read_oid_from_seq(data, _vo, _tlen)
        _res['sig_alg'] = _oid_to_name(_oid)
        _res['sig_alg_oid'] = _oid

    # 颁发者
    if data[_pos] == 0x30:
        _, _tlen, _vo, _pos = _read_tag(data, _pos)
        _res['issuer'] = _read_dn(data, _vo, _tlen)

    # 有效期
    if data[_pos] == 0x30:
        _, _tlen, _vo, _pos = _read_tag(data, _pos)
        # 两个时间
        _tpos = _vo
        _vtag, _vlen, _vvo, _tpos = _read_tag(data, _tpos)
        _res['valid_from'] = _read_time(data, _vvo, _vlen)
        _vtag, _vlen, _vvo, _tpos = _read_tag(data, _tpos)
        _res['valid_to'] = _read_time(data, _vvo, _vlen)

    # 主体
    if data[_pos] == 0x30:
        _, _tlen, _vo, _pos = _read_tag(data, _pos)
        _res['subject'] = _read_dn(data, _vo, _tlen)

    # 公钥信息
    if data[_pos] == 0x30:
        _, _tlen, _vo, _pos = _read_tag(data, _pos)
        _pki_vo = _vo
        _oid = _read_oid_from_seq(data, _pki_vo, _tlen)
        _res['pubkey_alg'] = _oid_to_name(_oid)
        # BIT STRING (tag 0x03), 长度→key size
        _pki_end = _vo + _tlen
        _tmp = _pki_vo
        while _tmp < _pki_end:
            _ttag, _ttlen, _tvo, _tnext = _read_tag(data, _tmp)
            if _ttag == 0x03:  # BIT STRING
                _key_bytes = data[_tvo + 1:_tvo + _ttlen]  # 跳过unused bits字节
                _res['key_size'] = len(_key_bytes) * 8
                break
            _tmp = _tnext

    # 扩展 (context [3])
    if _pos < _end and data[_pos] == 0xA3:
        _, _tlen, _vo, _pos = _read_tag(data, _pos)
        _ext_seq_end = _vo + _tlen
        _epos = _vo
        while _epos < _ext_seq_end:
            _etag, _elen, _evo, _enext = _read_tag(data, _epos)
            if _etag == 0x30:
                # 内部: OID + [critical boolean] + OCTET STRING value
                _ext_vo = _evo
                _oid = _read_oid_from_seq(data, _ext_vo, _elen)
                # 跳过OID tag+length+value
                _oid_tag, _oid_len, _oid_vo, _oid_next = _read_tag(data, _ext_vo)
                _rest = _oid_next

                # critical?
                if _rest < _eno and data[_rest] == 0x01:  # BOOLEAN
                    _btag, _blen, _bvo, _brest = _read_tag(data, _rest)
                    _rest = _brest

                if _rest < _eno and data[_rest] == 0x04:  # OCTET STRING
                    _otag, _olen, _ovo, _onext = _read_tag(data, _rest)
                    _oct_data = data[_ovo:_ovo + _olen]

                    if _oid == '2.5.29.17':  # SAN
                        _res['sans'] = _parse_san_extension(data, _ovo, _olen)
                    elif _oid == '2.5.29.19':  # BasicConstraints
                        _res['is_ca'] = _check_ca(_oct_data)
            _epos = _enext

    return _res


def _check_ca(data: bytes) -> bool:
    """解析BasicConstraints: SEQUENCE { BOOLEAN cA }"""
    if len(data) < 3 or data[0] != 0x30:
        return False
    _pos = 2
    _end = 2 + data[1] if data[1] < 0x80 else 2 + (data[1] & 0x7F)
    while _pos < min(_end, len(data)):
        _tag = data[_pos]
        _len = data[_pos + 1] if _pos + 1 < len(data) else 0
        if _tag == 0x01 and _len == 1:
            return data[_pos + 2] != 0x00
        _pos = _pos + 2 + _len if _len < 0x80 else _pos + 3 + (_len & 0x7F)
    return False


# 公开API
def parse_der_certificate(data: bytes) -> Optional[CertInfo]:
    """解析DER编码的X.509证书"""
    if len(data) < 4 or data[0] != 0x30:
        return None
    _, _tlen, _vo, _next = _read_tag(data, 0)
    _info = _parse_tbscert(data, _vo, _tlen)

    return CertInfo(
        subject=_info.get('subject', ''),
        issuer=_info.get('issuer', ''),
        serial=_info.get('serial', ''),
        valid_from=_info.get('valid_from', ''),
        valid_to=_info.get('valid_to', ''),
        pubkey_alg=_info.get('pubkey_alg', ''),
        key_size=_info.get('key_size', 0),
        sans=_info.get('sans', []),
        is_ca=_info.get('is_ca', False),
        sig_alg=_info.get('sig_alg', ''),
        raw_der=data,
    )


_CERT_PEM_RE = re.compile(
    r'-----BEGIN CERTIFICATE-----\s*(.+?)\s*-----END CERTIFICATE-----', re.DOTALL)


def find_pem_certificates(data: bytes) -> List[bytes]:
    """提取所有PEM编码的证书DER blob"""
    _out = []
    try:
        _text = data.decode('ascii')
    except UnicodeDecodeError:
        _text = data.decode('latin-1', errors='ignore')
    for _m in _CERT_PEM_RE.finditer(_text):
        try:
            _der = base64.b64decode(_m.group(1))
            _out.append(_der)
        except (ValueError, binascii.Error):  # 修复: bare except → base64 decode error
            pass
    return _out


def find_certificates(data: bytes) -> List[CertInfo]:
    """从任意数据中提取所有证书"""
    _certs = []
    _pems = find_pem_certificates(data)
    for _der in _pems:
        _cert = parse_der_certificate(_der)
        if _cert:
            _certs.append(_cert)

    # 无PEM时尝试直接搜DER (30 82开头的SEQUENCE)
    if not _pems:
        _pos = 0
        _dl = len(data)
        while _pos < _dl - 4:
            _pos = data.find(b'\x30\x82', _pos)
            if _pos == -1:
                break
            # 解析长度
            if _pos + 4 <= _dl:
                _l1 = data[_pos + 2]
                _l2 = data[_pos + 3]
                _cert_len = (_l1 << 8) | _l2
                _cert_len += 4  # tag + 2 length bytes
                if _pos + _cert_len <= _dl and 100 < _cert_len < 16384:
                    _cand = data[_pos:_pos + _cert_len]
                    _cert = parse_der_certificate(_cand)
                    if _cert:
                        _certs.append(_cert)
                        _pos += _cert_len
                        continue
            _pos += 1

    return _certs


def check_weakness(cert: CertInfo) -> List[Tuple[CertWeaknessSeverity, str]]:
    """检查证书弱点, 返回 [(严重级别, 描述)]"""
    _w = []

    # RSA密钥过短
    _ks = cert.key_size
    if _ks > 0 and 'RSA' in cert.pubkey_alg.upper():
        if _ks < 2048:
            _w.append((CertWeaknessSeverity.CRITICAL,
                       'RSA密钥仅{}位, 低于2048位安全阈值'.format(_ks)))
        elif _ks == 2048:
            _w.append((CertWeaknessSeverity.WARNING,
                       'RSA 2048位, 建议迁移至3072+'))

    # EC过小
    if 'EC' in cert.pubkey_alg.upper() and _ks > 0 and _ks < 256:
        _w.append((CertWeaknessSeverity.CRITICAL,
                   'EC密钥仅{}位, 低于256位安全阈值'.format(_ks)))

    # 签名算法
    _sa = cert.sig_alg.lower()
    if 'sha1' in _sa or 'sha-1' in _sa:
        _w.append((CertWeaknessSeverity.CRITICAL, '签名使用SHA1, 已不安全的哈希'))
    if 'md5' in _sa:
        _w.append((CertWeaknessSeverity.CRITICAL, '签名使用MD5, 已被完全攻破'))

    # 自签名
    if cert.subject == cert.issuer and cert.subject:
        _w.append((CertWeaknessSeverity.INFO, '自签名证书'))

    # 过期
    now = datetime.utcnow()
    for _label, _ts in [('valid_from', '未到生效日期'), ('valid_to', '已过期')]:
        try:
            _s = getattr(cert, _label)
            if _s:
                if _s.endswith('Z'):
                    _dt = datetime.strptime(_s, '%Y-%m-%dT%H:%M:%SZ')
                    if _label == 'valid_to' and _dt < now:
                        _w.append((CertWeaknessSeverity.CRITICAL, '证书已过期 ({})'.format(_s)))
                    elif _label == 'valid_from' and _dt > now:
                        _w.append((CertWeaknessSeverity.WARNING, '证书尚未生效 ({})'.format(_s)))
        except ValueError:  # 修复: bare except → ValueError (datetime解析)
            pass

    # SAN
    if not cert.sans:
        _cn = ''
        for _part in cert.subject.split(', '):
            if _part.startswith('CN='):
                _cn = _part[3:]
        if _cn and re.match(r'\d+\.\d+', _cn):
            _w.append((CertWeaknessSeverity.WARNING, '缺少SAN扩展, CN含IP格式'))

    return _w


# SCT (Signed Certificate Timestamp) 检测
# CT (Certificate Transparency) 要求CA将证书提交到公开日志。
# SCT嵌入在X.509v3扩展中 (OID 1.3.6.1.4.1.11129.2.4.2),
# 或通过TLS扩展/OCSP stapling提供。每个SCT包含:
# 日志ID (32字节 SHA-256)
# 时间戳 (8字节 Unix millis)
# 签名 (64/71字节 ECDSA P-256/P-384)
# 最小SCT约44 bytes (log_id + timestamp + signature).

_SCT_OID_BYTES = bytes.fromhex('060A2B06010401D679020402')  # DER: 06 0A 2B 06 01 04 01 D6 79 02 04 02


def count_scts(cert_der: bytes) -> int:
    """统计证书DER中的SCT条目数 (基于目标OID出现次数)."""
    if not cert_der:
        return 0
    # SCT OID出现一次即一个SCT列表扩展；列表内每个SCT由OCTET STRING包裹
    # 简化: 计数OID出现次数
    cnt = 0
    pos = 0
    while True:
        pos = cert_der.find(_SCT_OID_BYTES, pos)
        if pos == -1:
            break
        cnt += 1
        pos += len(_SCT_OID_BYTES)
    return cnt


def extract_sct_timestamps(cert_der: bytes) -> list:
    """从SCT列表中提取时间戳 (Unix millis, 8字节big-endian)。

    每个SCT的timestamp位于signature之前，距log_id偏移32字节。
    返回Unix秒级时间戳列表。
    """
    stamps = []
    if not cert_der or _SCT_OID_BYTES not in cert_der:
        return stamps
    # 定位SCT扩展后的OCTET STRING内容
    sct_pos = cert_der.find(_SCT_OID_BYTES)
    if sct_pos < 0:
        return stamps
    # 粗糙提取: 扫描SCT OID后512B内所有8B时间戳候选
    # 有效范围: 2013-01-01 (1356998400s) 至 2030-12-31
    region = cert_der[sct_pos:sct_pos + 1024]
    for off in range(0, len(region) - 8, 2):
        try:
            ts_ms = int.from_bytes(region[off:off + 8], 'big')
        except Exception:
            continue
        ts_s = ts_ms / 1000.0
        if 1356998400 <= ts_s <= 1924992000:  # 2013..2030
            stamps.append(int(ts_s))
    return sorted(set(stamps))


# 扫描器封装 —— 提供文件级入口与结构化结果

@dataclass
class Cert:
    """单张证书的检测结果。"""
    info: Optional[CertInfo] = None
    is_weak_sig: bool = False
    is_weak_key: bool = False
    is_self_signed: bool = False


@dataclass
class CertScanResult:
    """证书扫描聚合结果。"""
    total_certs: int = 0
    private_keys_found: int = 0
    certs: List[Cert] = field(default_factory=list)


class CertAnalyzer:
    """证书分析器 —— 提取 PEM 证书并标注弱点。"""

    def analyze_file(self, path: str) -> CertScanResult:
        try:
            with open(path, 'rb') as fh:
                data = fh.read()
        except OSError:
            return CertScanResult()
        return self.analyze_data(data)

    def analyze_data(self, data: bytes) -> CertScanResult:
        result = CertScanResult()
        if not data:
            return result
        text = data.decode('latin-1', errors='ignore')
        result.private_keys_found = sum(
            1 for m in re.finditer(
                r'-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----', text))

        pems = find_pem_certificates(data)
        for der in pems:
            info = parse_der_certificate(der)
            cert = Cert(info=info)
            if info is not None:
                sa = (info.sig_alg or '').lower()
                cert.is_weak_sig = ('md5' in sa or 'sha1' in sa)
                cert.is_weak_key = ('RSA' in (info.pubkey_alg or '').upper()
                                    and 0 < info.key_size < 2048)
                cert.is_self_signed = bool(info.subject and info.subject == info.issuer)
            # 字段级解析不完整时，回退到原始 DER 的弱点特征扫描
            if not (cert.is_weak_sig or cert.is_weak_key or cert.is_self_signed):
                cert.is_weak_sig = cert.is_weak_sig or _raw_weak_sig(der)
            result.certs.append(cert)
        result.total_certs = len(result.certs)
        return result


def _raw_weak_sig(der: bytes) -> bool:
    """在原始 DER 中检测弱签名 OID。

    MD5 with RSA 与 SHA1 with RSA 的 DER OID 序列。

    """
    md5_oid = bytes.fromhex('300d06092a864886f70d0101040500')
    sha1_oid = bytes.fromhex('300d06092a864886f70d0101050500')
    return md5_oid in der or sha1_oid in der


def analyze_certificates(path: str) -> CertScanResult:
    """便捷入口 —— 分析文件中的证书。"""
    return CertAnalyzer().analyze_file(path)


@dataclass
class CertFinding:
    """证书弱点发现条目。"""
    cert: Optional[CertInfo] = None
    weakness: str = ""
    severity: CertWeaknessSeverity = CertWeaknessSeverity.INFO
    description: str = ""
