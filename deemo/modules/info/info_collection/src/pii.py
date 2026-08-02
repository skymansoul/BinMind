# 2026-07-26
# pii — PII 扫描器，18 种敏感数据类型
# Microsoft Presidio-inspired 分层方法：regex -> 校验函数 -> 上下文关键词
# Luhn 校验、BIN 前缀匹配、base58 验证等二级校验降低误报

import re
import os
from dataclasses import dataclass, field
from typing import List, Optional, Tuple, Set

# ===== PII 类型枚举 =====
PII_TYPES = [
    "CREDIT_CARD", "SSN", "EMAIL", "PHONE", "IP_ADDRESS",
    "API_KEY", "PASSPORT", "DRIVERS_LICENSE", "IBAN",
    "BITCOIN_ADDRESS", "JWT_TOKEN", "PRIVATE_KEY",
    "DB_CONNECTION_STRING", "OAUTH_TOKEN", "WINDOWS_SID",
    "MAC_ADDRESS", "VIN", "GPS_COORDINATE",
]


@dataclass
class PiiFinding:
  type: str
  value: str
  confidence: float  # 0.0-1.0
  location: int = 0  # 偏移量
  context: str = ""


# ---- 上下文关键词（提高置信度）----
_CONTEXT_KEYWORDS: dict = {
    "CREDIT_CARD": {"card", "credit", "cc", "visa", "mastercard", "amex", "cvc", "cvv", "expir"},
    "SSN": {"ssn", "social security", "tax id", "taxpayer"},
    "PASSWORD": {"password", "passwd", "pwd", "secret", "credential"},
    "API_KEY": {"api", "key", "token", "auth", "bearer", "apikey", "api_key"},
    "PRIVATE_KEY": {"private key", "rsa", "dsa", "ecdsa", "ed25519", "certificate"},
    "DB_CONNECTION": {"connection", "jdbc", "mongodb", "postgres", "mysql", "database", "connstr"},
}


# //// 各类型正则定义 ////

# Credit Card: 匹配 13-19 位数字 + 分隔符
_CC_PATTERN = re.compile(
    r'\b(?:4[0-9]{12}(?:[0-9]{3})?|'  # Visa
    r'5[1-5][0-9]{14}|'  # MasterCard
    r'3[47][0-9]{13}|'  # Amex
    r'3(?:0[0-5]|[68][0-9])[0-9]{11}|'  # Diners Club
    r'6(?:011|5[0-9]{2})[0-9]{12}|'  # Discover
    r'(?:2131|1800|35\d{3})\d{11})'  # JCB
    r'(?:[\s-]?[0-9]{4}){3,4}\b'
)

# SSN: XXX-XX-XXXX 格式，带区域号验证
_SSN_PATTERN = re.compile(
    r'\b(?!000|666|9\d{2})(\d{3})[- ]?(?!00)(\d{2})[- ]?(?!0000)(\d{4})\b'
)

# Email: 简化 RFC 5322
_EMAIL_PATTERN = re.compile(
    r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b'
)

# Phone: 国际 + 美国格式
_PHONE_PATTERN = re.compile(
    r'(?:\+?1[-. ]?)?\(?\d{3}\)?[-. ]?\d{3}[-. ]?\d{4}'
    r'|(?:\+\d{1,3}[-. ]?)?\(?\d{1,4}\)?[-. ]?\d{1,14}'
)

# IP v4
_IPV4_PATTERN = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}'
    r'(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
)
# IP v6 (简化)
_IPV6_PATTERN = re.compile(
    r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b'
    r'|\b::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}\b'
    r'|\b(?:[0-9a-fA-F]{1,4}:){1,7}:\b'
    r'|\b(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}\b'
)

# API Keys: AWS / GCP / Azure / GitHub / Stripe / Slack
_API_KEY_PATTERNS = {
    "aws_access": re.compile(r'\b(?:AKIA|ASIA)[0-9A-Z]{16}\b'),
    "aws_secret": re.compile(r'\b[A-Za-z0-9/+=]{40}\b'),
    "gcp_api": re.compile(r'\bAIza[0-9A-Za-z\-_]{35}\b'),
    "github_token": re.compile(r'\b(?:ghp|gho|ghu|ghs|ghr)_[0-9a-zA-Z]{36}\b'),
    "github_old": re.compile(r'\b[0-9a-f]{40}\b'),
    "stripe_live": re.compile(r'\bsk_live_[0-9a-zA-Z]{24,99}\b'),
    "stripe_test": re.compile(r'\bsk_test_[0-9a-zA-Z]{24,99}\b'),
    "slack_bot": re.compile(r'\bxoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}\b'),
    "slack_token": re.compile(r'\bxox[aprs]-[a-zA-Z0-9-]{10,}\b'),
    "generic_key": re.compile(r'(?i)(?:api[_-]?key|apikey|api[_-]?secret)[\'\":\s]*([A-Za-z0-9+/_-]{20,64})'),
}

# Passport numbers: 国际通用格式 (字母 + 6-9 位数字)
_PASSPORT_PATTERN = re.compile(
    r'\b[A-Z]{1,2}\d{6,9}\b'
)

# Driver's License (US states simplified)
_DL_PATTERN = re.compile(
    r'\b(?:[A-Z]\d{7,8}|\d{3}-\d{2}-\d{4}|\d{2}-\d{3}-\d{4})\b'
)

# IBAN: 国家码 + 校验位 + BBAN
_IBAN_PATTERN = re.compile(
    r'\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b'
)

# Bitcoin: base58 (P2PKH/P2SH) and bech32
_BTC_BASE58_PATTERN = re.compile(r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b')
_BTC_BECH32_PATTERN = re.compile(r'\bbc1[ac-hj-np-z02-9]{11,71}\b')

# JWT: header.payload.signature
_JWT_PATTERN = re.compile(
    r'\beyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\b'
)

# Private Key PEM markers
_PRIVATE_KEY_PATTERN = re.compile(
    r'-----BEGIN\s+(?:RSA|DSA|EC|OPENSSH|ENCRYPTED)\s+PRIVATE\s+KEY-----'
    r'[\s\S]*?'
    r'-----END\s+(?:RSA|DSA|EC|OPENSSH|ENCRYPTED)\s+PRIVATE\s+KEY-----'
)

# DB Connection Strings
_DB_CONN_PATTERN = re.compile(
    r'(?i)(?:jdbc|mongodb|mysql|postgres(?:ql)?|sqlite|oracle|mssql|redis)://'
    r'[^\s\'\"]+'
)

# OAuth tokens
_OAUTH_PATTERN = re.compile(
    r'ya29\.[0-9A-Za-z\-_]+'
    r'|ey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}',
    re.IGNORECASE
)

# Windows SID
_SID_PATTERN = re.compile(
    r'\bS-1-\d+(-\d+){1,14}\b'
)

# MAC address
_MAC_PATTERN = re.compile(
    r'\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b'
    r'|\b(?:[0-9A-Fa-f]{4}\.){2}[0-9A-Fa-f]{4}\b'
)

# VIN: 17 字符 (不含 I, O, Q)
_VIN_PATTERN = re.compile(
    r'\b[A-HJ-NPR-Z0-9]{17}\b'
)

# GPS coordinates
_GPS_PATTERN = re.compile(
    r'[-+]?\d{1,3}\.\d{4,}[\s,]+[-+]?\d{1,3}\.\d{4,}'
)

# ===== 校验函数 =====
_BASE58_ALPHABET = set('123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz')


def _luhn_check(card_number: str) -> bool:
    """Luhn 算法校验银行卡号。"""
    _digits = [int(c) for c in card_number.replace(' ', '').replace('-', '') if c.isdigit()]
    if len(_digits) < 13:
        return False
    _checksum = 0
    _parity = len(_digits) % 2
    for _i, _d in enumerate(_digits):
        if _i % 2 == _parity:
            _d2 = _d * 2
            _checksum += _d2 - 9 if _d2 > 9 else _d2
        else:
            _checksum += _d
    return _checksum % 10 == 0


def _is_valid_base58(s: str) -> bool:
    return all(c in _BASE58_ALPHABET for c in s)


def _iban_checksum(iban: str) -> bool:
    """IBAN MOD-97 校验。"""
    _clean = iban.strip().upper()
    if len(_clean) < 15:
        return False
    _rearranged = _clean[4:] + _clean[:4]
    _num_str = ''.join(
        str(ord(c) - 55) if c.isalpha() else c
        for c in _rearranged
    )
    try:
        return int(_num_str) % 97 == 1
    except ValueError:
        return False


def _ssn_area_valid(ssn: str) -> bool:
    """SSN 区域号基本验证：不能全零、不在保留范围。"""
    _clean = ssn.replace('-', '').replace(' ', '')
    if len(_clean) != 9:
        return False
    _area = int(_clean[:3])
    _group = int(_clean[3:5])
    _serial = int(_clean[5:])
    if _area == 0 or _area == 666 or _area >= 900:
        return False
    if _group == 0 or _serial == 0:
        return False
    return True


# 信用卡 BIN 前缀验证
_CC_BIN_PREFIXES = {
    "4": "visa",
    "51": "mc", "52": "mc", "53": "mc", "54": "mc", "55": "mc",
    "34": "amex", "37": "amex",
    "6011": "discover", "65": "discover",
    "30": "diners", "36": "diners", "38": "diners",
    "2131": "jcb", "1800": "jcb", "35": "jcb",
}


def _is_valid_cc_prefix(number: str) -> bool:
    _clean = number.replace(' ', '').replace('-', '')
    for _pref in _CC_BIN_PREFIXES:
        if _clean.startswith(_pref):
            return True
    return False


# ---- 上下文检测 ----
def _context_score(value: str, text: str, pii_type: str, radius: int = 80) -> float:
    """在匹配位置附近搜索关键词，提高置信度。"""
    _kw = _CONTEXT_KEYWORDS.get(pii_type, set())
    if not _kw:
        return 0.0
    _pos = text.find(value)
    if _pos < 0:
        return 0.0
    _start = max(0, _pos - radius)
    _end = min(len(text), _pos + len(value) + radius)
    _context = text[_start:_end].lower()
    _matches = sum(1 for k in _kw if k.lower() in _context)
    return min(_matches / max(len(_kw), 1), 1.0) * 0.3


# //// 扫描主函数 ////
# 分层扫描策略：
# 1. 正则第一轮（快速，高召回）
# 2. 校验函数第二轮（精确，降低误报）
# 3. 上下文关键词第三轮（提高置信度）

def scan(text: str, target_types: List[str] = None) -> List[PiiFinding]:
    """对文本进行 PII 扫描，返回发现列表。

    参数 target_types: 要扫描的类型列表，None 表示全部 18 种。
    """
    if not text:
        return []
    _findings: List[PiiFinding] = []
    _types = set(target_types) if target_types else set(PII_TYPES)

    if "CREDIT_CARD" in _types:
        for _m in _CC_PATTERN.finditer(text):
            _val = _m.group(0)
            if _is_valid_cc_prefix(_val) and _luhn_check(_val):
                _conf = 0.70 + _context_score(_val, text, "CREDIT_CARD")
                _findings.append(PiiFinding("CREDIT_CARD", _val, min(_conf, 1.0), _m.start()))

    if "SSN" in _types:
        for _m in _SSN_PATTERN.finditer(text):
            _val = _m.group(0)
            if _ssn_area_valid(_val):
                _conf = 0.60 + _context_score(_val, text, "SSN")
                _findings.append(PiiFinding("SSN", _val, min(_conf, 1.0), _m.start()))

    if "EMAIL" in _types:
        for _m in _EMAIL_PATTERN.finditer(text):
            _val = _m.group(0)
            if len(_val) <= 254 and not _val.startswith('_') and not _val.endswith('.'):
                _findings.append(PiiFinding("EMAIL", _val, 0.75, _m.start()))

    if "PHONE" in _types:
        _seen: Set[str] = set()
        for _m in _PHONE_PATTERN.finditer(text):
            _val = _m.group(0)
            _clean = re.sub(r'[^\d]', '', _val)
            if len(_clean) >= 10 and _clean not in _seen:
                _seen.add(_clean)
                _findings.append(PiiFinding("PHONE", _val, 0.55, _m.start()))

    if "IP_ADDRESS" in _types:
        for _pat in [_IPV4_PATTERN, _IPV6_PATTERN]:
            for _m in _pat.finditer(text):
                _val = _m.group(0)
                # 排除 version 字符串中的数字
                if not re.search(r'(?:version|ver)\s*' + re.escape(_val[:4]), text[max(0, _m.start()-20):_m.start()], re.IGNORECASE):
                    _findings.append(PiiFinding("IP_ADDRESS", _val, 0.65, _m.start()))

    if "API_KEY" in _types:
        for _name, _pat in _API_KEY_PATTERNS.items():
            for _m in _pat.finditer(text):
                _val = _m.group(0)
                # 从 generic_key 模式提取 group(1)
                if _name == "generic_key" and _m.lastindex:
                    _val = _m.group(1) if _m.group(1) else _m.group(0)
                _conf = 0.60
                if _name in ("aws_access", "github_token", "stripe_live", "slack_bot"):
                    _conf = 0.85
                _conf += _context_score(_val, text, "API_KEY")
                _findings.append(PiiFinding("API_KEY", _val, min(_conf, 1.0), _m.start(),
                                            context=_name))

    if "PASSPORT" in _types:
        for _m in _PASSPORT_PATTERN.finditer(text):
            _val = _m.group(0)
            _findings.append(PiiFinding("PASSPORT", _val, 0.40, _m.start()))

    if "DRIVERS_LICENSE" in _types:
        for _m in _DL_PATTERN.finditer(text):
            _val = _m.group(0)
            _findings.append(PiiFinding("DRIVERS_LICENSE", _val, 0.35, _m.start()))

    if "IBAN" in _types:
        for _m in _IBAN_PATTERN.finditer(text):
            _val = _m.group(0)
            if _iban_checksum(_val):
                _findings.append(PiiFinding("IBAN", _val, 0.75, _m.start()))

    if "BITCOIN_ADDRESS" in _types:
        for _m in _BTC_BASE58_PATTERN.finditer(text):
            _val = _m.group(0)
            if _is_valid_base58(_val):
                _findings.append(PiiFinding("BITCOIN_ADDRESS", _val, 0.70, _m.start()))
        for _m in _BTC_BECH32_PATTERN.finditer(text):
            _val = _m.group(0)
            _findings.append(PiiFinding("BITCOIN_ADDRESS", _val, 0.80, _m.start()))

    if "JWT_TOKEN" in _types:
        for _m in _JWT_PATTERN.finditer(text):
            _val = _m.group(0)
            _findings.append(PiiFinding("JWT_TOKEN", _val, 0.50, _m.start()))

    if "PRIVATE_KEY" in _types:
        for _m in _PRIVATE_KEY_PATTERN.finditer(text):
            _val = _m.group(0)
            _conf = 0.90 + _context_score(_val, text, "PRIVATE_KEY")
            _findings.append(PiiFinding("PRIVATE_KEY", _val, min(_conf, 1.0), _m.start()))

    if "DB_CONNECTION_STRING" in _types:
        for _m in _DB_CONN_PATTERN.finditer(text):
            _val = _m.group(0)
            _conf = 0.70 + _context_score(_val, text, "DB_CONNECTION")
            _findings.append(PiiFinding("DB_CONNECTION_STRING", _val, min(_conf, 1.0), _m.start()))

    if "OAUTH_TOKEN" in _types:
        for _m in _OAUTH_PATTERN.finditer(text):
            _val = _m.group(0)
            _findings.append(PiiFinding("OAUTH_TOKEN", _val, 0.45, _m.start()))

    if "WINDOWS_SID" in _types:
        for _m in _SID_PATTERN.finditer(text):
            _val = _m.group(0)
            _findings.append(PiiFinding("WINDOWS_SID", _val, 0.60, _m.start()))

    if "MAC_ADDRESS" in _types:
        for _m in _MAC_PATTERN.finditer(text):
            _val = _m.group(0)
            _findings.append(PiiFinding("MAC_ADDRESS", _val, 0.70, _m.start()))

    if "VIN" in _types:
        for _m in _VIN_PATTERN.finditer(text):
            _val = _m.group(0)
            _findings.append(PiiFinding("VIN", _val, 0.40, _m.start()))

    if "GPS_COORDINATE" in _types:
        for _m in _GPS_PATTERN.finditer(text):
            _val = _m.group(0)
            _findings.append(PiiFinding("GPS_COORDINATE", _val, 0.55, _m.start()))

    return _findings


def scan_file(filepath: str, target_types: List[str] = None, chunk_size: int = 1048576) -> List[PiiFinding]:
    """扫描文件中的 PII 信息。大文件分块扫描。

    参数 chunk_size: 每块大小（字节），默认 1MB。
    """
    if not os.path.isfile(filepath):
        return []
    _all_findings: List[PiiFinding] = []
    _overlap = 512  # 重叠区避免跨块边界丢失匹配
    with open(filepath, 'r', encoding='utf-8', errors='replace') as _fh:
        _buf = ""
        _offset = 0
        while True:
            _chunk = _fh.read(chunk_size)
            if not _chunk:
                break
            _text = _buf + _chunk
            _findings = scan(_text, target_types)
            for _f in _findings:
                _f.location += _offset - len(_buf)
                _all_findings.append(_f)
            _buf = _text[-_overlap:] if len(_text) > _overlap else _text
            _offset += len(_chunk)
    return _all_findings
