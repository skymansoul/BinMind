"""PII 扫描器 — 在二进制、日志及文本流中识别个人可识别信息。"""

import json
import logging
import os
import re
import struct
from collections import defaultdict, Counter
from dataclasses import dataclass, field
from enum import Enum
from math import log2
from typing import Any, Dict, List, Optional

_log = logging.getLogger(__name__)


class RiskLevel(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class PIIType(Enum):
    EMAIL = "email"
    SSN = "ssn"
    CREDIT_CARD = "credit_card"
    PHONE = "phone"
    IP_ADDRESS = "ip_address"
    API_KEY = "api_key"
    AWS_KEY = "aws_key"
    JWT_TOKEN = "jwt_token"
    PRIVATE_KEY = "private_key"
    DATABASE_URL = "database_url"
    PASSPORT = "passport"
    DRIVER_LICENSE = "driver_license"
    DATE_OF_BIRTH = "date_of_birth"
    STREET_ADDRESS = "street_address"


# 编译后的正则库 — 按选择度从高到低排列
_PATTERNS: Dict[str, re.Pattern] = {
    "email": re.compile(
        r'[a-zA-Z0-9][a-zA-Z0-9._%+-]{0,63}@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?'
        r'(?:\.[a-zA-Z]{2,})+',
    ),
    "credit_card": re.compile(
        r'\b(?:\d[ -]*?){13,19}\b',
    ),
    "ssn": re.compile(
        r'\b(?!000|666|9\d{2})\d{3}[-\s]?(?!00)\d{2}[-\s]?(?!0000)\d{4}\b',
    ),
    "phone_us": re.compile(
        r'\b(?:\+?1[-.\s]?)?\(?([2-9]\d{2})\)?[-.\s]?([2-9]\d{2})[-.\s]?(\d{4})\b',
    ),
    "phone_international": re.compile(
        r'\b\+[\d]{1,3}[\s.-]?\(?\d{1,4}\)?[\s.-]?\d{1,4}[\s.-]?\d{1,9}\b',
    ),
    "ipv4": re.compile(
        r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b',
    ),
    "ipv6": re.compile(
        r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|'
        r'\b(?:[0-9a-fA-F]{1,4}:){1,7}:\b|'
        r'\b::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}\b',
    ),
    "api_key": re.compile(
        r'(?i)(?:api[_-]?key|secret|token|auth[_-]?token|access[_-]?key)'
        r'[\s:=]+["\']?[a-zA-Z0-9+/=._-]{20,}["\']?',
    ),
    "aws_access_key": re.compile(
        r'\bAKIA[0-9A-Z]{16}\b',
    ),
    "aws_secret_key": re.compile(
        r'(?i)(?:aws[_-]?secret|secret[_-]?key)[\s:=]+["\']?[a-zA-Z0-9+/=]{40}["\']?',
    ),
    "jwt_token": re.compile(
        r'eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}',
    ),
    "private_key_pem": re.compile(
        r'-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----'
        r'(?:[a-zA-Z0-9+/=\r\n]+)'
        r'-----END\s+(?:RSA\s+)?PRIVATE\s+KEY-----',
    ),
    "database_url": re.compile(
        r'(?i)(?:postgres|mysql|mongodb|redis|sqlite)://[a-zA-Z0-9._-]+(:[^@\s]+)?@[a-zA-Z0-9._-]+'
        r'(:\d+)?/[a-zA-Z0-9._-]+',
    ),
    "passport": re.compile(
        r'\b[A-Z]{1,2}\d{6,8}\b',  # 通用护照号码模式
    ),
    "driver_license_us": re.compile(
        r'\b[A-Z]\d{7}\b',  # 美国多州驾照格式
    ),
    "date_of_birth": re.compile(
        r'\b(?:19|20)\d{2}[-/](?:0[1-9]|1[0-2])[-/](?:0[1-9]|[12]\d|3[01])\b',
    ),
    "street_address": re.compile(
        r'\b\d{1,5}\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+)*\s+(?:Street|St|Avenue|Ave|Road|Rd|'
        r'Boulevard|Blvd|Drive|Dr|Lane|Ln|Court|Ct|Circle|Cir|Way|Place|Pl)\b',
    ),
    # base64 编码疑似敏感数据（长度 >= 32，含高熵段）
    "base64_suspicious": re.compile(
        r'(?:(?:[A-Za-z0-9+/]{4}){8,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?)',
    ),
}

def _luhn_check(number: str) -> bool:
    """Luhn 算法校验信用卡号候选值。"""
    digits = [int(c) for c in number if c.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False
    checksum = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


def _base64_entropy_check(b64_str: str) -> bool:
    """base64 串熵检验：低于 4.0 的低熵串（如全填充 'A'）不标记为敏感。

    纯 base64 英文/数字/符号混合熵约 5.2–5.8。
    """
    if len(b64_str) < 32:
        return False
    n = len(b64_str)
    counts = Counter(b64_str)
    entropy = -sum((c / n) * log2(c / n) for c in counts.values())
    return entropy > 4.0


# 发现数据结构

@dataclass
class PIIScanFinding:
    pii_type: str          # EMAIL, SSN, CREDIT_CARD 等
    value: str
    start: int
    end: int
    risk: RiskLevel = RiskLevel.HIGH
    redacted: str = ""     # 脱敏后形态
    context: str = ""      # 周边文本窗口
    rarity_score: float = 1.0  # 基于历史扫描的稀有度，1.0=首次出现

    def redacted_value(self) -> str:
        if self.redacted:
            return self.redacted
        return self._default_redact()

    def _default_redact(self) -> str:
        val = self.value
        if self.pii_type == "email":
            at = val.find("@")
            return val[0] + "***" + val[at:] if at > 0 else "***@***"
        if self.pii_type in ("credit_card", "ssn", "phone_us", "phone_international"):
            plain = "".join(c for c in val if c.isdigit())
            return ("X" * (len(plain) - 4) + plain[-4:]) if len(plain) >= 4 else "X" * len(plain)
        if self.pii_type == "date_of_birth":
            return "YYYY-MM-DD"
        if self.pii_type == "ipv4":
            parts = val.split(".")
            return ".".join(p if i >= 2 else "XX" for i, p in enumerate(parts))
        if self.pii_type == "aws_access_key":
            return val[:6] + "X" * (len(val) - 10) + val[-4:]

        # 通用兜底：保留首尾各 2 字符
        if len(val) > 6:
            return val[:2] + "*" * (len(val) - 4) + val[-2:]
        return "*" * len(val)


@dataclass
class PIIScanResult:
    source: str = ""
    findings: List[PIIScanFinding] = field(default_factory=list)
    total_bytes_scanned: int = 0
    redacted_output: str = ""

    def summary(self) -> Dict[str, int]:
        counts: Dict[str, int] = defaultdict(int)
        for f in self.findings:
            counts[f.pii_type] += 1
        return {"total": sum(counts.values()), "by_type": dict(counts)}


# 字符串稀有度评分：参照 TF-IDF 思想
# 在全量字符串集合中，某种模式出现的频率越低，越可能是真实 PII。
# 维护全局模式计数器，每次扫描后更新。
_global_pattern_freq: Counter = Counter()
_global_scan_count: int = 0


def _compute_rarity_score(pii_type: str, value: str) -> float:
    """基于历史扫描数据计算 PII 值稀有度。

    稀有度 = 1 - (该值出现次数 / (最大出现次数 + 1))。
    首次出现的值得分 1.0，高频通用模板趋近 0。
    """
    key = f"{pii_type}:{value}"
    cnt = _global_pattern_freq.get(key, 0)
    max_cnt = max(_global_pattern_freq.values()) if _global_pattern_freq else 1
    return 1.0 - (cnt / (max_cnt + 1))


def _update_global_frequency(findings: list) -> None:
    """更新全局频率计数器。"""
    global _global_scan_count
    for f in findings:
        key = f"{f.pii_type}:{f.value}"
        _global_pattern_freq[key] += 1
    _global_scan_count += 1


# 扫描器核心

class PIIScanner:
    """文本/二进制/字符串中个人可识别信息检测器。"""

    _MAX_STRING_LEN = 4096
    _MIN_PRINTABLE_RUN = 4
    # 二进制大块全零或全 0xFF 直接跳过
    _ZERO_RUN_SKIP = 128

    def __init__(self, include_low_confidence: bool = False):
        self._include_low = include_low_confidence

    # -- 公开扫描入口 ----------------------------------------------------------

    def scan(self, data: Any, source: str = "") -> PIIScanResult:
        """按输入类型分发：文件路径、字符串或字节。"""
        if isinstance(data, str) and os.path.isfile(data):
            source = data
            raw = self._read_file(data)
            if raw is None:
                return PIIScanResult(source=source, findings=[])
            return self._scan_bytes(raw, source)

        if isinstance(data, str):
            return self._scan_text(data, source)

        if isinstance(data, (bytes, bytearray)):
            return self._scan_bytes(data, source)

        return PIIScanResult(source=str(source), findings=[])

    # -- 文本扫描 --------------------------------------------------------

    def _scan_text(self, text: str, source: str) -> PIIScanResult:
        findings = self._match_patterns(text, 0)
        _update_global_frequency(findings)
        redacted = self._redact(text, findings)
        return PIIScanResult(source=source, findings=findings,
                             total_bytes_scanned=len(text.encode("utf-8")),
                             redacted_output=redacted)

    # -- 二进制扫描：先提取可打印字符串 ---------------------------------

    def _scan_bytes(self, raw: bytes, source: str) -> PIIScanResult:
        """从二进制数据中提取 ASCII 及 UTF-16 字符串，应用 PII 模式匹配。"""
        findings: List[PIIScanFinding] = []

        # 第一遍：ASCII 可打印序列（跳过零块以加速）
        current_run = b""
        current_start = 0
        zero_streak = 0
        for i, b in enumerate(raw):
            if b == 0 or b == 0xFF:
                zero_streak += 1
                if zero_streak > self._ZERO_RUN_SKIP and current_run:
                    if len(current_run) >= self._MIN_PRINTABLE_RUN:
                        text = current_run.decode("ascii", errors="replace")
                        findings.extend(self._match_patterns(text, current_start))
                    current_run = b""
                if current_run:
                    if len(current_run) >= self._MIN_PRINTABLE_RUN:
                        text = current_run.decode("ascii", errors="replace")
                        findings.extend(self._match_patterns(text, current_start))
                    current_run = b""
                continue
            zero_streak = 0
            if 0x20 <= b <= 0x7E:
                if not current_run:
                    current_start = i
                current_run += bytes([b])
            else:
                if len(current_run) >= self._MIN_PRINTABLE_RUN:
                    text = current_run.decode("ascii", errors="replace")
                    findings.extend(self._match_patterns(text, current_start))
                current_run = b""

        # 清空尾部 ASCII 序列
        if len(current_run) >= self._MIN_PRINTABLE_RUN:
            text = current_run.decode("ascii", errors="replace")
            findings.extend(self._match_patterns(text, current_start))

        # 第二遍：UTF-16 LE 字符串
        try:
            utf16_text = raw.decode("utf-16-le", errors="ignore")
            findings.extend(self._match_patterns(utf16_text, 0, offset_multiplier=2))
        except Exception:
            _log.debug("suppressed", exc_info=True)

        # 后过滤：验证候选值（信用卡 Luhn、SSN 格式、base64 熵等）
        findings = [f for f in findings if self._validate(f)]
        _update_global_frequency(findings)

        redacted = self._redact(raw.decode("ascii", errors="replace")
                                if len(raw) < 1_000_000 else
                                raw[:1_000_000].decode("ascii", errors="replace"),
                                findings)

        return PIIScanResult(
            source=source,
            findings=findings,
            total_bytes_scanned=len(raw),
            redacted_output=redacted if len(redacted) < 100_000 else "",
        )

    def _match_patterns(self, text: str, offset: int,
                         offset_multiplier: int = 1) -> List[PIIScanFinding]:
        findings: List[PIIScanFinding] = []
        for name, pattern in _PATTERNS.items():
            for m in pattern.finditer(text):
                val = m.group(0)

                # base64 候选需通过熵检验
                if name == "base64_suspicious" and not _base64_entropy_check(val):
                    continue

                # 去重：相同位置相同值跳过（同类型不同位置保留）
                if any(f.value == val and f.start == m.start() * offset_multiplier + offset
                       for f in findings):
                    continue

                risk = self._classify_risk(name, val)
                ctx = text[max(0, m.start() - 20): m.end() + 30]
                rarity = _compute_rarity_score(name, val)

                findings.append(PIIScanFinding(
                    pii_type=name,
                    value=val,
                    start=m.start() * offset_multiplier + offset,
                    end=m.end() * offset_multiplier + offset,
                    risk=risk,
                    context=ctx,
                    rarity_score=round(rarity, 3),
                ))

        return findings

    @staticmethod
    def _classify_risk(pii_type: str, value: str) -> RiskLevel:
        if pii_type in ("credit_card", "ssn", "private_key_pem"):
            return RiskLevel.CRITICAL
        if pii_type in ("api_key", "aws_secret_key", "passport", "database_url"):
            return RiskLevel.HIGH
        if pii_type in ("email", "phone_us", "phone_international", "jwt_token",
                        "driver_license_us", "date_of_birth", "aws_access_key"):
            return RiskLevel.MEDIUM
        if pii_type == "base64_suspicious":
            return RiskLevel.MEDIUM
        return RiskLevel.LOW

    @staticmethod
    def _validate(finding: PIIScanFinding) -> bool:
        if finding.pii_type == "credit_card":
            return _luhn_check(finding.value)
        if finding.pii_type == "ssn":
            nums = "".join(c for c in finding.value if c.isdigit())
            return len(nums) == 9 and not nums.startswith("000") and not nums.startswith("666")
        # 过滤无效 IPv4 八位组
        if finding.pii_type == "ipv4":
            parts = finding.value.split(".")
            if len(parts) == 4:
                return all(
                    0 <= int(p) <= 255 and not (p.startswith("0") and len(p) > 1)
                    for p in parts if p.isdigit()
                )
        return True

    @staticmethod
    def _redact(text: str, findings: List[PIIScanFinding]) -> str:
        if not findings:
            return text

        # 从末尾向前处理，保持字符偏移不变
        sorted_findings = sorted(findings, key=lambda f: f.start, reverse=True)
        result = list(text)
        for f in sorted_findings:
            if f.start < len(result) and f.end <= len(result):
                replacement = f.redacted_value()
                result[f.start:f.end] = list(replacement)
        return "".join(result)

    @staticmethod
    def _read_file(path: str) -> Optional[bytes]:
        try:
            with open(path, "rb") as fh:
                return fh.read()
        except OSError as exc:
            _log.warning("Cannot read %s: %s", path, exc)
            return None


# -- 模块级便捷函数 ----------------------------------------------------------

def scan_text(text: str) -> List[PIIScanFinding]:
    return PIIScanner()._scan_text(text, "").findings

def scan_file(path: str) -> List[PIIScanFinding]:
    return PIIScanner().scan(path).findings


# XOR 解码后 PII 二次扫描
# 大量凭证信息在二进制中以 XOR 编码存储。对常见单字节 XOR key
# 解码后重新执行 PII 模式匹配，捕获静态扫描遗漏的隐藏凭证。

_XOR_DECODE_KEYS = (0x55, 0xAA, 0xFF, 0x20, 0x13, 0x37, 0x00, 0x01, 0x02, 0x03, 0x04)


def scan_with_xor_decode(raw: bytes, source: str = "") -> dict[str, list[PIIScanFinding]]:
    """对原始字节执行常见 XOR key 解码后重新扫描 PII。

    尝试 _XOR_DECODE_KEYS 中的每个 key 解码整个输入，
    对解码结果运行 PII 模式匹配。
    返回: {xor_key_hex: findings_list, ...}。
    """
    results: dict[str, list[PIIScanFinding]] = {}
    scanner = PIIScanner()
    n = len(raw)

    for key in _XOR_DECODE_KEYS:
        decoded_bytes = bytes(b ^ key for b in raw)
        try:
            decoded_text = decoded_bytes.decode("ascii", errors="ignore")
        except Exception:
            continue
        # 仅在解码后 ASCII 可打印率 > 0.3 时才进行 PII 扫描
        ascii_cnt = sum(1 for c in decoded_text if 0x20 <= ord(c) <= 0x7E)
        if n > 0 and ascii_cnt / n < 0.3:
            continue
        findings = scanner._scan_text(decoded_text, source).findings
        if findings:
            results[f"0x{key:02x}"] = findings

    return results
