"""PII 扫描器 — 在二进制、日志及文本流中识别个人可识别信息。"""

import json
import logging
import os
import re
import struct
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
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


# 编译后的正则库 — 按选择度从高到低排列。
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
        r'(?:[a-zA-Z0-9+/=\r\n]+)?'
        r'(?:-----END\s+(?:RSA\s+)?PRIVATE\s+KEY-----)?',
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


# 发现数据结构

_PII_TYPE_MAP = {
    "email": PIIType.EMAIL,
    "ssn": PIIType.SSN,
    "credit_card": PIIType.CREDIT_CARD,
    "phone_us": PIIType.PHONE,
    "phone_international": PIIType.PHONE,
    "ipv4": PIIType.IP_ADDRESS,
    "ipv6": PIIType.IP_ADDRESS,
    "api_key": PIIType.API_KEY,
    "aws_access_key": PIIType.AWS_KEY,
    "aws_secret_key": PIIType.AWS_KEY,
    "jwt_token": PIIType.JWT_TOKEN,
    "private_key_pem": PIIType.PRIVATE_KEY,
    "database_url": PIIType.DATABASE_URL,
    "passport": PIIType.PASSPORT,
    "driver_license_us": PIIType.DRIVER_LICENSE,
    "date_of_birth": PIIType.DATE_OF_BIRTH,
    "street_address": PIIType.STREET_ADDRESS,
}

@dataclass
class PIIScanFinding:
    pii_type: str          # EMAIL, SSN, CREDIT_CARD 等
    value: str
    start: int
    end: int
    risk: RiskLevel = RiskLevel.HIGH
    redacted: str = ""     # 脱敏后形态，如 "J***@example.com"
    context: str = ""      # 周边文本窗口

    @property
    def type(self) -> PIIType:
        return _PII_TYPE_MAP.get(self.pii_type, PIIType.API_KEY)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'type': self.type.value,
            'value': self.value,
            'start': self.start,
            'end': self.end,
            'risk': self.risk.value,
            'redacted': self.redacted_value(),
            'context': self.context,
        }

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
    binary_path: str = ""
    analysis_success: bool = True
    error_message: str = ""

    @property
    def detections(self) -> List[PIIScanFinding]:
        return self.findings

    @property
    def total_detections(self) -> int:
        return len(self.findings)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'binary_path': self.binary_path or self.source,
            'detections': [f.to_dict() for f in self.findings],
            'total_detections': len(self.findings),
            'analysis_success': self.analysis_success,
            'error_message': self.error_message,
            'total_bytes_scanned': self.total_bytes_scanned,
        }

    @staticmethod
    def _mask_value(pii_type: PIIType, value: str) -> str:
        if pii_type == PIIType.EMAIL:
            at = value.find("@")
            if at > 0:
                return value[0] + "***@" + value[at + 1:]
            return "***@***"
        if pii_type == PIIType.PHONE:
            if len(value) >= 7:
                return value[:3] + "***" + value[-4:]
            return value[:1] + "***" + value[-1:]
        # 通用：保留前 5 与后 4 字符
        if len(value) > 9:
            return value[:5] + "*" * (len(value) - 9) + value[-4:]
        if len(value) > 4:
            return value[:2] + "*" * (len(value) - 4) + value[-2:]
        return value[:1] + "***" + value[-1:]

    def summary(self) -> Dict[str, int]:
        counts: Dict[str, int] = defaultdict(int)
        for f in self.findings:
            counts[f.pii_type] += 1
        return {"total": sum(counts.values()), "by_type": dict(counts)}


# 扫描器核心

class PIIScanner:
    """在文本、二进制文件及字符串节中检测个人可识别信息。

    Usage::

        scanner = PIIScanner("user_data.bin")
        result = scanner.scan()
        # 或
        scanner = PIIScanner()
        result = scanner.scan("user_data.txt")
    """

    _MAX_STRING_LEN = 4096
    _MIN_PRINTABLE_RUN = 4

    def __init__(self, binary_path: Optional[str] = None,
                 include_low_confidence: bool = False):
        self.binary_path = binary_path
        self._include_low = include_low_confidence

    # 公开扫描入口

    def scan(self, data: Any = None, source: str = "") -> PIIScanResult:
        """按输入类型分发：文件路径、字符串或字节。data 缺省时使用构造传入路径。"""
        if data is None:
            data = self.binary_path
        if isinstance(data, str):
            if os.path.isfile(data):
                source = data
                raw = self._read_file(data)
                if raw is None:
                    return PIIScanResult(source=source, binary_path=str(data),
                                         analysis_success=False,
                                         error_message='无效的文件路径: ' + str(data))
                res = self._scan_bytes(raw, source)
                res.binary_path = str(data)
                res.analysis_success = True
                return res
            if data == self.binary_path:
                # 构造传入的路径不存在——按无效路径处理
                return PIIScanResult(source=str(data), binary_path=str(data),
                                     analysis_success=False,
                                     error_message='无效的文件路径: ' + str(data))
            # 非文件路径字符串按纯文本处理
            res = self._scan_text(data, source)
            res.analysis_success = True
            return res

        if isinstance(data, (bytes, bytearray)):
            res = self._scan_bytes(bytes(data), source)
            res.analysis_success = True
            return res

        return PIIScanResult(source=str(source), analysis_success=False,
                             error_message='无效的文件路径: ' + str(data))

    def generate_report(self) -> str:
        """生成 PII 扫描报告文本。"""
        result = self.scan()
        lines = ['PII与敏感数据泄露扫描报告', '=' * 40]
        if not result.analysis_success:
            lines.append('扫描失败: ' + result.error_message)
            return '\n'.join(lines)
        lines.append('扫描文件: ' + (result.binary_path or result.source or 'N/A'))
        lines.append('扫描字节数: %d' % result.total_bytes_scanned)
        lines.append('检测总数: %d' % result.total_detections)
        lines.append('-' * 40)
        for f in result.findings:
            lines.append('- %s: %s (偏移 %d, 风险 %s)'
                         % (f.type.value, f.value, f.start, f.risk.value))
        return '\n'.join(lines)

    # 文本扫描

    def _scan_text(self, text: str, source: str) -> PIIScanResult:
        findings = self._match_patterns(text, 0)
        redacted = self._redact(text, findings)
        return PIIScanResult(source=source, findings=findings,
                             total_bytes_scanned=len(text.encode("utf-8")),
                             redacted_output=redacted)

    # 二进制扫描: 先提取可打印字符串

    def _scan_bytes(self, raw: bytes, source: str) -> PIIScanResult:
        """从二进制数据中提取 ASCII 及 UTF-16 字符串，应用 PII 模式匹配。"""
        findings: List[PIIScanFinding] = []

        # 第一遍：ASCII 可打印序列
        current_run = b""
        current_start = 0
        for i, b in enumerate(raw):
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

        # 后过滤：验证候选值（信用卡 Luhn、SSN 格式等）
        findings = [f for f in findings if self._validate(f)]

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
            used_char_offset = text if "email" in name else text
            for m in pattern.finditer(text):
                val = m.group(0)

                # 去重：相同位置相同值则跳过（同类型不同位置保留）
                if any(f.value == val and f.start == m.start() * offset_multiplier + offset
                       for f in findings):
                    continue

                risk = self._classify_risk(name, val)
                ctx = text[max(0, m.start() - 20): m.end() + 30]

                findings.append(PIIScanFinding(
                    pii_type=name,
                    value=val,
                    start=m.start() * offset_multiplier + offset,
                    end=m.end() * offset_multiplier + offset,
                    risk=risk,
                    context=ctx,
                ))

        return findings

    @staticmethod
    def _classify_risk(pii_type: str, value: str) -> RiskLevel:
        if pii_type in ("credit_card", "ssn", "private_key_pem"):
            return RiskLevel.CRITICAL
        if pii_type in ("api_key", "aws_secret_key", "passport", "database_url"):
            return RiskLevel.HIGH
        if pii_type in ("email", "phone_us", "phone_international", "jwt_token",
                        "driver_license_us", "date_of_birth"):
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


# 模块级便捷函数

def scan_text(text: str) -> List[PIIScanFinding]:
    return PIIScanner()._scan_text(text, "").findings

def scan_file(path: str) -> List[PIIScanFinding]:
    return PIIScanner().scan(path).findings
