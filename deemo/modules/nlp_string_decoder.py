"""
智能字符串解码: 自然语言处理辅助识别模块

功能:
    1. 对解码后的字符串, 使用语言模型判断是否为可读文本 (英文/中文)
    2. 过滤无效结果
    3. 自动标记高价值字符串 (URL/命令/文件路径) 并关联到行为分析

核心技术:
    - 字符熵 (Shannon entropy) 过滤
    - 字符集检测 (ASCII/UTF-8/GBK)
    - 简单 n-gram 统计判断可读性
    - 高价值模式: URL, 命令, 文件路径, IP, registry
"""

import logging
import re
import math
import unicodedata
from typing import Dict, Any, List, Optional, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum
from collections import Counter

logger = logging.getLogger(__name__)


class StringKind(Enum):
    RANDOM = "random"
    ASCII_TEXT = "ascii_text"
    CJK_TEXT = "cjk_text"
    URL = "url"
    FILE_PATH = "file_path"
    COMMAND = "command"
    REGISTRY = "registry"
    IP_ADDR = "ip_addr"
    EMAIL = "email"
    BASE64 = "base64"
    HEX = "hex"
    EMPTY = "empty"


@dataclass
class StringClassify:
    """字符串分类结果"""
    text: str
    kind: StringKind
    confidence: float
    entropy: float
    is_readable: bool
    is_high_value: bool
    metadata: Dict[str, Any] = field(default_factory=dict)


class EntropyCalculator:
    """Shannon 熵"""

    @staticmethod
    def calc(s: str) -> float:
        if not s:
            return 0.0
        cnt = Counter(s)
        n = len(s)
        return -sum((c / n) * math.log2(c / n) for c in cnt.values())


class LanguageDetector:
    """语言检测"""

    CJK_RANGES = [
        (0x4E00, 0x9FFF),     # CJK Unified
        (0x3400, 0x4DBF),     # CJK Ext A
        (0x20000, 0x2A6DF),   # CJK Ext B
    ]

    @staticmethod
    def is_cjk(s: str) -> bool:
        for ch in s:
            cp = ord(ch)
            for lo, hi in LanguageDetector.CJK_RANGES:
                if lo <= cp <= hi:
                    return True
        return False

    @staticmethod
    def is_ascii_printable(s: str) -> bool:
        return all(32 <= ord(c) <= 126 or c in '\n\r\t' for c in s)


class PatternMatcher:
    """模式匹配"""

    URL_RE = re.compile(
        r"^https?://[^\s/$.?#].[^\s]*$", re.IGNORECASE
    )
    IP_RE = re.compile(
        r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?::[0-9]+)?$"
    )
    EMAIL_RE = re.compile(
        r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    )
    WINDOWS_PATH_RE = re.compile(
        r"^[a-zA-Z]:\\(?:[^\\/:*?\"<>|\r\n]+\\)*[^\\/:*?\"<>|\r\n]*$"
    )
    UNIX_PATH_RE = re.compile(
        r"^(/[^/\s]+)+/?$"
    )
    REGISTRY_RE = re.compile(
        r"^(HKEY_[A-Z_]+|HKLM|HKCU|HKCR|HKU|HKCC)\\", re.IGNORECASE
    )
    COMMAND_RE = re.compile(
        r"^(?:/usr/(?:bin|sbin)|/bin/|/sbin/|cmd\.exe|powershell|sh |bash |cmd )"
    )
    BASE64_RE = re.compile(
        r"^[A-Za-z0-9+/]{16,}={0,2}$"
    )
    HEX_RE = re.compile(
        r"^[0-9a-fA-F]{8,}$"
    )

    @classmethod
    def classify_pattern(cls, s: str) -> Optional[StringKind]:
        if cls.URL_RE.match(s):
            return StringKind.URL
        if cls.EMAIL_RE.match(s):
            return StringKind.EMAIL
        if cls.IP_RE.match(s):
            return StringKind.IP_ADDR
        if cls.WINDOWS_PATH_RE.match(s) or cls.UNIX_PATH_RE.match(s):
            return StringKind.FILE_PATH
        if cls.REGISTRY_RE.match(s):
            return StringKind.REGISTRY
        if cls.COMMAND_RE.match(s):
            return StringKind.COMMAND
        if cls.HEX_RE.match(s):
            return StringKind.HEX
        if cls.BASE64_RE.match(s):
            return StringKind.BASE64
        return None


class ReadabilityScorer:
    """可读性打分"""

    @staticmethod
    def score_english(s: str) -> float:
        """英文可读性 (0-1)"""
        if not s:
            return 0.0
        # 至少含有一个元音, 字母比例高
        letters = sum(1 for c in s if c.isalpha())
        if letters / len(s) < 0.5:
            return 0.0
        vowels = sum(1 for c in s.lower() if c in "aeiouy")
        if vowels == 0:
            return 0.0
        # 空格比例 (单词分隔)
        spaces = s.count(" ")
        score = min(1.0, (vowels / letters) + (spaces / max(1, len(s))) * 2.0)
        return score / 2.0

    @staticmethod
    def score_cjk(s: str) -> float:
        if not s:
            return 0.0
        cjk_count = sum(1 for c in s if LanguageDetector.is_cjk(c))
        return min(1.0, cjk_count / max(1, len(s)) * 1.5)


class StringDecoder:
    """字符串解码器"""

    def __init__(self, min_length: int = 4,
                 max_entropy: float = 5.5):
        self.min_length = min_length
        self.max_entropy = max_entropy

    def _looks_like_text(self, s: str) -> Tuple[bool, float, StringKind]:
        if not s or len(s) < self.min_length:
            return False, 0.0, StringKind.EMPTY
        # 检查可读性
        if LanguageDetector.is_cjk(s):
            score = ReadabilityScorer.score_cjk(s)
            return score > 0.4, score, StringKind.CJK_TEXT
        if not LanguageDetector.is_ascii_printable(s):
            return False, 0.0, StringKind.RANDOM
        # 模式匹配
        pat = PatternMatcher.classify_pattern(s)
        if pat:
            return True, 0.95, pat
        # 英文打分
        eng = ReadabilityScorer.score_english(s)
        if eng > 0.4:
            return True, eng, StringKind.ASCII_TEXT
        # 字节熵
        ent = EntropyCalculator.calc(s)
        if ent > self.max_entropy:
            return False, 0.0, StringKind.RANDOM
        return False, eng, StringKind.RANDOM

    def classify(self, s: str) -> StringClassify:
        is_read, conf, kind = self._looks_like_text(s)
        ent = EntropyCalculator.calc(s)
        is_high_value = kind in {
            StringKind.URL, StringKind.FILE_PATH, StringKind.COMMAND,
            StringKind.REGISTRY, StringKind.IP_ADDR, StringKind.EMAIL
        }
        return StringClassify(
            text=s, kind=kind, confidence=conf, entropy=ent,
            is_readable=is_read, is_high_value=is_high_value
        )

    def classify_batch(self, strings: List[str]) -> List[StringClassify]:
        return [self.classify(s) for s in strings]

    def filter_readable(self, strings: List[str]) -> List[str]:
        return [c.text for c in self.classify_batch(strings) if c.is_readable]

    def filter_high_value(self, strings: List[str]) -> List[StringClassify]:
        return [c for c in self.classify_batch(strings) if c.is_high_value]


def nlp_decode_strings(strings: List[str]) -> Dict[str, Any]:
    """便捷入口"""
    decoder = StringDecoder()
    classified = decoder.classify_batch(strings)
    return {
        'success': True,
        'total': len(strings),
        'readable_count': sum(1 for c in classified if c.is_readable),
        'high_value_count': sum(1 for c in classified if c.is_high_value),
        'classified': [
            {
                'text': c.text,
                'kind': c.kind.value,
                'confidence': c.confidence,
                'entropy': round(c.entropy, 2),
                'is_readable': c.is_readable,
                'is_high_value': c.is_high_value
            }
            for c in classified
        ],
        'high_value': [
            {'text': c.text, 'kind': c.kind.value}
            for c in classified if c.is_high_value
        ]
    }
