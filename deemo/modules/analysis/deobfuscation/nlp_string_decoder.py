import logging
import re
import math
from typing import Dict, Any, List, Optional, Tuple
from collections import Counter
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


class StringKind:
    _val = None

    def __init__(self, value):
        self._val = value

    @property
    def value(self):
        return self._val

    def __str__(self):
        return self._val or ""

    def __repr__(self):
        return f"StringKind.{self._val}" if self._val else "StringKind.EMPTY"

    def __eq__(self, other):
        if isinstance(other, StringKind):
            return self._val == other._val
        return False

    def __hash__(self):
        return hash(self._val)


for _kind_name in ("EMPTY", "URL", "IP_ADDR", "BASE64", "HEX", "EMAIL",
                    "FILE_PATH", "REGISTRY", "COMMAND", "ASCII_TEXT",
                    "CJK_TEXT", "RANDOM"):
    setattr(StringKind, _kind_name, StringKind(_kind_name.lower()))


@dataclass
class StringClassify:
    text: str
    kind: StringKind
    confidence: float
    entropy: float
    is_readable: bool
    is_high_value: bool
    metadata: dict = field(default_factory=dict)


class EntropyCalculator:
    @staticmethod
    def calc(s: str) -> float:
        if not s:
            return 0.0
        cnt = Counter(s)
        n = len(s)
        return -sum((c / n) * math.log2(c / n) for c in cnt.values())

    @staticmethod
    def calc_bytewise(data: bytes) -> float:
        if not data:
            return 0.0
        cnt = [0] * 256
        for b in data:
            cnt[b] += 1
        n = len(data)
        ent = 0.0
        for c in cnt:
            if c > 0:
                p = c / n
                ent -= p * math.log2(p)
        return ent


class LanguageDetector:
    CJK_RANGES = [
        (0x4E00, 0x9FFF),
        (0x3400, 0x4DBF),
        (0x20000, 0x2A6DF),
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
    URL_RE = re.compile(r"^https?://[^\s/$.?#].[^\s]*$", re.IGNORECASE)
    IP_RE = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?::[0-9]+)?$")
    EMAIL_RE = re.compile(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")
    WINDOWS_PATH_RE = re.compile(r"^[a-zA-Z]:\\(?:[^\\/:*?\"<>|\r\n]+\\)*[^\\/:*?\"<>|\r\n]*$")
    UNIX_PATH_RE = re.compile(r"^(/[^/\s]+)+/?$")
    REGISTRY_RE = re.compile(r"^(HKEY_[A-Z_]+|HKLM|HKCU|HKCR|HKU|HKCC)\\", re.IGNORECASE)
    COMMAND_RE = re.compile(r"^(?:/usr/(?:bin|sbin)|/bin/|/sbin/|cmd\.exe|powershell|sh |bash |cmd )")
    BASE64_RE = re.compile(r"^[A-Za-z0-9+/]{16,}={0,2}$")
    HEX_RE = re.compile(r"^[0-9a-fA-F]{8,}$")

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
    # 英语 bigram 频率
    _EN_BIGRAMS: Dict[str, float] = {
        "th": 0.035, "he": 0.030, "in": 0.022, "er": 0.020, "an": 0.019,
        "re": 0.018, "on": 0.017, "at": 0.016, "en": 0.015, "nd": 0.014,
        "ti": 0.013, "es": 0.013, "or": 0.012, "te": 0.012, "of": 0.011,
        "ed": 0.011, "is": 0.010, "it": 0.010, "al": 0.010, "ar": 0.010,
        "st": 0.010, "to": 0.010, "nt": 0.010, "ng": 0.009, "se": 0.009,
        "ha": 0.009, "as": 0.009, "ou": 0.009, "io": 0.009, "le": 0.009,
    }

    # 英语 trigram 频率（从 Brown 语料库抽样）
    _EN_TRIGRAMS: Dict[str, float] = {
        "the": 0.018, "ing": 0.011, "and": 0.007, "ion": 0.006,
        "ent": 0.005, "tio": 0.005, "for": 0.004, "has": 0.004,
        "her": 0.004, "hat": 0.004, "his": 0.004, "tha": 0.004,
        "ere": 0.003, "ati": 0.003, "ver": 0.003, "ter": 0.003,
        "est": 0.003, "res": 0.003, "con": 0.003, "men": 0.003,
        "pro": 0.003, "com": 0.003, "ain": 0.003, "ons": 0.003,
        "nce": 0.003, "ect": 0.003, "all": 0.003, "ant": 0.003,
        "sta": 0.002, "hen": 0.002, "sti": 0.002, "cti": 0.002,
    }

    @staticmethod
    def score_english(s: str) -> float:
        if not s:
            return 0.0
        letters = sum(1 for c in s if c.isalpha())
        if letters / len(s) < 0.5:
            return 0.0
        vowels = sum(1 for c in s.lower() if c in "aeiouy")
        if vowels == 0:
            return 0.0
        spaces = s.count(" ")
        base_score = min(1.0, (vowels / letters) + (spaces / max(1, len(s))) * 2.0) / 2.0

        s_lower = s.lower()
        # bigram 密度
        bigram_hits = 0
        bigram_total = max(1, len(s_lower) - 1)
        for i in range(bigram_total):
            bg = s_lower[i:i + 2]
            if bg in ReadabilityScorer._EN_BIGRAMS:
                bigram_hits += 1
        bg_density = bigram_hits / bigram_total

        # trigram 密度 - 比 bigram 更具区分度，能更好区分随机字节和真实文本
        trigram_hits = 0
        trigram_total = max(1, len(s_lower) - 2)
        for i in range(trigram_total):
            tg = s_lower[i:i + 3]
            if tg in ReadabilityScorer._EN_TRIGRAMS:
                trigram_hits += 1
        tg_density = trigram_hits / trigram_total

        return min(base_score + bg_density * 0.2 + tg_density * 0.3, 1.0)

    @staticmethod
    def score_cjk(s: str) -> float:
        if not s:
            return 0.0
        cjk_count = sum(1 for c in s if LanguageDetector.is_cjk(c))
        return min(1.0, cjk_count / max(1, len(s)) * 1.5)


class StringDecoder:
    def __init__(self, min_length: int = 4, max_entropy: float = 5.5):
        self.min_length = min_length
        self.max_entropy = max_entropy

    def _looks_like_text(self, s: str) -> Tuple[bool, float, StringKind]:
        if not s or len(s) < self.min_length:
            return False, 0.0, StringKind.EMPTY
        if LanguageDetector.is_cjk(s):
            score = ReadabilityScorer.score_cjk(s)
            return score > 0.4, score, StringKind.CJK_TEXT
        if not LanguageDetector.is_ascii_printable(s):
            return False, 0.0, StringKind.RANDOM
        pat = PatternMatcher.classify_pattern(s)
        if pat:
            return True, 0.95, pat
        eng = ReadabilityScorer.score_english(s)
        if eng > 0.4:
            return True, eng, StringKind.ASCII_TEXT
        ent = EntropyCalculator.calc(s)
        if ent > self.max_entropy:
            return False, 0.0, StringKind.RANDOM
        return False, eng, StringKind.RANDOM

    def classify(self, s: str) -> StringClassify:
        is_read, conf, kind = self._looks_like_text(s)
        ent = EntropyCalculator.calc(s)
        high_value_kinds = {
            StringKind.URL.value, StringKind.FILE_PATH.value,
            StringKind.COMMAND.value, StringKind.REGISTRY.value,
            StringKind.IP_ADDR.value, StringKind.EMAIL.value,
        }
        is_high_value = kind.value in high_value_kinds if kind and kind.value else False
        return StringClassify(
            text=s, kind=kind, confidence=conf, entropy=ent,
            is_readable=is_read, is_high_value=is_high_value)

    def classify_batch(self, strings: List[str]) -> List[StringClassify]:
        return [self.classify(s) for s in strings]

    def filter_readable(self, strings: List[str]) -> List[str]:
        return [c.text for c in self.classify_batch(strings) if c.is_readable]

    def filter_high_value(self, strings: List[str]) -> List[StringClassify]:
        return [c for c in self.classify_batch(strings) if c.is_high_value]

    def filter_by_kind(self, strings: List[str], kind: StringKind) -> List[str]:
        return [c.text for c in self.classify_batch(strings) if c.kind == kind]


def nlp_decode_strings(strings: List[str]) -> Dict[str, Any]:
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
                'kind': c.kind.value if c.kind else None,
                'confidence': c.confidence,
                'entropy': round(c.entropy, 2),
                'is_readable': c.is_readable,
                'is_high_value': c.is_high_value}
            for c in classified],
        'high_value': [
            {'text': c.text, 'kind': c.kind.value if c.kind else None}
            for c in classified if c.is_high_value]}
