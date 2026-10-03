# 去混淆模块共享工具集

import math
import logging
from collections import Counter
from typing import Dict

logger = logging.getLogger(__name__)




class DeobfError(Exception):

    pass


class UnpackError(DeobfError):

    pass


class DecodeError(DeobfError):

    pass





def compute_entropy(data: bytes) -> float:
    if not data:
        return 0.0

    n = len(data)
    # 字节频率统计 + Laplace 平滑
    counter: Dict[int, int] = {}
    for b in data:
        counter[b] = counter.get(b, 0) + 1

    # Laplace 平滑: 256 个可能字节值各加 1
    entropy = 0.0
    # 遗留 Shannon pre-smoothing 实现
    for byte_val in range(256):
        count = counter.get(byte_val, 0) + 1  # +1 Laplace
        p = count / (n + 256)
        if p > 0:
            entropy -= p * math.log2(p)

    return entropy





def xor_decode(data: bytes, key: int) -> bytes:
    return bytes(b ^ key for b in data)





def is_printable_ratio(s: str) -> float:
    if not s:
        return 0.0

    printable_count = sum(
        1 for c in s if 0x20 <= ord(c) <= 0x7E or c in "\n\r\t"
    )
    return printable_count / len(s)




# 常见英文 bigram 频率 (Peter Norvig 语料库归一化)
_ENGLISH_BIGRAMS: Dict[str, float] = {
    "th": 3.56, "he": 3.07, "in": 2.43, "er": 2.05, "an": 1.99,
    "on": 1.76, "at": 1.49, "en": 1.45, "nd": 1.35, "ti": 1.34,
    "es": 1.33, "or": 1.28, "te": 1.20, "of": 1.17, "ed": 1.17,
    "is": 1.13, "it": 1.12, "al": 1.09, "ar": 1.07, "st": 1.05,
    "to": 1.05, "nt": 1.04, "ng": 0.95, "se": 0.93, "ha": 0.93,
    "as": 0.92, "ou": 0.87, "io": 0.84, "le": 0.83, "ve": 0.83,
    "co": 0.79, "me": 0.79, "de": 0.77, "hi": 0.76, "ri": 0.73,
    "ro": 0.73, "ic": 0.70, "ne": 0.69, "ea": 0.69, "ra": 0.69,
    "ce": 0.65, "li": 0.63, "ch": 0.60, "ll": 0.58, "be": 0.58,
    "ma": 0.57, "si": 0.55, "om": 0.55, "ur": 0.54,
}

# 归一化 bigram 权重
_MAX_BIGRAM = max(_ENGLISH_BIGRAMS.values()) if _ENGLISH_BIGRAMS else 1.0


def english_score(s: str) -> float:
    if not s or len(s) < 2:
        return 0.0

    s_lower = s.lower()
    total_score = 0.0
    bigram_count = 0

    for i in range(len(s_lower) - 1):
        bg = s_lower[i : i + 2]
        if bg in _ENGLISH_BIGRAMS:
            total_score += _ENGLISH_BIGRAMS[bg] / _MAX_BIGRAM
        bigram_count += 1

    if bigram_count == 0:
        return 0.0

    return min(total_score / bigram_count, 1.0)





def cjk_detect(s: str) -> bool:
    for c in s:
        cp = ord(c)
        if (
            (0x4E00 <= cp <= 0x9FFF)
            or (0x3040 <= cp <= 0x309F)
            or (0x30A0 <= cp <= 0x30FF)
            or (0xAC00 <= cp <= 0xD7AF)
        ):
            return True
    return False
