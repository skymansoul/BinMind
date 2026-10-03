"""DNS分析——熵计算、双字母频率、元辅音比等特征提取函数。"""

import math
import re
from collections import Counter
from typing import List

from .dns_analyzer_types import BIGRAM_FREQ, BIGRAM_MAX, DGA_LABEL_LEN_MIN, DGA_LABEL_LEN_MAX


def shannon_entropy(s: str) -> float:
    """计算字符串香农熵，衡量字符分布随机性。

    DGA域名通常每标签熵较高（>3.0），正常域名含常见词根如
    'google', 'yahoo'等，熵值较低。分标签计算而非整个域名。
    """
    if not s:
        return 0.0
    _h = Counter(s)
    length = len(s)
    return -sum((freq / length) * math.log2(freq / length) for freq in _h.values())


def label_entropies(domain: str) -> List[float]:
    """计算域名每个标签（点分隔部分）的熵值"""
    labels = domain.lower().rstrip(".").split(".")
    # 去除TLD，关注二级及更深标签
    if len(labels) > 1:
        labels = labels[:-1]
    return [shannon_entropy(lb) for lb in labels if lb]


def bigram_frequency_score(domain: str) -> float:
    # 与英文双字母频率模型比较，DGA域名的双字母频率异常低
    _s = domain.lower().rstrip(".").split(".")[-2] if len(domain.split(".")) >= 2 else domain.lower()
    _s = re.sub(r'[^a-z]', '', _s)
    if len(_s) < 2:
        return 0.0
    bigrams = [_s[i:i+2] for i in range(len(_s)-1)]
    total = 0.0
    _m = 0
    for bg in bigrams:
        freq = BIGRAM_FREQ.get(bg, 0.0)
        total += freq
        _m += 1
    return total / (_m * BIGRAM_MAX) if _m > 0 else 0.0


def vowel_consonant_ratio(domain: str) -> float:
    _s = domain.lower().rstrip(".").split(".")[-2] if len(domain.split(".")) >= 2 else domain.lower()
    _s = re.sub(r'[^a-z]', '', _s)
    if not _s:
        return 0.0
    vowels = sum(1 for ch in _s if ch in "aeiou")
    consonants = len(_s) - vowels
    if consonants == 0:
        return 1.0
    return vowels / consonants


def length_penalty(label: str) -> float:
    """对极短或极长标签应用熵修正因子。

    短标签（<4字符）熵计算噪声大，上调0.1。长标签（>25字符）无论熵值
    均为高度可疑。正常标签返回0。
    """
    _l = len(label)
    if _l < 4:
        return 0.15  # 短标签噪声惩罚
    elif _l > 25:
        return 0.5   # 长标签高度可疑
    return 0.0
