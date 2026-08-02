# 2026-07-25
# ==== 经典密码破解工具集 ====
# CTF和逆向分析专用。覆盖xor/vigenere/substitution/caesar/rot系列。
# 评分策略: English字母频率 + bigram + trigram + 常见单词, 四维加权求和。
# Kasiski检验 + Friedman重合指数用于Vigenere密钥长度推断。
# 替换密码破解: 爬山算法 + 模拟退火, 种内迭代10000轮。

import math
import random
from typing import List, Tuple, Optional


_ENGLISH_FREQ = {
    'a': 0.08167, 'b': 0.01492, 'c': 0.02782, 'd': 0.04253,
    'e': 0.12702, 'f': 0.02228, 'g': 0.02015, 'h': 0.06094,
    'i': 0.06966, 'j': 0.00153, 'k': 0.00772, 'l': 0.04025,
    'm': 0.02406, 'n': 0.06749, 'o': 0.07507, 'p': 0.01929,
    'q': 0.00095, 'r': 0.05987, 's': 0.06327, 't': 0.09056,
    'u': 0.02758, 'v': 0.00978, 'w': 0.02360, 'x': 0.00150,
    'y': 0.01974, 'z': 0.00074, ' ': 0.13000,
}

_COMMON_BIGRAMS = {'th': 1.52, 'he': 1.28, 'in': 0.94, 'er': 0.94,
                   'an': 0.82, 're': 0.68, 'nd': 0.63, 'at': 0.59,
                   'on': 0.57, 'nt': 0.56, 'ha': 0.56, 'es': 0.56,
                   'st': 0.55, 'en': 0.55, 'ed': 0.53, 'to': 0.52,
                   'it': 0.50, 'ou': 0.50, 'ea': 0.47, 'hi': 0.46}

_COMMON_TRIGRAMS = {'the': 1.81, 'and': 0.73, 'ing': 0.72, 'her': 0.47,
                    'hat': 0.42, 'his': 0.41, 'tha': 0.38, 'ere': 0.38,
                    'for': 0.35, 'ent': 0.34, 'ion': 0.33, 'ter': 0.33,
                    'was': 0.32, 'you': 0.30, 'ith': 0.30, 'ver': 0.28}

_COMMON_WORDS = {'the', 'and', 'that', 'have', 'for', 'not', 'with',
                 'you', 'this', 'but', 'his', 'from', 'they', 'say',
                 'her', 'she', 'will', 'one', 'all', 'would', 'there',
                 'their', 'what', 'out', 'about', 'who', 'get', 'which',
                 'when', 'make', 'can', 'like', 'time', 'just', 'him',
                 'know', 'take', 'people', 'into', 'year', 'your', 'good',
                 'some', 'could', 'them', 'see', 'other', 'than', 'then',
                 'now', 'look', 'only', 'come', 'its', 'over', 'think',
                 'also', 'back', 'after', 'use', 'two', 'how', 'our',
                 'work', 'first', 'well', 'way', 'even', 'new', 'want',
                 'because', 'any', 'these', 'give', 'day', 'most', 'us'}


# ---- 英语评分 ----
def _score_english(data: bytes) -> float:
    """四维English评分: unigram+bigram+trigram+common_words"""
    _s = 0.0
    try:
        _text = data.decode('latin-1').lower()
    except:
        return _s
    _n = max(1, len(_text))

    # 可打印比例
    _printable = sum(1 for _c in _text if 32 <= ord(_c) < 127 or _c in '\n\r\t')
    _s += 5.0 * _printable / _n

    for _c in _text:
        _s += _ENGLISH_FREQ.get(_c, -0.01)

    for _i in range(_n - 1):
        _bg = _text[_i:_i + 2]
        _s += _COMMON_BIGRAMS.get(_bg, 0) * 0.1

    for _i in range(_n - 2):
        _tg = _text[_i:_i + 3]
        _s += _COMMON_TRIGRAMS.get(_tg, 0) * 0.2

    _words = _text.split()
    for _w in _words:
        if _w in _COMMON_WORDS:
            _s += 3.0

    return _s / len(data) * 100


# ---- 单字节XOR破解 ----
def single_byte_xor_crack(data: bytes) -> List[Tuple[int, float, bytes]]:
    """暴力256密钥, 按English评分排序返回top 5"""
    _res = []
    for _k in range(256):
        _plain = bytes(_b ^ _k for _b in data)
        _sc = _score_english(_plain)
        _res.append((_k, _sc, _plain))
    _res.sort(key=lambda x: -x[1])
    return _res[:5]


# ---- 辅助函数 ----
def _byte_entropy(data: bytes) -> float:
    _n = len(data)
    _freq = [0] * 256
    for _b in data:
        _freq[_b] += 1
    _h = 0.0
    for _c in _freq:
        if _c:
            _p = _c / _n
            _h -= _p * math.log2(_p)
    return _h


def _is_base64(data: bytes) -> bool:
    _a = set(b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=')
    return all(_b in _a for _b in data)


def _is_hex(data: bytes) -> bool:
    try:
        _s = data.decode('ascii')
        return all(_c in '0123456789abcdefABCDEF \n\r\t' for _c in _s)
    except:
        return False


# ---- 密码类型检测 ----
def detect_cipher_type(data: bytes) -> str:
    """IC + entropy + charset分析 → 密码类型"""
    _ic = friedman_ic(data)
    _ent = _byte_entropy(data)
    _printable = sum(1 for _b in data if 32 <= _b < 127) / max(1, len(data))

    if _printable > 0.9:
        if len(data) % 4 == 0 and _is_base64(data):
            return 'base64'
        if _is_hex(data):
            return 'hex'
        return 'plaintext'

    if 0.06 < _ic < 0.07:
        return 'modern'
    if 0.04 < _ic < 0.06:
        return 'vigenere'
    if 0.66 < _ic < 0.72:
        return 'caesar' if _single_byte_check(data) else 'xor'
    if _ic > 0.72:
        return 'substitution'
    if _ic < 0.04:
        return 'modern'

    return 'unknown'


def _single_byte_check(data: bytes) -> bool:
    _best_e = float('inf')
    for _k in range(256):
        _pt = bytes(_b ^ _k for _b in data[:256])
        _ent = _byte_entropy(_pt)
        _best_e = min(_best_e, _ent)
    return _best_e < _byte_entropy(data[:256]) * 0.7


# ---- Kasiski检验 ----
def kasiski_examination(data: bytes) -> int:
    """重复trigram间距的GCD → 推测密钥长度"""
    _tri = {}
    for _i in range(len(data) - 3):
        _tg = data[_i:_i + 3]
        _tri.setdefault(_tg, []).append(_i)

    _dists = [_tri[_tg][_j] - _tri[_tg][_j - 1]
              for _tg, _ps in _tri.items()
              if len(_ps) > 1
              for _j in range(1, min(4, len(_ps)))]

    if not _dists:
        return 1
    _g = _dists[0]
    for _d in _dists[1:]:
        _g = math.gcd(_g, _d)
    return _g if _g > 1 else 1


# ---- Friedman重合指数 ----
def friedman_ic(data: bytes) -> float:
    """Index of Coincidence: English≈0.067, Random≈0.038"""
    _n = len(data)
    if _n < 2:
        return 0.0
    _freq = [0] * 256
    for _b in data:
        _freq[_b] += 1
    return sum(_c * (_c - 1) for _c in _freq) / (_n * (_n - 1))


# ---- Vigenere破解 ----
def solve_vigenere(data: bytes, key_length: int) -> str:
    """按列频率分析破解Vigenere(key_length>0)"""
    if key_length < 1:
        key_length = 1
    _key = []
    for _col in range(key_length):
        _cb = bytes(data[_i] for _i in range(_col, len(data), key_length))
        _best_k, _best_s = 0, -float('inf')
        for _k in range(256):
            _pt = bytes(_b ^ _k for _b in _cb)
            _s = _score_english(_pt)
            if _s > _best_s:
                _best_s, _best_k = _s, _k
        _key.append(_best_k)
    _plain = bytes(data[_i] ^ _key[_i % key_length] for _i in range(len(data)))
    try:
        return _plain.decode('latin-1')
    except:
        return _plain.hex()


# ---- 替换密码破解(爬山+模拟退火) ----
def substitution_solve(data: bytes) -> str:
    """爬山+模拟退火破解monoalphabetic substitution"""
    _alpha = list('abcdefghijklmnopqrstuvwxyz')
    _best_key = _alpha[:]
    _text = data.decode('latin-1', errors='replace').lower()
    _best_score = _sub_score(_text, dict(zip(_alpha, _best_key)))

    for _iter in range(10000):
        _a, _b = random.sample(range(26), 2)
        _nk = _best_key[:]
        _nk[_a], _nk[_b] = _nk[_b], _nk[_a]
        _ns = _sub_score(_text, dict(zip(_alpha, _nk)))
        _temp = max(0.001, 1.0 - _iter / 10000)
        if _ns > _best_score or random.random() < math.exp((_ns - _best_score) / _temp):
            _best_key, _best_score = _nk, _ns

    _final = dict(zip(_alpha, _best_key))
    return ''.join(_final.get(_c, _c) for _c in _text)


def _sub_score(text: str, mapping: dict) -> float:
    _mapped = ''.join(mapping.get(c, c) for c in text if c.isalpha() or c == ' ')
    return _score_english(_mapped.encode('latin-1'))


# ---- ROT-N ----
def rot_n(data: bytes, n: int) -> bytes:
    """字母移位, n可为负"""
    _out = bytearray(len(data))
    for _i, _b in enumerate(data):
        if 65 <= _b <= 90:
            _out[_i] = (_b - 65 + n) % 26 + 65
        elif 97 <= _b <= 122:
            _out[_i] = (_b - 97 + n) % 26 + 97
        else:
            _out[_i] = _b
    return bytes(_out)


# ---- Rail Fence 密码检测 (2026-07-28) ----
# 栅栏密码将明文按 "之" 字形写入k行, 然后按行读出。
# 检测策略: brute-force k∈[2,12], 对每种k做之字形展开,
# 用英语n-gram评分 — 最高分对应的k为候选密钥。

def _rail_fence_decrypt(ct: str, rails: int) -> str:
    """栅栏解密: k行之字形展开."""
    n = len(ct)
    if rails <= 1 or rails >= n:
        return ct
    # 计算每行应填充的字符数
    cycle = 2 * (rails - 1)
    row_lens = [0] * rails
    for i in range(n):
        pos = i % cycle
        if pos < rails:
            row_lens[pos] += 1
        else:
            row_lens[cycle - pos] += 1

    # 从密文按行填充
    rows = []
    off = 0
    for rl in row_lens:
        rows.append(list(ct[off:off + rl]))
        off += rl

    # 之字形读出
    out = []
    row_ptr = [0] * rails
    for i in range(n):
        pos = i % cycle
        if pos < rails:
            r = pos
        else:
            r = cycle - pos
        out.append(rows[r][row_ptr[r]])
        row_ptr[r] += 1
    return ''.join(out)


def detect_rail_fence(ciphertext: str) -> List[Tuple[int, float, str]]:
    """Brute-force栅栏密码密钥检测, 返回 (rails, score, plaintext_sample)."""
    results = []
    filtered = ''.join(c.upper() for c in ciphertext if c.isalpha())
    if len(filtered) < 4:
        return results
    for rails in range(2, min(13, len(filtered) // 2)):
        pt = _rail_fence_decrypt(filtered, rails)
        s = _score_english(pt)
        results.append((rails, s, pt[:60]))
    results.sort(key=lambda r: -r[1])
    return results[:5]


# ---- Beaufort 密码 (Vigenère 变体) ----
# Beaufort: C_i = (K_i - P_i) mod 26 (对称: 加密=解密)
# 与 Vigenère 的区别: 密钥字母减明文而非加

def beaufort_decrypt(ciphertext: str, key: str) -> str:
    """Beaufort密码解密 (与加密相同操作)."""
    key = key.upper()
    result = []
    ki = 0
    for c in ciphertext:
        if c.isalpha():
            base = ord('A') if c.isupper() else ord('a')
            k_val = ord(key[ki % len(key)]) - ord('A')
            p_val = (k_val - (ord(c.upper()) - ord('A'))) % 26
            result.append(chr(base + p_val))
            ki += 1
        else:
            result.append(c)
    return ''.join(result)
