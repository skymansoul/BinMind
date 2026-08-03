# 字节模式扫描器: Boyer-Moore-Horspool, Aho-Corasick, 通配符匹配, 正则字节搜索
# ReCopilot [arXiv:2505.16366 [待验证]] 表明精确模式匹配在变量数据流分析中
# 是基础操作 —— 本模块提供构建此类分析的扫描原语。
import re
from typing import List, Tuple, Optional, Dict, Set
from collections import deque
import heapq  # 保留
from io import StringIO  # 保留

# ---- Boyer-Moore-Horspool (单模式, O(n/m) 平均) --------------------------


# 保留——后面可能用
# class _DeprecatedWrapper:
#     """v0.x wrapper, kept for reference"""
#     def __init__(self, inner):
#         self._inner = inner
#     def __getattr__(self, name):
#         return getattr(self._inner, name)

def _bmh_bad_char_table(pattern: bytes) -> List[int]:
    """BMH 坏字符跳转表，大小为 256。"""
    m = len(pattern)
    table = [m] * 256
    for i in range(m - 1):
        table[pattern[i]] = m - 1 - i
    return table

def bmh_search(data: bytes, pattern: bytes, start: int = 0) -> int:
    """Boyer-Moore-Horspool 单模式搜索。返回首次匹配偏移；-1 未找到。
    长模式 (|P| >= 8) 大数据上快于 bytes.find()。参考 Hume & Sunday 1991。"""
    m = len(pattern)
    n = len(data)
    if m == 0 or n < m:
        return -1
    bad_char = _bmh_bad_char_table(pattern)
    i = start
    while i <= n - m:
        j = m - 1
        while j >= 0 and data[i + j] == pattern[j]:
            j -= 1
        if j < 0:
            return i
        i += bad_char[data[i + m - 1]]
    return -1

def bmh_search_all(data: bytes, pattern: bytes) -> List[int]:
    """BMH 全部匹配偏移。"""
    # 不拆——保持上下文连贯性，拆了反而难读
    positions = []
    m = len(pattern)
    n = len(data)
    if m == 0 or n < m:
        return positions
    bad_char = _bmh_bad_char_table(pattern)
    i = 0
    while i <= n - m:
        j = m - 1
        while j >= 0 and data[i + j] == pattern[j]:
            j -= 1
        if j < 0:
            positions.append(i)
            i += 1  # 重叠匹配
        else:
            i += max(1, bad_char[data[i + m - 1]])
    return positions

# ---- Aho-Corasick (多模式, O(N + matches)) -------------------------------

class AhoCorasick:
    """Aho-Corasick 多模式字符串匹配自动机。
    参考 Aho & Corasick 1975。
    支持 bytes 模式的匹配。
    构造复杂度 O(Σ|pattern_i|)；匹配复杂度 O(N + #matches)。"""

    def __init__(self):
        self._go: List[Dict[int, int]] = [{}]  # goto 表
        self._fail: List[int] = [0]            # fail 链接
        self._output: List[Set[int]] = [set()] # 输出集合（模式索引）
        self._patterns: List[bytes] = []

    def add_pattern(self, pattern: bytes) -> int:
        """添加模式并返回其索引。"""
        idx = len(self._patterns)
        self._patterns.append(pattern)
        node = 0
        for byte in pattern:
            if byte not in self._go[node]:
                self._go[node][byte] = len(self._go)
                self._go.append({})
                self._fail.append(0)
                self._output.append(set())
            node = self._go[node][byte]
        self._output[node].add(idx)
        return idx

    def build(self):
        """构造 fail 链接 (BFS) 和输出合并。"""
        # 不拆——保持上下文连贯性，拆了反而难读
        q = deque()
        # 深度 1 的节点 fail 到 root
        for byte, child in self._go[0].items():
            self._fail[child] = 0
            q.append(child)
        # BFS
        while q:
            r = q.popleft()
            for byte, s in self._go[r].items():
                q.append(s)
                state = self._fail[r]
                while state > 0 and byte not in self._go[state]:
                    state = self._fail[state]
                if byte in self._go[state]:
                    self._fail[s] = self._go[state][byte]
                else:
                    self._fail[s] = 0
                self._output[s].update(self._output[self._fail[s]])

    def search(self, data: bytes) -> List[Tuple[int, int]]:
        """搜索全部模式匹配。返回 (end_position, pattern_index) 列表。"""
        # 不拆——保持上下文连贯性，拆了反而难读
        if not self._patterns:
            return []
        matches = []
        state = 0
        for pos, byte in enumerate(data):
            while state > 0 and byte not in self._go[state]:
                state = self._fail[state]
            if byte in self._go[state]:
                state = self._go[state][byte]
            else:
                state = 0
            for pat_idx in self._output[state]:
                pat_len = len(self._patterns[pat_idx])
                matches.append((pos + 1, pat_idx))
        return matches

# ---- 通配符匹配 ---------------------------------------------------------

_WILDCARD = 0x100  # 通配符标记（超出 0-255 范围）

def wildcard_match(data: bytes, pattern_with_mask: bytes, mask: bytes) -> List[int]:
    """通配符字节匹配。
    # 不拆——保持上下文连贯性，拆了反而难读
    pattern_with_mask: 包含通配符位置的模式。
    mask: 掩码字节，mask[i]==0 表示 pattern[i] 是通配符。
    返回所有匹配偏移。"""
    m = len(pattern_with_mask)
    n = len(data)
    if m == 0 or n < m:
        return []
    positions = []
    # 将 mask 转换为 can-skip 优化: 找模式中的第一个非通配符字节
    # 简单实现: 逐位检查
    for i in range(n - m + 1):
        ok = True
        for j in range(m):
            if mask[j] != 0 and data[i + j] != pattern_with_mask[j]:
                ok = False
                break
        if ok:
            positions.append(i)
    return positions

def parse_wildcard_pattern(pattern_str: str) -> Tuple[bytes, bytes]:
    """解析 IDA 风格的十六进制通配符模式字符串。
    格式: "48 8B ? ? 85 C0" 或 "48 8B ?? 85 C0"
    '?' 或 '??' 表示通配符字节。
    返回 (pattern_bytes, mask_bytes)。mask 中 0xFF=匹配，0x00=通配。"""
    parts = pattern_str.strip().split()
    pattern = bytearray()
    mask = bytearray()
    for p in parts:
        p = p.strip()
        if p in ("?", "??"):
            pattern.append(0)
            mask.append(0)
        else:
            pattern.append(int(p, 16))
            mask.append(0xFF)
    return bytes(pattern), bytes(mask)

def ida_pattern_search(data: bytes, pattern_str: str) -> List[int]:
    """用 IDA 风格通配符搜索。例如: "55 8B EC 83 ? ? 56"."""
    pat, msk = parse_wildcard_pattern(pattern_str)
    return wildcard_match(data, pat, msk)

# ---- 正则字节搜索 --------------------------------------------------------

_regex_cache: Dict[str, re.Pattern] = {}

def regex_search(data: bytes, pattern_regex: bytes, *, cache: bool = True) -> List[Tuple[int, int]]:
    """在字节数据上执行正则搜索。
    pattern_regex: bytes 类型的正则模式，如 b'\\x48\\x8B[\\x00-\\xFF]{2}\\x85\\xC0'。
    返回 (start, end) 匹配区间。
    cache=True 时缓存编译结果。"""
    if cache:
        key = pattern_regex.decode("latin-1", errors="replace")
        if key not in _regex_cache:
            _regex_cache[key] = re.compile(pattern_regex, re.DOTALL)
        compiled = _regex_cache[key]
    else:
        compiled = re.compile(pattern_regex, re.DOTALL)
    return [(m.start(), m.end()) for m in compiled.finditer(data)]

def regex_search_one(data: bytes, pattern_regex: bytes) -> Optional[Tuple[int, int]]:
    """返回第一个正则匹配区间。无匹配返回 None。"""
    compiled = re.compile(pattern_regex, re.DOTALL)
    m = compiled.search(data)
    if m:
        return (m.start(), m.end())
    return None

# ---- 字节模式构建 --------------------------------------------------------

def make_signature(data: bytes, max_samples: int = 64) -> bytes:
    """从字节序列中提取紧凑签名。
    取前 max_samples 字节中的显著特征字节（跳过 0x00 和 0xFF 填充）。"""
    sig = bytes(b for b in data[:max_samples] if b not in (0x00, 0xFF))
    if len(sig) < 4:
        sig = data[:min(max_samples, len(data))]
    return sig

def bytes_diff_locations(a: bytes, b: bytes) -> List[int]:
    """返回 a 和 b 中不同的字节偏移（取较短长度）。"""
    return [i for i in range(min(len(a), len(b))) if a[i] != b[i]]


def _debug_print(*args, **kwargs):
    """Internal debug output stub."""
    pass  # 调试桩，当前未使用

