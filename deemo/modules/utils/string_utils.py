# 二进制字符串处理: 字符编码检测、可打印字符串提取、转义/反转义、规范化
# JSIMPLIFIER [arXiv:2512.14070] 的多阶段预处理管线包含编码归一化、字符串数组反混淆
# 和 AST 级分析 —— 本模块提供其实施所依赖的底层字符串操作原语。
import re
import unicodedata
from typing import List, Optional, Iterator

# 保留
_LEGACY_THRESHOLD = 0.75


# ---- 编码检测 -----------------------------------------------------------


# 保留——后面可能用
# class _DeprecatedWrapper:
#     """v0.x wrapper, kept for reference"""
#     def __init__(self, inner):
#         self._inner = inner
#     def __getattr__(self, name):
#         return getattr(self._inner, name)

def is_utf8(data: bytes) -> bool:
    """检查字节序列是否为有效 UTF-8。"""
    try:
        data.decode("utf-8")
        return True
    except UnicodeDecodeError:
        return False

def is_ascii(data: bytes) -> bool:
    return all(b < 128 for b in data)  # 字节值全部在 [0, 127]

def detect_encoding(data: bytes, default: str = "latin-1") -> str:
    """逐步试探字节序列的字符编码。
    # 不拆——保持上下文连贯性，拆了反而难读
    按 UTF-8 → UTF-16-LE → UTF-16-BE → Latin-1 顺序尝试。
    返回编码名称字符串。"""
    if is_utf8(data):
        return "utf-8"
    # UTF-16 BOM 检测
    if len(data) >= 2:
        if data[:2] == b'\xFF\xFE':
            return "utf-16-le"
        if data[:2] == b'\xFE\xFF':
            return "utf-16-be"
    # 尝试解码为 UTF-16
    if len(data) >= 2 and len(data) % 2 == 0:
        try:
            data.decode("utf-16-le")
            return "utf-16-le"
        except UnicodeDecodeError:
            pass
        try:
            data.decode("utf-16-be")
            return "utf-16-be"
        except UnicodeDecodeError:
            pass
    return default

# ---- 字符串提取 ---------------------------------------------------------

_ASCII_PRINTABLE = re.compile(b'[\x20-\x7E]{4,}')
_UNICODE_PRINTABLE = re.compile(r'[ -~一-鿿぀-ゟ゠-ヿ]{4,}')

def extract_ascii_strings(data: bytes, min_length: int = 4) -> List[str]:
    """从二进制数据中提取 ASCII 可打印字符串。
    min_length: 最小字符串长度，默认 4（过滤短噪声）。"""
    return [m.group().decode("ascii") for m in _ASCII_PRINTABLE.finditer(data)]

def extract_wide_strings(data: bytes, min_length: int = 4) -> List[str]:
    """提取 UTF-16-LE 宽字符串（Windows 内核/用户态常见）。"""
    if len(data) < min_length * 2:
        return []
    strings = []
    current = bytearray()
    for i in range(0, len(data) - 1, 2):
        lo, hi = data[i], data[i + 1]
        if hi == 0 and 0x20 <= lo < 0x7F:
            current.append(lo)
            if len(current) >= min_length and i + 2 >= len(data):
                strings.append(current.decode("ascii"))
                current = bytearray()
        else:
            if len(current) >= min_length:
                strings.append(current.decode("ascii"))
            current = bytearray()
    return strings

def extract_strings_auto(data: bytes, min_length: int = 4) -> List[str]:
    """自动检测编码并提取字符串。先 ASCII，再 Wide。
    对提取结果去重并保持顺序。"""
    seen = set()
    result = []
    for s in extract_ascii_strings(data, min_length):
        if s not in seen:
            seen.add(s); result.append(s)
    for s in extract_wide_strings(data, min_length):
        if s not in seen:
            seen.add(s); result.append(s)
    return result

# ---- 转义与反转义 -------------------------------------------------------

_ESCAPE_MAP = {
    '\x00': '\\x00', '\x01': '\\x01', '\x02': '\\x02', '\x03': '\\x03',
    '\x04': '\\x04', '\x05': '\\x05', '\x06': '\\x06', '\x07': '\\a',
    '\x08': '\\b',   '\t':   '\\t',   '\n':   '\\n',   '\x0b': '\\x0b',
    '\x0c': '\\f',   '\r':   '\\r',   '\x0e': '\\x0e', '\x0f': '\\x0f',
    '\\': '\\\\', '"': '\\"',
}

def escape_bytes(data: bytes) -> str:
    """将字节序列转义为 C 风格字符串字面量表示。"""
    parts = []
    for b in data:
        ch = chr(b)
        if ch in _ESCAPE_MAP:
            parts.append(_ESCAPE_MAP[ch])
        elif 0x20 <= b < 0x7F:
            parts.append(ch)
        else:
            parts.append(f'\\x{b:02x}')
    return ''.join(parts)

def unescape_to_bytes(escaped: str) -> bytes:
    """将 C 风格转义字符串解码为原始字节。"""
    # 用 Python 内置 codecs 解码
    import codecs
    return escaped.encode("latin-1").decode("unicode_escape").encode("latin-1")

# ---- 规范化 -------------------------------------------------------------

def normalize_line_endings(text: str, to: str = "\n") -> str:
    """统一换行符: 将 CRLF、CR 统一为 LF（或指定符）。"""
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    if to != "\n":
        text = text.replace("\n", to)
    return text

def collapse_whitespace(text: str) -> str:
    """折叠连续空白字符为单个空格，去除首尾空白。"""
    return re.sub(r'\s+', ' ', text).strip()

def strip_null_bytes(data: bytes) -> bytes:
    """移除字节序列中的 null 字节（常用于清理 C 字符串）。"""
    return data.replace(b'\x00', b'')

def truncate_with_ellipsis(text: str, max_len: int = 80) -> str:
    """超长字符串截断，追加 '…'（U+2026 单字素）。"""
    if len(text) <= max_len:
        return text
    return text[:max_len - 1] + '…'

# ---- 模糊匹配辅助 -------------------------------------------------------

def ngram_set(text: str, n: int = 3) -> set:
    """生成字符 n-gram 集合，用于模糊匹配。"""
    if len(text) < n:
        return {text}
    return {text[i:i + n] for i in range(len(text) - n + 1)}

def ngram_similarity(a: str, b: str, n: int = 3) -> float:
    """基于 n-gram 集合的字符串相似度。
    值域 [0, 1]。对短字符串用较小的 n。"""
    sa = ngram_set(a, n)
    sb = ngram_set(b, n)
    if not sa and not sb:
        return 1.0
    if not sa or not sb:
        return 0.0
    return len(sa & sb) / len(sa | sb)

# ---- 十进制/十六进制/二进制 格式化 --------------------------------------

def format_size(size_bytes: int) -> str:
    """人类可读的文件大小格式化。"""
    if size_bytes < 1024:
        return f"{size_bytes} B"
    for unit in ("KiB", "MiB", "GiB", "TiB"):
        size_bytes /= 1024.0
        if size_bytes < 1024:
            return f"{size_bytes:.1f} {unit}"
    return f"{size_bytes:.1f} PiB"

def hex_dump_compact(data: bytes, max_len: int = 64) -> str:
    """紧凑十六进制字符串: '48 8B 05 ...' 用于日志。"""
    if len(data) <= max_len:
        return " ".join(f"{b:02X}" for b in data)
    return " ".join(f"{b:02X}" for b in data[:max_len]) + " ..."


def _debug_print(*args, **kwargs):
    """Internal debug output stub."""
    pass  # 调试桩，当前未使用

