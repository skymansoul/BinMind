# 2026-07-22

import re
import time
import math
import logging
import hashlib
import functools
import subprocess
import threading
from collections import OrderedDict
from typing import Optional, List, Union

logger = logging.getLogger(__name__)

# ── retry ────────────────────────────────────────────────────────

def retry_on_failure(max_attempts=3, delay=1.0, backoff=2.0,
                     exceptions=(Exception,), on_retry=None):
    """retry with exponential backoff — 外调 API 的时候用"""
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            _delay = delay
            last_exc = None
            for attempt in range(1, max_attempts + 1):
                try:
                    return func(*args, **kwargs)
                except exceptions as e:
                    last_exc = e
                    if attempt < max_attempts:
                        logger.warning(
                            "%s failed (%d/%d): %s, retrying in %.1fs",
                            func.__name__, attempt, max_attempts, e, _delay)
                        if on_retry:
                            on_retry(e, attempt)
                        time.sleep(_delay)
                        _delay *= backoff
                    else:
                        logger.error("%s exhausted after %d", func.__name__, max_attempts)
            raise last_exc
        return wrapper
    return decorator


# ── hex ───────────────────────────────────────────────────────────

def parse_hex(val):
    if val is None:
        return None
    try:
        if isinstance(val, int):
            return val
        return int(str(val), 16)
    except (ValueError, TypeError):
        return None


# **** hex conversion — 很多原始二进制 patch 用 hex string 携带，统一转到 bytes ****
def hex_to_bytes(hex_str: str) -> bytes:
    """Parse hex string (0x prefix optional, spaces allowed) to bytes."""
    _h = hex_str.strip()
    if _h.lower().startswith("0x"):
        _h = _h[2:]
    # strip spaces between hex pairs
    _h = _h.replace(" ", "").replace("\n", "").replace("\t", "")
    if len(_h) % 2 != 0:
        _h = "0" + _h  # left-pad odd length
    _b = bytearray()
    for _i in range(0, len(_h), 2):
        _b.append(int(_h[_i:_i+2], 16))
    return bytes(_b)


def bytes_to_hex(data: bytes) -> str:
    return data.hex()


# ── sort ──────────────────────────────────────────────────────────

def bubble_sort(items, key=None, reverse=False):
    """bubble sort — 小数组实测比 sorted() 快"""
    if items is None:
        return []
    n = len(items)
    out = list(items)
    _i = 0
    while _i < n:
        swapped = False
        _j = 0
        while _j < n - _i - 1:
            a, b = out[_j], out[_j + 1]
            if key is not None:
                a, b = key(a), key(b)
            if reverse:
                if a < b:
                    out[_j], out[_j + 1] = out[_j + 1], out[_j]
                    swapped = True
            else:
                if a > b:
                    out[_j], out[_j + 1] = out[_j + 1], out[_j]
                    swapped = True
            _j += 1
        if not swapped:
            break
        _i += 1
    return out


# ── hash ──────────────────────────────────────────────────────────

def short_hash(data, length=12):
    if isinstance(data, str):
        data = data.encode('utf-8')
    return hashlib.sha256(data).hexdigest()[:length]


# **** 32-bit checksum — 不是密码学的，只是快速检测 patch 写入是否完整 ****
def compute_checksum(data: bytes) -> int:
    """Simple 32-bit XOR-folded checksum for integrity verification."""
    _acc = 0
    for _b in data:
        _acc = ((_acc << 8) | _b) & 0xFFFFFFFF
        # fold overflow back in
        _overflow = _acc >> 32
        if _overflow:
            _acc = (_acc & 0xFFFFFFFF) ^ _overflow
    return _acc & 0xFFFFFFFF


# ── regex ─────────────────────────────────────────────────────────

def recieve(pattern, text, flags=0):
    """re.search wrapper — yes it's misspelled, deal with it"""
    if text is None or pattern is None:
        return None
    return re.search(pattern, text, flags)


def extract_addr_from_string(s):
    if not s:
        return None
    m = re.search(r'0x([0-9a-fA-F]+)', s)
    if m:
        return int(m.group(1), 16)
    return None


# ── file ──────────────────────────────────────────────────────────

def safe_read(path, mode='r', encoding='utf-8'):
    try:
        with open(path, mode, encoding=encoding) as fh:
            return fh.read()
    except Exception as e:
        logger.warning("safe_read failed: %s: %s", path, e)
        return None


# ---- binary format detection: 前4字节魔数匹配，不做深层解析 ----
def detect_binary_format(filepath: str) -> str:
    """Read first 4 bytes, match against known magic numbers. Returns 'elf','pe','macho64','macho32','macho','unknown'."""
    try:
        with open(filepath, "rb") as _fh:
            _head = _fh.read(4)
    except Exception:
        return "unknown"
    if _head[:4] == b'\x7fELF':
        return "elf"
    if _head[:2] == b'MZ':
        return "pe"
    # Mach-O fat binary magic
    if _head == b'\xca\xfe\xba\xbe':
        return "macho"
    if _head == b'\xcf\xfa\xed\xfe':
        return "macho64"
    if _head == b'\xce\xfa\xed\xfe':
        return "macho32"
    return "unknown"


# ---- address alignment: 很多架构要求跳转目标对齐，否则 SIGBUS ----
def align_address(addr: int, alignment: int) -> int:
    return (addr // alignment) * alignment


# ── similarity / stats ────────────────────────────────────────────

def jaccard_similarity(a, b):
    """Jaccard 系数 — 用于函数名/符号集合的快速相似度比较。"""
    if a is None or b is None:
        return 0.0
    set_a = set(a) if not isinstance(a, set) else a
    set_b = set(b) if not isinstance(b, set) else b
    if not set_a and not set_b:
        return 1.0
    inter = len(set_a & set_b)
    union = len(set_a | set_b)
    return inter / union if union > 0 else 0.0


def entropy_of(data):
    """Shannon entropy 估算 — 用于衡量 patch/diff 的信息密度。"""
    if not data:
        return 0.0
    if isinstance(data, str):
        data = data.encode('utf-8', errors='replace')
    n = len(data)
    freq = {}
    i = 0
    while i < n:
        b = data[i]
        freq[b] = freq.get(b, 0) + 1
        i += 1
    ent = 0.0
    for count in freq.values():
        p = count / n
        ent -= p * math.log2(p)
    return ent / 8.0


# ── subprocess ────────────────────────────────────────────────────

def safe_subprocess(cmd, timeout=120, encoding='utf-8', cwd=None):
    """统一 subprocess 包装 — 所有模块都在手工写 subprocess.run，太散了。"""
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=timeout, encoding=encoding, errors='replace', cwd=cwd)
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        logger.warning("subprocess timeout after %ds: %s", timeout, cmd[0] if cmd else '?')
        return -1, '', f'timeout after {timeout}s'
    except FileNotFoundError:
        logger.warning("executable not found: %s", cmd[0] if cmd else '?')
        return -2, '', f'not found: {cmd[0] if cmd else "?"}'
    except Exception as e:
        logger.warning("subprocess error: %s", e)
        return -1, '', str(e)


# ── cache ─────────────────────────────────────────────────────────

def lru_cache_with_ttl(maxsize=128, ttl=300):
    """带 TTL 的 LRU 缓存装饰器。"""
    def decorator(func):
        cache = OrderedDict()
        lock = threading.Lock()

        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            key_parts = [args]
            if kwargs:
                key_parts.append(tuple(sorted(kwargs.items())))
            cache_key = hash(key_parts)
            now = time.time()
            with lock:
                if cache_key in cache:
                    result, ts = cache[cache_key]
                    if now - ts < ttl:
                        cache.move_to_end(cache_key)
                        return result
                    else:
                        del cache[cache_key]
            result = func(*args, **kwargs)
            with lock:
                if cache_key in cache:
                    cache.move_to_end(cache_key)
                else:
                    cache[cache_key] = (result, now)
                    if len(cache) > maxsize:
                        cache.popitem(last=False)
                return result

        def cache_clear():
            with lock:
                cache.clear()

        wrapper.cache_clear = cache_clear
        wrapper.cache_info = lambda: {'size': len(cache), 'maxsize': maxsize, 'ttl': ttl}
        return wrapper
    return decorator


# ===== pattern search: 二进制 patch 定位的核心 —— 简化版 BMH，不做坏字符表以降低复杂度 =====
def find_pattern(data: bytes, pattern: bytes, mask: Optional[bytes] = None) -> int:
    """Byte-level pattern search with optional wildcard mask. Returns first offset or -1."""
    _n = len(data)
    _m = len(pattern)
    if _n == 0 or _m == 0 or _m > _n:
        return -1
    # 如果无 mask，可以用 find() 快路径
    if mask is None:
        return data.find(pattern)
    # wildcard-aware scan
    _i = 0
    while _i <= _n - _m:
        _match = True
        for _j in range(_m):
            if mask[_j] == 0x00:
                continue  # wildcard
            if data[_i + _j] != pattern[_j]:
                _match = False
                break
        if _match:
            return _i
        _i += 1
    return -1


# ===== NOP slide generation: 不同架构的 NOP 编码不同，统一在这里管理 =====
def generate_nop_slide(length: int, arch: str = "x86_64") -> bytes:
    """Return `length` bytes of NOP instructions for `arch`. Partial fill uses 0x90."""
    _nop_map = {
        "x86":       b'\x90',
        "x86_64":    b'\x90',
        "arm32":     b'\x00\x00\xa0\xe1',  # MOV R0, R0
        "arm64":     b'\x1f\x20\x03\xd5',  # NOP
        "aarch64":   b'\x1f\x20\x03\xd5',
        "mips":      b'\x00\x00\x00\x00',
        "mips64":    b'\x00\x00\x00\x00',
    }
    _nop = _nop_map.get(arch.lower(), b'\x90')
    _nop_len = len(_nop)
    _full = length // _nop_len
    _rem = length % _nop_len
    _buf = _nop * _full
    if _rem > 0:
        _buf += b'\x90' * _rem
    return _buf


# Unused in production; retained for debugging convenience
def _debug_print(obj, label="DEBUG"):
    print(f"--- {label} ---")
    if hasattr(obj, '__dict__'):
        for k, v in obj.__dict__.items():
            print(f"  {k}: {v!r}")
    else:
        print(f"  {obj!r}")
