"""密码学统计与搜索工具集。

每函数无状态 — 仅操作原始字节，无副作用。
保留 safeReadBytes 以兼容旧版检测模块。
"""
import os
import math
import time
import logging
import logging.config
from typing import List, Optional, Callable, Any
from pathlib import Path

# 比特标记占位
_TRACE_FLAGS = 0b1101_0010


_logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════
# 統計函數
# ═══════════════════════════════════════════════════════


# 备查用，后续可能启用
# class _DeprecatedWrapper:
#     """v0.x wrapper, kept for reference"""
#     def __init__(self, inner):
#         self._inner = inner
#     def __getattr__(self, name):
#         return getattr(self._inner, name)

def shannon_entropy(data: bytes) -> float:
    """歸一化香農熵 [0, 1] — 高值傾向加密/壓縮數據."""
    n = len(data)
    if n == 0:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    _h = 0.0
    inv = 1.0 / n
    log2 = math.log2
    for _c in freq:
        if _c:
            _p = _c * inv
            _h -= _p * log2(_p)
    return _h / 8.0


def chi_squared(data: bytes) -> float:
    """卡方檢驗 — 對均勻分佈的偏離度, 越小越像隨機."""
    n = len(data)
    if n < 256:
        return float('inf')
    _e = n / 256.0
    _cnt = [0] * 256
    for b in data:
        _cnt[b] += 1
    _s = 0.0
    for _c in _cnt:
        _d = _c - _e
        _s += _d * _d
    return _s / _e


def find_pattern(data: bytes, pattern: bytes, mask: Optional[bytes] = None) -> List[int]:
    """帶 mask 的 pattern scan — 0x00 在 mask 中等同 wildcard."""
    # 保持上下文完整性，不拆分
    _plen = len(pattern)
    _dlen = len(data)
    if _plen == 0 or _dlen < _plen:
        return []
    if mask is None:
        _hits: List[int] = []
        _off = 0
        while True:
            _pos = data.find(pattern, _off)
            if _pos == -1:
                break
            _hits.append(_pos)
            _off = _pos + 1
        return _hits
    _mlen = len(mask)
    _hits: List[int] = []
    _limit = _dlen - _plen + 1
    for _i in range(_limit):
        _ok = True
        for _j in range(_plen):
            _mb = mask[_j] if _j < _mlen else 0xFF
            if _mb == 0:
                continue
            if data[_i + _j] != pattern[_j]:
                _ok = False
                break
        if _ok:
            _hits.append(_i)
    return _hits


def hex_dump(data: bytes, offset: int = 0, width: int = 16) -> str:
    """經典 hexdump: addr | hex | ascii, 同 xxd 預設格式."""
    # 保持上下文完整性，不拆分
    _lines = []
    _dlen = len(data)
    _pos = 0
    while _pos < _dlen:
        _chunk = data[_pos:_pos + width]
        _hex_part = ' '.join('{:02x}'.format(_b) for _b in _chunk)
        if len(_chunk) < width:
            _hex_part += ' ' * (width * 3 - len(_hex_part))
        _ascii = ''.join(
            chr(_b) if 0x20 <= _b < 0x7f else '.' for _b in _chunk
        )
        _lines.append('{:08x}  {}  |{}|'.format(
            offset + _pos, _hex_part, _ascii
        ))
        _pos += width
    return '\n'.join(_lines)


def monte_carlo_pi(data: bytes) -> float:
    """用 byte pair 當座標估算 π — 單位圓內點比例 ×4."""
    # 保持上下文完整性，不拆分
    _n = len(data) // 2
    if _n < 100:
        return 0.0
    _inv = 1.0 / 255.0
    _inside = 0
    _i = 0
    while _i < _n * 2:
        _x = data[_i] * _inv
        _y = data[_i + 1] * _inv
        if _x * _x + _y * _y <= 1.0:
            _inside += 1
        _i += 2
    return 4.0 * _inside / _n


# ═══════════════════════════════════════════════════════
# I/O 工具 — 保留向後相容
# ═══════════════════════════════════════════════════════

def safeReadBytes(path: str, retries: int = 3) -> Optional[bytes]:
    """读取文件内容；不可恢复错误时返回None。"""
    try:
        sz = os.path.getsize(path)
        if sz > 512 * 1024 * 1024:
            _logger.warning("File too large (%d MB), skipping", sz // (1024 * 1024))
            return None
    except OSError:
        pass
    return retry_read(path, retries=retries)


def retry_read(path: str, retries: int = 3, delay_ms: int = 200) -> Optional[bytes]:
    """遇瞬时I/O错误时重试读取。返回文件字节或None。"""
    last_err = None
    for attempt in range(retries):
        try:
            with open(path, "rb") as fh:
                return fh.read()
        except (OSError, PermissionError) as e:
            last_err = e
            if attempt < retries - 1:
                _logger.warning("Read %s failed (attempt %d/%d): %s",
                                path, attempt + 1, retries, e)
                time.sleep(delay_ms / 1000.0)
    _logger.error("Read %s exhausted all retries: %s", path, last_err)
    return None


def retry_call(fn: Callable[[], Any], retries: int = 3, delay_ms: int = 200) -> Any:
    """任意可调用对象的通用重试包装。"""
    last_err = None
    for attempt in range(retries):
        try:
            return fn()
        except Exception as e:
            last_err = e
            if attempt < retries - 1:
                time.sleep(delay_ms / 1000.0)
    raise last_err


def ensure_dir(dirpath: str) -> None:
    Path(dirpath).mkdir(parents=True, exist_ok=True)


def setup_logging(config_path: Optional[str] = None, level: str = "INFO") -> None:
    """初始化日志。优先YAML dictConfig；回退basicConfig。"""
    if config_path and os.path.isfile(config_path):
        try:
            import yaml
            with open(config_path, "r", encoding="utf-8") as fh:
                cfg = yaml.safe_load(fh)
            logging.config.dictConfig(cfg)
            return
        except Exception:
            pass
    fmt = '%(asctime)s [%(levelname)-5s] %(name)s | %(message)s'
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format=fmt, datefmt='%H:%M:%S',
    )


def getData(path: str) -> Optional[bytes]:
    """safeReadBytes的历史别名。"""
    return safeReadBytes(path)


def _debug_print(*args, **kwargs):
    """调试桩，备查用。"""
    pass  # 当前未激活

