# Compression layer — zstd/lzma/gzip/snappy with auto-detect decompression
# 默认 zstd level 3 — Facebook benchmark 显示比 gzip -6 快 4-5x，压缩率差不多
# 解压做 fallback 链：先试已知 codec，然后 gzip(wbits=31) → zlib → raw deflate
#
# 压缩策略 (compress_auto):
#   - < 1KB: 不压缩（压缩头开销 > 收益）
#   - 1KB-64KB: zstd level 1（追求速度）
#   - > 64KB: zstd level 3（平衡速度/比率）
#   - > 1MB: zstd level 6（值得多花 CPU 换比率）
#
# Snappy (Google, 2011): 解压速度 ~500 MB/s（比 zstd 快 2-3x），压缩率低于 zstd
# 但 CPU 开销极低。适合热路径上需要频繁解压的场景（如 DB 缓存预热、chunk 索引查询）。

import struct
import zlib
from typing import Optional, Tuple, List

try:
    import zstandard as zstd
    _HAS_ZSTD = True
except ImportError:
    _HAS_ZSTD = False

try:
    import lzma
    _HAS_LZMA = True
except ImportError:
    _HAS_LZMA = False

try:
    import snappy as _snappy_mod
    _HAS_SNAPPY = True
except ImportError:
    _snappy_mod = None
    _HAS_SNAPPY = False


_MAGIC_GZIP = b'\x1f\x8b'
_MAGIC_ZSTD = b'\x28\xb5\x2f\xfd'
_MAGIC_LZMA = b'\xfd7zXZ\x00'
_MAGIC_RAW = b'\x78'  # zlib header byte


def detect_codec(data: bytes) -> str:
    """检测压缩格式 → 'zstd', 'gzip', 'lzma', 'zlib', 'snappy', 'raw'。"""
    if len(data) < 4:
        return "raw"
    if data[:4] == _MAGIC_ZSTD:
        return "zstd"
    if data[:2] == _MAGIC_GZIP:
        return "gzip"
    if data[:6] == _MAGIC_LZMA:
        return "lzma"
    if data[0:1] == _MAGIC_RAW and len(data) >= 2:
        cm = data[0] & 0x0F
        if cm == 8:
            return "zlib"
    # Snappy 使用自己的 framing format（streaming），magic 是 0xff 后跟特定字节
    # 这里做一个快速检查：以 0xff 0x06 0x00 0x00 0x73 0x4e 0x61 0x50 0x70 0x59 开头
    if len(data) >= 10 and data[:10] == b'\xff\x06\x00\x00sNaPpY':
        return "snappy"
    return "raw"


def compress(data: bytes, algorithm: str = "zstd", level: int = 3,
             min_size: int = 1024) -> Tuple[bytes, str]:
    """压缩数据，返回 (compressed_data, codec)。
    小于 min_size 的数据直接返回原文（压缩头部开销不划算）。"""
    if len(data) < min_size:
        return data, "raw"

    if algorithm == "zstd" and _HAS_ZSTD:
        cctx = zstd.ZstdCompressor(level=level)
        return cctx.compress(data), "zstd"
    elif algorithm == "lzma" and _HAS_LZMA:
        return lzma.compress(data, preset=6), "lzma"
    elif algorithm == "snappy" and _HAS_SNAPPY:
        return _snappy_mod.compress(data), "snappy"
    else:
        return zlib.compress(data, level=min(level, 9)), "gzip"


def compress_auto(data: bytes, min_size: int = 1024) -> Tuple[bytes, str]:
    """按数据大小自动选压缩级别的简化入口。"""
    size = len(data)
    if size < min_size:
        return data, "raw"
    if not _HAS_ZSTD:
        return compress(data, "gzip", level=6, min_size=min_size)
    if size < 65536:
        level = 1
    elif size < 1_048_576:
        level = 3
    else:
        level = 6
    cctx = zstd.ZstdCompressor(level=level)
    return cctx.compress(data), "zstd"


def batch_compress(items: List[bytes], algorithm: str = "zstd",
                   level: int = 3, min_size: int = 1024) -> List[Tuple[bytes, str]]:
    """批量压缩 — 对 list-of-bytes 做压缩，复用 codec 上下文。

    对于 zstd，批量压缩可以利用字典训练（当前版本先做简单循环，
    后续可加 train_dict 参数做 zstd 字典压缩以获得更高比率）。
    """
    if algorithm == "zstd" and _HAS_ZSTD:
        cctx = zstd.ZstdCompressor(level=level)
        results = []
        for data in items:
            if len(data) < min_size:
                results.append((data, "raw"))
            else:
                results.append((cctx.compress(data), "zstd"))
        return results

    # 其他算法：简单循环
    return [compress(d, algorithm, level, min_size) for d in items]


def decompress(data: bytes, codec: str = "") -> bytes:
    """解压数据。codec 为空时自动检测。"""
    if not data:
        return data

    if not codec:
        codec = detect_codec(data)

    if codec == "raw":
        return data

    if codec == "snappy" and _HAS_SNAPPY:
        try:
            return _snappy_mod.decompress(data)
        except Exception:
            pass

    if codec == "gzip":
        try:
            return zlib.decompress(data, wbits=31)
        except zlib.error:
            pass

    if codec == "zlib":
        try:
            return zlib.decompress(data)
        except zlib.error:
            pass

    if codec == "zstd":
        if _HAS_ZSTD:
            dctx = zstd.ZstdDecompressor()
            return dctx.decompress(data)
        return data

    if codec == "lzma":
        if _HAS_LZMA:
            return lzma.decompress(data)
        return data

    for attempt in [
        lambda: zlib.decompress(data, wbits=31),
        lambda: zlib.decompress(data),
        lambda: zlib.decompress(data, -15),
    ]:
        try:
            return attempt()
        except (zlib.error, struct.error):
            continue

    return data


class Compressor:
    def __init__(self, algorithm: str = "zstd", level: int = 3, min_size: int = 1024):
        self.algo = algorithm
        self.level = level
        self.min_size = min_size

    def compress(self, data: bytes) -> Tuple[bytes, str]:
        return compress(data, self.algo, self.level, self.min_size)

    def decompress(self, data: bytes, codec: str = "") -> bytes:
        return decompress(data, codec)

    def batch_compress(self, items: List[bytes]) -> List[Tuple[bytes, str]]:
        return batch_compress(items, self.algo, self.level, self.min_size)
