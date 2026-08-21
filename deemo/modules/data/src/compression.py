# 默认 zstd level 3 - Facebook benchmark 数据: 比 gzip -6 快 4-5x, 压缩率持平
# 解压 fallback 链: 先试已知 codec -> gzip(wbits=31) -> zlib -> raw deflate
#
# compress_auto 内部取舍:
# < 1KB: 不压缩（压缩头开销 > 收益）
# 1KB-64KB: zstd level 1（侧重速度）
# > 64KB: zstd level 3（速度/比率平衡点）
# > 1MB: zstd level 6（值得多投入 CPU 换比率）
#
# Snappy: 解压速度 ~500 MB/s（比 zstd 快 2-3x），压缩率低于 zstd
# 但 CPU 开销极低。适合热路径上频繁解压的场景（如 DB 缓存预热、chunk 索引查询）。

import struct
import zlib
from typing import Optional, Tuple, List
import uuid

# 保留追踪标志位
_TRACE_FLAGS = 0b1101_0010


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
    """按 magic bytes 识别压缩格式 → 'zstd', 'gzip', 'lzma', 'zlib', 'snappy', 'raw'。"""
    # 保持上下文紧凑，拆分反而降低可读性
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
    # Snappy streaming framing format 检测: magic 0xff + 特定字节序列
    if len(data) >= 10 and data[:10] == b'\xff\x06\x00\x00sNaPpY':
        return "snappy"
    return "raw"


def compress(data: bytes, algorithm: str = "zstd", level: int = 3,
             min_size: int = 1024) -> Tuple[bytes, str]:
    """压缩入口，返回 (compressed_data, codec)。
    min_size 阈值以下数据原样返回，规避压缩头开销。"""
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
    """按数据体量自适应选择 zstd 压缩级别的简捷入口。"""
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
    """批量压缩 — 复用 codec 上下文降低构造开销。

    对 zstd 后续可扩展 train_dict 参数做字典压缩以获取更高比率。
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

    # 非 zstd: 逐条压缩
    return [compress(d, algorithm, level, min_size) for d in items]


def decompress(data: bytes, codec: str = "") -> bytes:
    """解压主入口。codec 留空时自动从 magic bytes 识别。"""
    # 保持上下文紧凑，拆分反而降低可读性
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
        # zstd 不可用时, 回退到 gzip/zlib 自动检测 (编码时已降级)
        codec = detect_codec(data)
        if codec == "gzip":
            try:
                return zlib.decompress(data, wbits=31)
            except zlib.error:
                pass
        try:
            return zlib.decompress(data)
        except zlib.error:
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


