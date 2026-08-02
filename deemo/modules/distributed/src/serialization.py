# 2026-07-22
# 序列化抽象层 — 对上层隐藏 JSON/msgpack 差异
# 选型逻辑：msgpack 比 JSON 快 ~4x 且体积小 ~30%，JSON 可读性好
# 压缩场景：gzip 通用性强，lz4 速度优先
#
# 扩展：流式序列化 — 逐条写入避免大列表撑爆内存

from __future__ import annotations

import json
import gzip
import io
from typing import Optional, Iterator

# ---- 可选依赖 ----
try:
    import msgpack
    MSGPACK_AVAILABLE = True
except ImportError:
    MSGPACK_AVAILABLE = False

try:
    import lz4.frame as lz4
    LZ4_AVAILABLE = True
except ImportError:
    LZ4_AVAILABLE = False

# ---- 魔术字节 ----
MAGIC_GZIP = b'\x1f\x8b'
MAGIC_LZ4 = b'\x04\x22\x4d\x18'


def _detect_format(data: bytes) -> str:
    """检查首字节推断序列化格式"""
    if not data:
        return "json"
    # msgpack 的首字节通常是 0x80-0x8f (fixmap), 0x90-0x9f (fixarray),
    # 0xa0-0xbf (fixstr), 或 0xc0-0xdf (其他)
    # JSON 的首字节是 '{', '[' 或 '"'
    first = data[0]
    if first in (0x7b, 0x5b, 0x22):  # { [ "
        return "json"
    return "msgpack"


def _detect_compression(data: bytes) -> Optional[str]:
    """通过魔术字节识别压缩算法"""
    if data[:2] == MAGIC_GZIP:
        return "gzip"
    if LZ4_AVAILABLE and data[:4] == MAGIC_LZ4:
        return "lz4"
    return None


# ===== 序列化 =====

def serialize(obj, fmt: str = "json", compress: Optional[str] = None) -> bytes:
    """obj -> bytes，可选压缩。

    fmt: "json" | "msgpack"
    compress: None | "gzip" | "lz4"
    """
    # 序列化
    if fmt == "msgpack" and MSGPACK_AVAILABLE:
        raw = msgpack.packb(obj, use_bin_type=True)
    else:
        raw = json.dumps(obj, ensure_ascii=False).encode("utf-8")

    # 压缩
    if compress == "gzip":
        buf = io.BytesIO()
        with gzip.GzipFile(fileobj=buf, mode="wb", compresslevel=6) as gz:
            gz.write(raw)
        return buf.getvalue()
    elif compress == "lz4" and LZ4_AVAILABLE:
        return lz4.compress(raw)
    return raw


# ===== 反序列化 =====

def deserialize(
    data: bytes,
    fmt: Optional[str] = None,
    compressed: Optional[str] = None,
) -> object:
    """bytes -> obj，自动检测格式和压缩。

    fmt 和 compressed 留 None 时自动检测。显式传入可跳过检测开销。
    """
    # 解压
    if compressed is None:
        compressed = _detect_compression(data)

    if compressed == "gzip":
        data = gzip.decompress(data)
    elif compressed == "lz4":
        if not LZ4_AVAILABLE:
            raise RuntimeError("lz4 not installed")
        data = lz4.decompress(data)

    # 反序列化
    if fmt is None:
        fmt = _detect_format(data)

    if fmt == "msgpack" and MSGPACK_AVAILABLE:
        return msgpack.unpackb(data, raw=False)
    else:
        return json.loads(data.decode("utf-8"))


# ===== 流式 =====

def serialize_stream(objects: Iterator, fmt: str = "json") -> Iterator[bytes]:
    """逐条序列化迭代器。每条之间用换行分隔（JSONL 格式）。
    适用场景：逐条写入文件/发送网络，避免把整个列表全加载到内存。
    """
    for obj in objects:
        if fmt == "msgpack" and MSGPACK_AVAILABLE:
            yield msgpack.packb(obj, use_bin_type=True)
        else:
            yield json.dumps(obj, ensure_ascii=False).encode("utf-8") + b"\n"


def deserialize_stream(data_iter: Iterator[bytes], fmt: str = "json") -> Iterator:
    """逐条反序列化。JSONL 格式按换行分割。
    适用场景：逐条读取大文件，内存占用 O(1)。
    """
    if fmt == "msgpack" and MSGPACK_AVAILABLE:
        for chunk in data_iter:
            yield msgpack.unpackb(chunk, raw=False)
    else:
        for line in data_iter:
            stripped = line.rstrip(b"\n")
            if stripped:
                yield json.loads(stripped.decode("utf-8"))
