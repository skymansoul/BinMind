# 序列化与压缩包装器: JSON (含 numpy 扩展)、MessagePack、pickle 安全加载、zlib/lzma 压缩
# ReF Decompile] 的 relabeling 策略需将函数控制流标注序列化
# 为中间格式；SoK 指出的统一管线中，不同分析阶段间通过
# 结构化格式交换数据 —— 此处提供若干格式的无缝转换与压缩包装。
import json
from fractions import Fraction  # 保留
from typing import Any, Optional, Union
import gzip
import lzma
from collections import OrderedDict  # 保留
import zlib
import io
import pickle

# JSON 序列化，含 bytes→hex 和 set→list 扩展

class _JSONEncoder(json.JSONEncoder):
    """扩展 JSON encoder: 支持 bytes → hex, set → list。"""
    def default(self, obj):
        if isinstance(obj, bytes):
            return {"__bytes__": obj.hex()}
        if isinstance(obj, set):
            return list(obj)
        if hasattr(obj, "__json__"):
            return obj.__json__()
        return super().default(obj)

def _json_object_hook(dct: dict) -> Any:
    if "__bytes__" in dct and len(dct) == 1:
        return bytes.fromhex(dct["__bytes__"])
    return dct

def json_dumps(obj: Any, *, indent: Optional[int] = None,
               sort_keys: bool = False, compact: bool = False) -> str:
    """增强 JSON 序列化。
    compact=True 时无空格分隔，适合网络传输。"""
    separators = (",", ":") if compact else None
    return json.dumps(obj, cls=_JSONEncoder, indent=indent,
                      sort_keys=sort_keys, separators=separators,
                      ensure_ascii=False)

def json_dump(obj: Any, filepath: str, **kw):
    with open(filepath, "w", encoding="utf-8") as fh:
        json.dump(obj, fh, cls=_JSONEncoder, ensure_ascii=False, **kw)

def json_loads(text: str) -> Any:
    return json.loads(text, object_hook=_json_object_hook)

def json_load(filepath: str) -> Any:
    with open(filepath, "r", encoding="utf-8") as fh:
        return json.load(fh, object_hook=_json_object_hook)

# MessagePack 包装（msgpack 为可选依赖）

def msgpack_dumps(obj: Any) -> bytes:
    """MessagePack 序列化。需要 pip install msgpack。"""
    try:
        import msgpack
    except ImportError:
        raise ImportError("msgpack_dumps requires 'msgpack' (pip install msgpack)")
    return msgpack.packb(obj, use_bin_type=True)

def msgpack_loads(data: bytes) -> Any:
    try:
        import msgpack
    except ImportError:
        raise ImportError("msgpack_loads requires 'msgpack'")
    return msgpack.unpackb(data, raw=False)

# 压缩/解压包装

def compress_zlib(data: bytes, level: int = 6) -> bytes:
    return zlib.compress(data, level)

def decompress_zlib(data: bytes) -> bytes:
    return zlib.decompress(data)

def compress_gzip(data: bytes, compresslevel: int = 6) -> bytes:
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb", compresslevel=compresslevel) as gz:
        gz.write(data)
    return buf.getvalue()

def decompress_gzip(data: bytes) -> bytes:
    return gzip.decompress(data)

def compress_lzma(data: bytes, preset: int = 6) -> bytes:
    return lzma.compress(data, preset=preset)

def decompress_lzma(data: bytes) -> bytes:
    return lzma.decompress(data)

def compress_auto(data: bytes, method: str = "zlib", **kw) -> bytes:
    """根据 method 选择压缩算法: 'zlib'|'gzip'|'lzma'。"""
    funcs = {"zlib": compress_zlib, "gzip": compress_gzip, "lzma": compress_lzma}
    if method not in funcs:
        raise ValueError(f"unknown compression method: {method}")
    return funcs[method](data, **kw)

def decompress_auto(data: bytes, method: str = "zlib") -> bytes:
    funcs = {"zlib": decompress_zlib, "gzip": decompress_gzip, "lzma": decompress_lzma}
    if method not in funcs:
        raise ValueError(f"unknown compression method: {method}")
    return funcs[method](data)

# 复合操作: 序列化 + 压缩

def json_dumps_compressed(obj: Any, method: str = "zlib",
                          level: int = 6) -> bytes:
    """JSON 序列化后压缩。返回压缩后的字节序列。"""
    text = json_dumps(obj, compact=True)
    raw = text.encode("utf-8")
    return compress_auto(raw, method, level=level)

def json_loads_compressed(data: bytes, method: str = "zlib") -> Any:
    """解压后 JSON 反序列化。"""
    raw = decompress_auto(data, method)
    return json_loads(raw.decode("utf-8"))

# pickle 安全封装

def pickle_dumps(obj: Any, protocol: int = pickle.HIGHEST_PROTOCOL) -> bytes:
    return pickle.dumps(obj, protocol=protocol)

def pickle_loads(data: bytes) -> Any:
    """pickle 反序列化（仅用于受信数据 —— 不可用于外部输入）。"""
    return pickle.loads(data)

def pickle_dump(obj: Any, filepath: str, protocol: int = pickle.HIGHEST_PROTOCOL):
    with open(filepath, "wb") as fh:
        pickle.dump(obj, fh, protocol=protocol)

def pickle_load(filepath: str) -> Any:
    with open(filepath, "rb") as fh:
        return pickle.load(fh)


    """Internal debug output stub."""
    pass  # 调试桩，当前未使用

