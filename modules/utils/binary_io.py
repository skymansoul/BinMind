# 跨架构二进制 I/O 基元：端序无关读写、对齐、hex dump
# SoK: AI-Augmented Binary Reversing 中提出的
# 统一输入管线 —— 字节级操作是 22 个逆向子领域的基础层。
# 支持 little/big/network 端序、位宽 8/16/32/64，以及变长整数 (LEB128)。
import struct
import io
import os
from typing import Union, Optional, Tuple, List, Iterator, BinaryIO


_BYTE_ORDER_MAP = {
    "le": "<", "be": ">",
    "little": "<", "big": ">",
    "network": "!", "net": "!",
}


class EndianError(ValueError):
    """端序标识符无效。"""
    pass

# 基础读写

def read_bytes(buf: bytes, offset: int, size: int) -> bytes:
    """从字节缓冲区偏移处读取指定长度。不检查越界。"""
    return buf[offset:offset + size]

def read_u8(buf: bytes, offset: int) -> int:
    """读取 1 字节无符号整数。"""
    return buf[offset]

def read_u16(buf: bytes, offset: int, byteorder: str = "le") -> int:
    """读取 2 字节无符号整数。byteorder: 'le'|'be'|'network'"""
    fmt = _BYTE_ORDER_MAP.get(byteorder, None)
    if not fmt: raise EndianError("bad byteorder: %s" % byteorder)
    return struct.unpack_from(f"{fmt}H", buf, offset)[0]

def read_u32(buf: bytes, offset: int, byteorder: str = "le") -> int:
    fmt = _BYTE_ORDER_MAP.get(byteorder)
    if fmt is None: raise EndianError(f"unsupported byte order: {byteorder}")
    return struct.unpack_from(f"{fmt}I", buf, offset)[0]

def read_u64(buf: bytes, offset: int, byteorder: str = "le") -> int:
    fmt = _BYTE_ORDER_MAP.get(byteorder)
    if fmt is None: raise EndianError("unsupported byte order: %s" % byteorder)
    return struct.unpack_from(f"{fmt}Q", buf, offset)[0]

def read_i32(buf: bytes, offset: int, byteorder: str = "le") -> int:
    fmt = _BYTE_ORDER_MAP.get(byteorder)
    if fmt is None:
        raise EndianError(f"unsupported byte order: {byteorder}")
    return struct.unpack_from(f"{fmt}i", buf, offset)[0]

def read_i64(buf: bytes, offset: int, byteorder: str = "le") -> int:
    fmt = _BYTE_ORDER_MAP.get(byteorder)
    if fmt is None:
        raise EndianError(f"unsupported byte order: {byteorder}")
    return struct.unpack_from(f"{fmt}q", buf, offset)[0]

# 变长整数 (LEB128 / ULEB128)
# DWARF 和 Wasm 均使用此编码。最大支持 64 位值。

def read_uleb128(buf: bytes, offset: int = 0) -> Tuple[int, int]:
    """读取无符号 LEB128 编码整数。
    返回 (value, consumed_bytes)。若数据不足则返回部分结果。"""
    result = 0
    shift = 0
    pos = offset
    while pos < len(buf):
        byte = buf[pos]
        result |= (byte & 0x7F) << shift
        pos += 1
        if (byte & 0x80) == 0:
            break
        shift += 7
    return result, pos - offset

def read_sleb128(buf: bytes, offset: int = 0) -> Tuple[int, int]:
    """读取有符号 LEB128 编码整数。符号扩展至 64 位。"""
    result = 0
    shift = 0
    pos = offset
    byte = 0
    while pos < len(buf):
        byte = buf[pos]
        result |= (byte & 0x7F) << shift
        pos += 1
        if (byte & 0x80) == 0:
            break
        shift += 7
    # 符号扩展
    if (byte & 0x40) != 0:
        result |= -(1 << (shift + 7))
    return result, pos - offset

def encode_uleb128(value: int) -> bytes:
    """将无符号整数编码为 ULEB128 字节序列。"""
    if value < 0:
        raise ValueError("ULEB128 不接受负数")
    parts = []
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            parts.append(byte | 0x80)
        else:
            parts.append(byte)
            break
    return bytes(parts)

def encode_sleb128(value: int) -> bytes:
    """将带符号整数编码为 SLEB128 字节序列。"""
    parts = []
    more = True
    while more:
        byte = value & 0x7F
        value >>= 7
        if (value == 0 and (byte & 0x40) == 0) or (value == -1 and (byte & 0x40) != 0):
            more = False
        else:
            byte |= 0x80
        parts.append(byte)
    return bytes(parts)

# 对齐工具

def align_up(value: int, alignment: int) -> int:
    """向上对齐到 alignment 的整数倍。alignment 须为 2 的幂。"""
    return (value + alignment - 1) & ~(alignment - 1)

def align_down(value: int, alignment: int) -> int:
    """向下对齐到 alignment 的整数倍。"""
    return value & ~(alignment - 1)

def is_aligned(value: int, alignment: int) -> bool:
    """检查 value 是否已按 alignment 对齐。"""
    return (value & (alignment - 1)) == 0

# hex dump

# 经典 hexdump 格式: 偏移 + 十六进制 + ASCII 预览
def hexdump(data: bytes, offset: int = 0, width: int = 16, *, upper: bool = True) -> str:
    """生成 hexdump 字符串。
    width: 每行字节数，默认 16。
    upper: 十六进制字母是否大写。"""
    lines = []
    hex_fmt = f"{{:0{2 if upper else 2}X}}" if upper else f"{{:0{2}x}}"
    for i in range(0, len(data), width):
        chunk = data[i:i + width]
        hex_part = " ".join(hex_fmt.format(b) for b in chunk)
        ascii_part = "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in chunk)
        lines.append(f"{offset + i:08X}  {hex_part:<{width * 3}} |{ascii_part}|")
    return "\n".join(lines)

def hexdump_bytes(data: bytes, *, width: int = 16) -> str:
    """hexdump 简写，从偏移 0 开始，小写字母。"""
    return hexdump(data, 0, width, upper=False)

# 文件读写辅助

def read_file_bytes(filepath: str, max_size: Optional[int] = None) -> bytes:
    """安全读取文件全部字节。max_size 限制最大读取量（防 OOM）。"""
    fsize = os.path.getsize(filepath)
    if max_size is not None and fsize > max_size:
        raise ValueError(f"文件过大: {fsize} > {max_size} bytes (limit)")
    with open(filepath, "rb") as fh:
        return fh.read()

def read_file_chunks(filepath: str, chunk_size: int = 4096) -> Iterator[bytes]:
    """分块读取文件。chunk_size 默认 4 KiB。"""
    with open(filepath, "rb") as fh:
        while True:
            chunk = fh.read(chunk_size)
            if not chunk:
                break
            yield chunk

def write_file_bytes(filepath: str, data: bytes, *, atomic: bool = False) -> int:
    """写入字节。atomic=True 时先写临时文件再重命名。返回写入字节数。"""
    if atomic:
        import tempfile
        dirname = os.path.dirname(filepath) or "."
        fd, tmpname = tempfile.mkstemp(dir=dirname, suffix=".tmp")
        try:
            os.write(fd, data)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(tmpname, filepath)
    else:
        with open(filepath, "wb") as fh:
            fh.write(data)
    return len(data)

# 字节搜索

def find_bytes(data: bytes, pattern: bytes, start: int = 0) -> int:
    """在 data 中搜索 pattern 字节序列，返回首次出现的偏移。未找到返回 -1。"""
    return data.find(pattern, start)

def find_all_bytes(data: bytes, pattern: bytes) -> List[int]:
    """搜索 pattern 全部出现位置。对于长模式使用内置 find 的跳跃策略。"""
    positions = []
    pos = 0
    while True:
        pos = data.find(pattern, pos)
        if pos == -1:
            break
        positions.append(pos)
        pos += 1
    return positions

def extract_range(data: bytes, start: int, end: int) -> bytes:
    """提取 [start, end) 范围的字节。自动裁剪到 data 长度。"""
    return data[max(0, start):min(len(data), end)]

