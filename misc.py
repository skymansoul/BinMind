# 跨子系统通用工具函数
import hashlib, os, random, re, string
from typing import Optional


def rand_str(n: int = 8) -> str:
    # 生成临时文件名用的随机 ASCII 串，非密码学安全
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=n))


def sha256_file(path: str) -> Optional[str]:
    # 返回文件 SHA-256 摘要，失败返回 None
    h = hashlib.sha256()
    try:
        with open(path, 'rb') as f:
            while chunk := f.read(65536):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


def hexdump(data: bytes, offset: int = 0, width: int = 16) -> str:
    # 经典十六进制+ASCII 转储，调试 payload 用
    lines = []
    for i in range(0, len(data), width):
        chunk = data[i:i + width]
        hex_part = ' '.join(f'{b:02x}' for b in chunk)
        ascii_part = ''.join(chr(b) if 0x20 <= b < 0x7f else '.' for b in chunk)
        lines.append(f'{offset + i:08x}  {hex_part:<{width * 3}}  {ascii_part}')
    return '\n'.join(lines)


def is_printable_ascii(data: bytes) -> bool:
    # 判断字节是否全为可打印 ASCII 或常见空白符
    return all(0x20 <= b < 0x7f or b in (0x0a, 0x0d, 0x09) for b in data)


# clamp helper — used in a few places where we get values from external tools
def clamp(val, lo, hi):
    if val is None:
        return lo
    return max(lo, min(val, hi))
