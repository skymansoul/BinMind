# .rdata/.rodata 节字节提取 - 供有界写恢复 (Bounded Write Recovery)从RIP相对地址读取字符串字面量.
# objdump -s 输出的数据行格式: <va> 4×32bit hex  ASCII

import subprocess
from typing import Dict

def extract_rodata_bytes(binary: str) -> Dict[int, bytes]:
    """提取二进制只读数据节的 {虚拟地址: 字节串} 映射.

    供有界写恢复 (Bounded Write Recovery)解析 lea reg,[rip+X] 指向的字符串字面量长度.
    """
    rodata: Dict[int, bytes] = {}
    try:
        out = subprocess.run(["objdump", "-s", binary],
                             capture_output=True, timeout=30
                             ).stdout.decode("utf-8", errors="replace")
    except Exception:
        return rodata
    for line in out.split("\n"):
        line = line.strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) < 3:
            continue
        addr = _parse_va(parts[0])
        if addr is None:
            continue
        hex_bytes = bytearray()
        for p in parts[1:5]:
            if len(p) == 8 and all(c in "0123456789abcdefABCDEF" for c in p):
                for i in range(0, 8, 2):
                    hex_bytes.append(int(p[i:i + 2], 16))
            else:
                break
        if hex_bytes:
            rodata[addr] = bytes(hex_bytes)
    return rodata


def read_cstring(rodata: Dict[int, bytes], addr: int, max_len: int = 512
                 ) -> bytes:
    """从地址读取NUL终止字符串 (跨行拼接)."""
    if not rodata:
        return b""
    base = addr & ~0xF
    off = addr - base
    buf = bytearray()
    while base in rodata and len(buf) < max_len:
        chunk = rodata[base]
        if off >= len(chunk):
            break
        for b in chunk[off:]:
            if b == 0:
                return bytes(buf)
            buf.append(b)
        base += 16
        off = 0
    return bytes(buf)


def _parse_va(s: str):
    s = s.strip().rstrip(":")
    if not s or len(s) < 4:
        return None
    try:
        return int(s, 16)
    except ValueError:
        return None


__all__ = ["extract_rodata_bytes", "read_cstring"]
