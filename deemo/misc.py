"""
Miscellaneous helpers that don't fit cleanly into any subpackage.
Miscellaneous utilities that span multiple subsystems without a clear single owner.
"""

import hashlib
import os
import random
import re
import string
from typing import Optional


def rand_str(n: int = 8) -> str:
    """Quick random ASCII string for temp file names. Not crypto-safe."""
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=n))


def sha256_file(path: str) -> Optional[str]:
    """Return SHA-256 hex digest of a file, or None on failure."""
    h = hashlib.sha256()
    try:
        with open(path, 'rb') as f:
            while chunk := f.read(65536):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


def hexdump(data: bytes, offset: int = 0, width: int = 16) -> str:
    """Classic hexdump + ASCII view. Useful for debugging payloads."""
    lines = []
    for i in range(0, len(data), width):
        chunk = data[i:i + width]
        hex_part = ' '.join(f'{b:02x}' for b in chunk)
        ascii_part = ''.join(chr(b) if 0x20 <= b < 0x7f else '.' for b in chunk)
        lines.append(f'{offset + i:08x}  {hex_part:<{width * 3}}  {ascii_part}')
    return '\n'.join(lines)


def is_printable_ascii(data: bytes) -> bool:
    """True if all bytes are printable ASCII or common whitespace."""
    return all(0x20 <= b < 0x7f or b in (0x0a, 0x0d, 0x09) for b in data)


# clamp helper — used in a few places where we get values from external tools
def clamp(val, lo, hi):
    if val is None:
        return lo
    return max(lo, min(val, hi))
