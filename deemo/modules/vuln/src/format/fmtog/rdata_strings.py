"""rdata 字符串表提取 — 常量格式串内容解析.

objdump -s 的 hex 列按 4 字节分组 (8 hex 无空格), 需按字节宽度
重组; 字符串跨行时按虚拟地址拼接. 解析失败返回空映射, 调用方
回退身份判定.
"""

import re
import subprocess
from typing import Dict, Optional


def extract_rdata_strings(binary_path: str) -> Dict[int, str]:
    """按起始地址提取 .rdata 全部字符串字面量."""
    try:
        proc = subprocess.run(['objdump', '-s', '-j', '.rdata', binary_path],
                              capture_output=True, text=True, timeout=30,
                              encoding='utf-8', errors='replace')
        if proc.returncode != 0:
            return {}
    except Exception:
        return {}
    chunks: Dict[int, bytes] = {}
    for line in proc.stdout.splitlines():
        m = re.match(r'\s*([0-9a-f]+)\s+((?:[0-9a-f]{2}\s*){1,16})\s+', line)
        if not m:
            continue
        addr = int(m.group(1), 16)
        hexpart = m.group(2)
        data = bytes(int(h, 16) for h in re.findall(r'[0-9a-f]{2}', hexpart))
        chunks[addr] = data
    if not chunks:
        return {}
    lo = min(chunks)
    hi = max(chunks) + len(chunks[max(chunks)])
    blob = bytearray(hi - lo)
    for a, d in chunks.items():
        blob[a - lo:a - lo + len(d)] = d
    result: Dict[int, str] = {}
    i = 0
    while i < len(blob):
        if blob[i] == 0:
            i += 1
            continue
        end = blob.index(0, i) if 0 in blob[i:] else len(blob)
        try:
            s = bytes(blob[i:end]).decode('utf-8', errors='replace')
        except Exception:
            s = ''
        if s:
            result[lo + i] = s
        i = end + 1
    return result
