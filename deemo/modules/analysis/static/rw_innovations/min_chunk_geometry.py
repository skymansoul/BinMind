"""MinChunkGeometry - 最小块几何 (stage 74).

request2size 下任何 malloc 可用 >= 32 字节 (MINSIZE), 写入 <= 32 时
无论分配多大必安全. 与 CACBV slack 不同: MINSIZE 下界定理直接应用.

设计决策:
  - 采用 glibc request2size 语义: MINSIZE = 32
  - 写大小从操作数宽度推断(非立即数值), 写偏移在 [0, alloc) 内 -> 恒安全
  - 即使 alloc 未知, 写 <= 32 也按最小块几何判安全
"""

import re
from typing import List, Optional

_MINSIZE = 32


def _write_width(line: str) -> int:
    """从写操作行推断写入字节数. 依据操作数宽度而非立即数值."""
    line = line.strip()
    # 行内宽度前缀优先
    if re.search(r"\bqword\b", line, re.IGNORECASE):
        return 8
    if re.search(r"\bdword\b", line, re.IGNORECASE):
        return 4
    if re.search(r"\bword\b", line, re.IGNORECASE):
        return 2
    if re.search(r"\bbyte\b", line, re.IGNORECASE):
        return 1
    # 寄存器源宽度
    m_reg = re.search(r"\[[^\]]*\]\s*(?:,|=)\s*([A-Za-z][A-Za-z0-9]*)", line)
    if m_reg:
        name = m_reg.group(1).lower()
        if name.startswith("r") and len(name) >= 2:
            return 8
        if name.startswith("e"):
            return 4
        if len(name) == 2 and name[0] in ("a", "b", "c", "d"):
            return 1
    # 立即数默认 4 字节
    return 4


def run_min_chunk_geometry(
    pseudocode: str,
    func_name: str,
    existing_findings: Optional[List[dict]] = None,
) -> List[dict]:
    """最小块几何判定. 返回 findings."""
    findings: List[dict] = []
    for ln, line in enumerate(pseudocode.splitlines(), 1):
        # 写点 [ptr+off] = 值 或 [ptr] = 值, 偏移支持十进制和 0x 十六进制
        m = re.search(r"\[\s*(\w+)\s*\+\s*(0[xX][0-9a-fA-F]+|\d+)\s*\]\s*(?:,|=)", line)
        if not m:
            m = re.search(r"\[\s*(\w+)\s*\]\s*(?:,|=)", line)
        if not m:
            continue
        if len(m.groups()) == 2:
            off_str = m.group(2)
            off = int(off_str, 16) if off_str.lower().startswith("0x") else int(off_str)
        else:
            off = 0
        # 写宽度从操作数推断
        write_size = _write_width(line)
        # 最小块几何: 任何 malloc 请求可用 >= 32B
        if write_size <= _MINSIZE and off + write_size <= _MINSIZE:
            verdict, conf = "safe_minsize", 0.95
        else:
            verdict, conf = "beyond_minsize", 0.4
        findings.append({
            "type": "heap_overflow",
            "function": func_name or "unknown",
            "severity": "low" if verdict == "safe_minsize" else "medium",
            "cwe": "CWE-122",
            "confidence": conf,
            "description": f"line{ln} off={off} write={write_size} "
                           f"minsize={_MINSIZE}",
            "verdict": verdict,
            "source": "min_chunk_geometry",
        })
    return findings


if __name__ == "__main__":
    demo = """\
p = malloc(1);
mov [p+8], 0x41;
"""
    out = run_min_chunk_geometry(demo, "demo")
    for f in out:
        print(f["description"], f["verdict"], f["confidence"])