"""HeapWriteOperandCap - 堆写操作数容量 (stage 103).

伪代码侧堆写操作数捕获 + 容量判定:
  捕获 mov [dst], src 的写大小 (src 寄存器 8B / 立即数按位宽)
  并对比分配容量.
与 use_deref_lattice 不同: 本模块专攻堆写操作数宽度.

设计决策:
  - 写大小: src 为寄存器 -> 8 (64位), 立即数 -> 字节数
  - 容量: 分配大小 - 偏移
  - write_size > capacity -> overflow
"""

import re
from typing import List, Optional


def _write_size(src: str) -> int:
    """写操作数大小."""
    if src.isdigit():
        return 1
    if src.startswith("["):
        return 8
    # 寄存器
    if re.match(r"^[er]?[abcd]x$", src):
        return 8
    if re.match(r"^[abcd][lh]$", src):
        return 1
    return 8


def run_heap_write_operand_cap(
    pseudocode: str,
    func_name: str,
    existing_findings: Optional[List[dict]] = None,
) -> List[dict]:
    """堆写操作数容量判定. 返回 findings."""
    findings: List[dict] = []
    m_alloc = re.search(r"(?:malloc|calloc|realloc)\s*\(\s*(\d+)", pseudocode)
    alloc = int(m_alloc.group(1)) if m_alloc else None
    for ln, line in enumerate(pseudocode.splitlines(), 1):
        m = re.search(r"\[\s*(\w+)\s*\+\s*(\d+)\s*\]\s*,\s*(\S+)\s*;?", line)
        if not m:
            continue
        var, off, src = m.group(1), int(m.group(2)), m.group(3)
        if alloc is None:
            continue
        ws = _write_size(src)
        cap = alloc - off
        verdict = "cap_ok" if ws <= cap else "cap_exceed"
        findings.append({
            "type": "heap_overflow",
            "function": func_name or "unknown",
            "severity": "medium",
            "cwe": "CWE-122",
            "confidence": 0.9 if verdict == "cap_exceed" else 0.7,
            "description": f"line{ln} off={off} src={src} ws={ws} "
                           f"cap={cap} verdict={verdict}",
            "verdict": verdict,
            "source": "heap_write_operand_cap",
        })
    return findings


if __name__ == "__main__":
    demo = """\
p = malloc(64);
mov [p+60], rax;
"""
    out = run_heap_write_operand_cap(demo, "demo")
    for f in out:
        print(f["description"], f["verdict"])