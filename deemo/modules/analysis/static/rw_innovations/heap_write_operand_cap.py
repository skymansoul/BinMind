"""HeapWriteOperandCap - 堆写操作数容量 (stage 103).

伪代码侧堆写操作数捕获 + 容量判定:
  捕获 mov [dst], src 的写大小 (src 寄存器宽度 / 立即数按默认 4B 或行内宽度前缀)
  并对比分配容量.
与 use_deref_lattice 不同: 本模块专攻堆写操作数宽度.

设计决策:
  - 写大小: src 为寄存器 -> 按寄存器宽度, 立即数 -> 4 (默认 32 位 imm 编码)
  - 容量: 分配大小 - 偏移
  - write_size > capacity -> overflow
  - 偏移含变量名时无法确定, 保守判 unknown 不注入
"""

import re
from typing import List, Optional


def _write_size(src: str, line: str) -> int:
    """写操作数大小. 依据操作数宽度而非立即数值."""
    # 行内宽度前缀优先
    if re.search(r"\bqword\b", line, re.IGNORECASE):
        return 8
    if re.search(r"\bdword\b", line, re.IGNORECASE):
        return 4
    if re.search(r"\bword\b", line, re.IGNORECASE):
        return 2
    if re.search(r"\bbyte\b", line, re.IGNORECASE):
        return 1
    # 内存源
    if src.startswith("["):
        return 8
    # 寄存器源
    src_low = src.lower()
    if re.match(r"^r[a-z0-9]+$", src_low):
        return 8
    if re.match(r"^e[a-z]x$", src_low):
        return 4
    if re.match(r"^[abcd][lh]$", src_low):
        return 1
    if re.match(r"^[abcd]x$", src_low):
        return 2
    # 立即数默认 4 字节
    return 4


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
        # 支持 [var+常量] 和 [var+变量名] 偏移
        m = re.search(r"\[\s*(\w+)\s*\+\s*(\w+)\s*\]\s*,\s*(\S+)\s*;?", line)
        if not m:
            continue
        var, off_tok, src = m.group(1), m.group(2), m.group(3)
        if alloc is None:
            continue
        # 偏移为变量名时无法确定, 保守判 unknown 不注入
        if not re.fullmatch(r"(0[xX][0-9a-fA-F]+|\d+)", off_tok):
            continue
        off = int(off_tok, 16) if off_tok.lower().startswith("0x") else int(off_tok)
        ws = _write_size(src, line)
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