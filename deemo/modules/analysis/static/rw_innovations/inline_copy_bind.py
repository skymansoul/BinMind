"""InlineCopyBind - 内联复制绑定 (stage 97).

rep movs 系列 (rep movsb/movsw/movsd/movsq) 的复制行为绑定:
把计数寄存器 (ecx/rcx) 的常量赋值绑定为写大小 write_size = count * unit.
与 memcpy 识别不同: 聚焦 rep movs 伪代码形态, 绑定计数到写侧.

设计决策:
  - unit: movsb=1, movsw=2, movsd=4, movsq=8
  - 计数寄存器: ecx/rcx (常量 -> 可绑定, 寄存器 -> 不可绑定)
  - 目标地址不可解析时仍保留 write_size 绑定 (容量判定交给后续阶段)
"""

import re
from typing import List, Optional

_UNIT = {"movsb": 1, "movsw": 2, "movsd": 4, "movsq": 8}


def _count_bind(line: str) -> Optional[int]:
    """解析 mov ecx/rcx, imm 的计数绑定."""
    m = re.search(r"\b(?:ecx|rcx)\s*,\s*(\d+)\b", line)
    return int(m.group(1)) if m else None


def _is_count_reg(line: str) -> bool:
    """行是否对计数寄存器赋非立即数 (不可静态绑定)."""
    return bool(re.search(r"\b(?:ecx|rcx)\s*,\s*(?!\d)", line))


def run_inline_copy_bind(
    pseudocode: str,
    func_name: str,
    existing_findings: Optional[List[dict]] = None,
) -> List[dict]:
    """内联复制绑定. 返回 findings."""
    findings: List[dict] = []
    for ln, line in enumerate(pseudocode.splitlines(), 1):
        m = re.search(r"\brep\s+(movs[a-z]?)\b", line, re.IGNORECASE)
        if not m:
            continue
        op = m.group(1).lower()
        unit = _UNIT.get(op, 1)
        # 回溯最近计数赋值
        bound = None
        for prev in pseudocode.splitlines()[:ln]:
            c = _count_bind(prev)
            if c is not None:
                bound = c
        if bound is None:
            unbound = any(_is_count_reg(l) for l in pseudocode.splitlines()[:ln])
            verdict = "count_unbound" if unbound else "count_missing"
            findings.append({
                "type": "memory_copy",
                "function": func_name or "unknown",
                "severity": "medium",
                "cwe": "CWE-787",
                "confidence": 0.4,
                "description": f"line{ln} rep={op} unit={unit} "
                               f"count=UNKNOWN verdict={verdict}",
                "verdict": verdict,
                "source": "inline_copy_bind",
            })
            continue
        write_size = bound * _UNIT.get(op, 1)
        findings.append({
            "type": "memory_copy",
            "function": func_name or "unknown",
            "severity": "low",
            "cwe": "CWE-787",
            "confidence": 0.9,
            "description": f"line{ln} rep={op} unit={unit} count={bound} "
                           f"write_size={write_size}",
            "verdict": "bound",
            "source": "inline_copy_bind",
        })
    return findings


if __name__ == "__main__":
    demo = """\
mov ecx, 16;
lea rdi, [p+8];
rep movsb;
"""
    out = run_inline_copy_bind(demo, "demo")
    for f in out:
        print(f["description"], f["verdict"])