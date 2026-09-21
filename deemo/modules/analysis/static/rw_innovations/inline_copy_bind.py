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

    # C 风格伪代码: memcpy/memmove/strcpy 计数绑定
    # 检测变量是否被守卫钳制 (if(n>MAX) n=MAX 形式)
    _guarded_vars: set = set()
    for line in pseudocode.splitlines():
        m_clamp = re.search(
            r"if\s*\(\s*(\w+)\s*[><=]+\s*\d+\s*\)\s*\1\s*=\s*\d+",
            line,
        )
        if m_clamp:
            _guarded_vars.add(m_clamp.group(1))

    for ln, line in enumerate(pseudocode.splitlines(), 1):
        m_copy = re.search(
            r"\b(?:memcpy|memmove|strcpy)\s*\(\s*\w+\s*,\s*\w+\s*,\s*(\w+)\s*\)",
            line,
        )
        if not m_copy:
            # strcpy 无第三参数, 单独匹配
            m_copy = re.search(r"\bstrcpy\s*\(\s*\w+\s*,\s*\w+\s*\)", line)
            if m_copy:
                # strcpy 长度未知, 视为无界复制
                findings.append({
                    "type": "memory_copy",
                    "function": func_name or "unknown",
                    "severity": "medium",
                    "cwe": "CWE-787",
                    "confidence": 0.6,
                    "description": f"line{ln} strcpy unbounded copy",
                    "verdict": "count_unbound",
                    "source": "inline_copy_bind",
                })
            continue
        len_tok = m_copy.group(1)
        if len_tok.isdigit():
            # 常量长度, 可绑定, 不注入
            continue
        # 变量长度: 检查是否被守卫钳制
        if len_tok in _guarded_vars:
            # 有守卫, 可绑定, 不注入 (安全场景不得注入弱告警)
            continue
        # 变量长度且无守卫 → 注入 count_unbound
        findings.append({
            "type": "memory_copy",
            "function": func_name or "unknown",
            "severity": "medium",
            "cwe": "CWE-787",
            "confidence": 0.6,
            "description": f"line{ln} memcpy len={len_tok} unbound (no guard)",
            "verdict": "count_unbound",
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