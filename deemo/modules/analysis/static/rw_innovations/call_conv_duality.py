"""CallConvDuality - 双 ABI 对偶 (stage 81).

同一 call 点按 SysV/Linux 与 Windows 两套寄存器约定各解析一遍 size,
双解析一致才采信. 与 constraint_based_pairing 双 ABI 枚举不同:
对偶一致性投票.

设计决策:
  - SysV: size 在 rdx/r8;  Win64: size 在 r8
  - 同一 call 点两套解析, 若都得到相同 size -> 采信
  - 双解析不一致 -> 降权
"""

import re
from typing import Dict, List, Optional

_SYSV_SIZE_REGS = ("rdx", "r8")
_WIN_SIZE_REGS = ("r8", "rcx")


def _resolve_size(pseudocode: str, line_no: int, regs: tuple) -> Optional[int]:
    """在 call 前若干行查找对 size 寄存器的常量赋值."""
    lines = pseudocode.splitlines()
    for i in range(max(0, line_no - 8), line_no):
        for reg in regs:
            m = re.search(r"\bmov\s+" + reg + r"\s*,\s*(0[xX][0-9a-fA-F]+|\d+)", lines[i])
            if m:
                return int(m.group(1), 0)
    return None


def run_call_conv_duality(
    pseudocode: str,
    func_name: str,
    existing_findings: Optional[List[dict]] = None,
) -> List[dict]:
    """双 ABI 对偶. 返回 findings."""
    findings: List[dict] = []
    for ln, line in enumerate(pseudocode.splitlines(), 1):
        if "call" not in line:
            continue
        size_sysv = _resolve_size(pseudocode, ln, _SYSV_SIZE_REGS)
        size_win = _resolve_size(pseudocode, ln, _WIN_SIZE_REGS)
        if size_sysv is not None and size_win is not None:
            agree = size_sysv == size_win
            verdict, conf = ("dual_agree", 0.9) if agree else ("dual_conflict", 0.3)
            desc = f"call@{ln} sysv={size_sysv} win={size_win} agree={agree}"
        elif size_sysv is not None:
            verdict, conf = "sysv_only", 0.6
            desc = f"call@{ln} sysv={size_sysv} win=unknown"
        elif size_win is not None:
            verdict, conf = "win_only", 0.6
            desc = f"call@{ln} sysv=unknown win={size_win}"
        else:
            verdict, conf = "no_size", 0.4
            desc = f"call@{ln} no size reg resolved"
        findings.append({
            "type": "heap_overflow",
            "function": func_name or "unknown",
            "severity": "medium",
            "cwe": "CWE-122",
            "confidence": conf,
            "description": desc,
            "verdict": verdict,
            "source": "call_conv_duality",
        })
    return findings


def _resolve_size(pseudocode: str, line_no: int, regs: tuple) -> Optional[int]:
    """在 call 前若干行查找对 size 寄存器的常量赋值."""
    lines = pseudocode.splitlines()
    for i in range(max(0, line_no - 8), line_no):
        for reg in regs:
            m = re.search(r"\bmov\s+" + reg + r"\s*,\s*(0[xX][0-9a-fA-F]+|\d+)", lines[i])
            if m:
                return int(m.group(1), 0)
    return None


if __name__ == "__main__":
    demo = """\
mov rdi, buf;
mov rdx, 64;
call memcpy;
"""
    out = run_call_conv_duality(demo, "demo")
    for f in out:
        print(f["description"], f["verdict"])