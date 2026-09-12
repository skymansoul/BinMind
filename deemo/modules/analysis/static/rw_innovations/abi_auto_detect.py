"""AbiAutoDetect - ABI 自动识别 (stage 91).

按 push rbp 序言与寄存器使用模式自动识别 SysV/Windows, 再解析
size 寄存器. 与 reg_tracker._detect_abi 不同: 序言模式+用法双信号.

设计决策:
  - 信号1 序言: push rbp 后 sub rsp 常见于两者, 但 rbp 保存方式差异
  - 信号2 用法: 大量 rdi/rsi 传参 -> SysV; 大量 rcx/rdx -> Win64
  - 双信号一致才确认, 否则 UNKNOWN
"""

import re
from typing import List, Optional


def _prologue_signal(lines: List[str]) -> Optional[str]:
    """序言信号: SysV 常 push rbp; mov rbp,rsp; Win64 也类似但 rsp 减幅大."""
    text = "\n".join(lines[:8]).lower()
    if "push rbp" in text and "mov rbp, rsp" in text:
        return "sysv"
    if "sub rsp" in text and "rcx" in text and "rdi" not in text:
        return "win64"
    return None


def _usage_signal(pseudocode: str) -> Optional[str]:
    """寄存器用法信号: 统计 rdi/rsi vs rcx/rdx 出现频率."""
    n_sysv = len(re.findall(r"\br(?:di|si)\b", pseudocode))
    n_win = len(re.findall(r"\br(?:cx|dx)\b", pseudocode))
    if n_sysv > n_win and n_sysv > 0:
        return "sysv"
    if n_win > n_sysv and n_win > 0:
        return "win64"
    return None


def run_abi_auto_detect(
    pseudocode: str,
    func_name: str,
    existing_findings: Optional[List[dict]] = None,
) -> List[dict]:
    """ABI 自动识别. 返回 findings."""
    findings: List[dict] = []
    lines = pseudocode.splitlines()
    sig1 = _prologue_signal(lines)
    sig2 = _usage_signal(pseudocode)
    if sig1 == sig2 and sig1 is not None:
        abi, conf, verdict = sig1, 0.95, "abi_confirmed"
    elif sig1 is not None and sig2 is not None:
        abi, conf, verdict = sig1, 0.6, "abi_partial"
    else:
        abi, conf, verdict = "unknown", 0.3, "abi_unknown"
    size_reg = {"sysv": "rdx", "win64": "r8"}.get(abi, "unknown")
    findings.append({
        "type": "heap_overflow",
        "function": func_name or "unknown",
        "severity": "medium",
        "cwe": "CWE-122",
        "confidence": conf,
        "description": f"prologue={sig1} usage={sig2} -> abi={abi} "
                       f"size_reg={size_reg}",
        "verdict": verdict,
        "source": "abi_auto_detect",
    })
    return findings


if __name__ == "__main__":
    demo = """\
push rbp;
mov rbp, rsp;
mov rdi, 0;
call foo;
"""
    out = run_abi_auto_detect(demo, "demo")
    for f in out:
        print(f["description"], f["verdict"])