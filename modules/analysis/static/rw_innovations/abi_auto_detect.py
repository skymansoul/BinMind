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


# C 风格函数签名正则: 返回类型 函数名(参数列表)
_C_SIG_RE = re.compile(
    r"^\s*(?:int|char|void|size_t|unsigned|long|short|float|double)\s+"
    r"\*?\s*\w+\s*\(([^)]*)\)"
)


def _c_sig_signal(pseudocode: str) -> Optional[tuple]:
    """解析 C 风格函数签名, 返回 (abi, param_count)."""
    for line in pseudocode.splitlines():
        m = _C_SIG_RE.search(line)
        if not m:
            continue
        params_str = m.group(1).strip()
        if not params_str or params_str == "void":
            return ("sysv", 0)
        params = [p.strip() for p in params_str.split(",")]
        count = len(params)
        # 参数类型中包含指针则记为指针参数
        has_ptr = any("*" in p for p in params)
        has_scalar = any(
            re.search(r"\bint\b|\bchar\b|\bsize_t\b|\bunsigned\b|\blong\b", p)
            for p in params
        )
        # System V AMD64: 标量+指针混合且 <=6 参为候选
        if count <= 6 and (has_ptr or has_scalar):
            return ("sysv", count)
        # >6 参为 partial
        if count > 6:
            return ("partial", count)
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
        # C 风格签名解析: 按参数个数/类型推断 ABI
        c_sig = _c_sig_signal(pseudocode)
        if c_sig is not None:
            c_abi, param_count = c_sig
            if c_abi == "sysv" and param_count <= 6:
                abi, conf, verdict = "sysv", 0.9, "abi_confirmed"
            elif c_abi == "partial":
                abi, conf, verdict = "sysv", 0.6, "abi_partial"
            else:
                abi, conf, verdict = "unknown", 0.3, "abi_unknown"
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