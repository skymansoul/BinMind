"""RecoverySoundnessGate - 恢复健全性门 (stage 75).

BWR 类尺寸恢复结果必须通过"恢复值 <= 分配上限"健全性检查才可用于
过滤, 否则证据退回. 与 BWR 不同: 对恢复结果二次门禁.

设计决策:
  - 模拟尺寸恢复: 从伪代码中恢复写大小 (常量或变量上界)
  - 健全性门: 恢复值必须 <= 分配上限 (alloc_size 或 2**31-1)
  - 通过门 -> 恢复可用; 否则退回 (证据作废)
"""

import re
from typing import List, Optional


def _recover_size(line: str) -> Optional[int]:
    """从写指令恢复写入大小 (常量)."""
    m = re.search(r"\[[^\]]+\]\s*(?:,|=)\s*(0[xX][0-9a-fA-F]+|\d+)", line)
    if not m:
        return None
    try:
        return int(m.group(1), 0)
    except ValueError:
        return None


def run_recovery_soundness_gate(
    pseudocode: str,
    func_name: str,
    existing_findings: Optional[List[dict]] = None,
) -> List[dict]:
    """恢复健全性门. 返回 findings."""
    findings: List[dict] = []
    alloc_size: Optional[int] = None
    m_alloc = re.search(r"malloc\s*\(\s*(\d+)\s*\)", pseudocode)
    if m_alloc:
        alloc_size = int(m_alloc.group(1))
    upper = alloc_size if alloc_size is not None else (1 << 31) - 1
    for ln, line in enumerate(pseudocode.splitlines(), 1):
        recovered = _recover_size(line)
        if recovered is None:
            continue
        sound = recovered <= upper
        verdict = "sound" if sound else "unsound"
        findings.append({
            "type": "heap_overflow",
            "function": func_name or "unknown",
            "severity": "medium",
            "cwe": "CWE-122",
            "confidence": 0.9 if sound else 0.3,
            "description": f"line{ln} recovered={recovered} "
                           f"upper={upper} sound={sound}",
            "verdict": verdict,
            "source": "recovery_soundness_gate",
        })
    return findings


if __name__ == "__main__":
    demo = """\
p = malloc(16);
mov [p+8], 0x100;
"""
    out = run_recovery_soundness_gate(demo, "demo")
    for f in out:
        print(f["description"], f["verdict"])