"""DeadStoreElimTolerant - 死存储消除容忍 (stage 96).

O2 优化下 mov 指针到多槽后仅最后一槽活, 追踪活跃槽集合.
与 _alias_slots 不同: 活跃槽集合论而非槽列表.

设计决策:
  - 槽: mov [mem], reg 的目标地址
  - 同一指针被多次写入不同槽时, 仅最后一槽活跃
  - 活跃槽集合: 记录当前活跃槽
  - 后续使用活跃槽 -> 正常; 使用非活跃槽 -> 容忍
"""

import re
from typing import Dict, List, Optional, Set


def _track_slots(pseudocode: str) -> Dict[str, Set[str]]:
    """追踪 {指针: 活跃槽集合}."""
    slots: Dict[str, Set[str]] = {}
    for line in pseudocode.splitlines():
        m = re.search(r"\bmov\s+\[\s*(\w+)\s*\+\s*(\d+)\s*\]\s*,\s*(\w+)", line)
        if m:
            ptr, off, val = m.group(1), m.group(2), m.group(3)
            # O2: 仅最后一槽活 -> 保留最近写入的槽
            slots[ptr] = {off}
    return slots


def run_dead_store_elim_tolerant(
    pseudocode: str,
    func_name: str,
    existing_findings: Optional[List[dict]] = None,
) -> List[dict]:
    """死存储消除容忍. 返回 findings."""
    findings: List[dict] = []
    slots = _track_slots(pseudocode)
    for ln, line in enumerate(pseudocode.splitlines(), 1):
        m = re.search(r"\[\s*(\w+)\s*\+\s*(\d+)\s*\]\s*(?:,|=)", line)
        if not m:
            continue
        ptr, off = m.group(1), m.group(2)
        if ptr in slots:
            live = off in slots[ptr]
            verdict, conf = ("live_slot", 0.8) if live else ("dead_slot", 0.5)
        else:
            verdict, conf = "untracked", 0.4
        findings.append({
            "type": "heap_overflow",
            "function": func_name or "unknown",
            "severity": "medium",
            "cwe": "CWE-122",
            "confidence": conf,
            "description": f"line{ln} ptr={ptr} off={off} "
                           f"active_slots={slots.get(ptr)}",
            "verdict": verdict,
            "source": "dead_store_elim_tolerant",
        })
    return findings


if __name__ == "__main__":
    demo = """\
mov [rbx+0], rax;
mov [rbx+8], rcx;
mov [rbx+8], 0;
"""
    out = run_dead_store_elim_tolerant(demo, "demo")
    for f in out:
        print(f["description"], f["verdict"])