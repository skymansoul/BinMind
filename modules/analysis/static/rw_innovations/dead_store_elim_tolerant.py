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


def _c_dead_store_analysis(pseudocode: str) -> list:
    """C 风格死存储分析: 同一下标连续两次写且中间无读 -> dead_slot.
    返回 [(行号, 指针, 下标表达式, verdict, description)] 列表."""
    results = []
    writes = []
    # 收集所有写操作: (行号, 指针, 下标表达式)
    # 全文扫描而非逐行, 用 finditer 捕获多次写
    for m in re.finditer(r"\b(\w+)\[([^\]]+)\]\s*=\s*([^;,]+)", pseudocode):
        # 计算行号: 写操作所在行
        pos = m.start()
        ln = pseudocode[:pos].count("\n") + 1
        writes.append((ln, m.group(1), m.group(2).strip(), m.group(3).strip()))
    # 记录已被覆盖的写序号
    dead_indices = set()
    # 检测连续写同一指针同一下标且中间无读
    for i in range(len(writes)):
        if i in dead_indices:
            continue
        ln_i, ptr_i, idx_i, val_i = writes[i]
        # 查找后续是否有同指针同下标的写
        for j in range(i + 1, len(writes)):
            ln_j, ptr_j, idx_j, val_j = writes[j]
            if ptr_j == ptr_i and idx_j == idx_i:
                # 相邻写且中间无其他写 -> 第一次 dead, 第二次 live
                dead_indices.add(i)
                dead_indices.add(j)
                results.append((ln_i, ptr_i, idx_i, "dead_slot", f"buf[{idx_i}]={val_i} overwritten by line{ln_j} buf[{idx_j}]={val_j}"))
                results.append((ln_j, ptr_j, idx_j, "live_slot", f"buf[{idx_j}]={val_j} final write"))
                break
        else:
            # 无后续覆盖 -> live_slot
            results.append((ln_i, ptr_i, idx_i, "live_slot", f"buf[{idx_i}]={val_i} no overwrite"))
    return results


def run_dead_store_elim_tolerant(
    pseudocode: str,
    func_name: str,
    existing_findings: Optional[List[dict]] = None,
) -> List[dict]:
    """死存储消除容忍. 返回 findings."""
    findings: List[dict] = []
    # C 风格优先
    c_results = _c_dead_store_analysis(pseudocode)
    if c_results:
        for ln, ptr, idx_expr, verdict, desc in c_results:
            conf = 0.5 if verdict == "dead_slot" else 0.8
            findings.append({
                "type": "heap_overflow",
                "function": func_name or "unknown",
                "severity": "medium",
                "cwe": "CWE-122",
                "confidence": conf,
                "description": f"line{ln} ptr={ptr} idx={idx_expr} {desc} mode=c",
                "verdict": verdict,
                "source": "dead_store_elim_tolerant",
            })
        return findings
    # 汇编风格回退
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
                           f"active_slots={slots.get(ptr)} mode=asm",
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