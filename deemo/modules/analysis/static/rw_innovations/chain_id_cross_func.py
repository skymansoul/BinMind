"""ChainIdCrossFunc - 跨函数链 ID (stage 102).

call 处 rax 分配新链 ID, 跨函数调用时链 ID 失效退化为独立链.
与 freed_alias_epoch 不同: 本模块聚焦调用边界而非时间纪元.

设计决策:
  - 链 ID 生成: 每次 call 后 rax 获得新链 ID (自增)
  - 跨函数: 调用后原链 ID 不可沿用 (callee 可能改写 rax)
  - 写点绑定链 ID, 同链内偏移可联合分析
"""

import re
from typing import List, Optional


def _chain_map(pseudocode: str) -> dict:
    """链 ID 映射: 变量 -> 链 ID (最终状态)."""
    chain: dict = {}
    cid = 0
    for line in pseudocode.splitlines():
        m = re.search(r"\b(\w+)\s*=\s*(?:\([^)]*\)\s*)?(?:malloc|calloc|realloc)\s*\(", line)
        if m:
            cid += 1
            chain[m.group(1)] = cid
            continue
        m = re.search(r"\bcall\s+(\w+)", line)
        if m:
            cid += 1
            chain["rax"] = cid
            continue
        m = re.search(r"\b(\w+)\s*=\s*rax", line)
        if m:
            cid += 1
            chain[m.group(1)] = cid
    return chain


def _chain_snapshots(pseudocode: str) -> List[dict]:
    """按行号生成链 ID 快照列表, 返回 [行号对应的 {var: cid}]."""
    snapshots: List[dict] = []
    chain: dict = {}
    cid = 0
    for line in pseudocode.splitlines():
        m = re.search(r"\b(\w+)\s*=\s*(?:\([^)]*\)\s*)?(?:malloc|calloc|realloc)\s*\(", line)
        if m:
            cid += 1
            chain[m.group(1)] = cid
            snapshots.append(dict(chain))
            continue
        m = re.search(r"\bcall\s+(\w+)", line)
        if m:
            cid += 1
            chain["rax"] = cid
            snapshots.append(dict(chain))
            continue
        m = re.search(r"\b(\w+)\s*=\s*rax", line)
        if m:
            cid += 1
            chain[m.group(1)] = cid
            snapshots.append(dict(chain))
            continue
        snapshots.append(dict(chain))
    return snapshots


def run_chain_id_cross_func(
    pseudocode: str,
    func_name: str,
    existing_findings: Optional[List[dict]] = None,
) -> List[dict]:
    """跨函数链 ID 分析. 返回 findings."""
    findings: List[dict] = []
    chain = _chain_map(pseudocode)
    snapshots = _chain_snapshots(pseudocode)
    lines = pseudocode.splitlines()
    for ln, line in enumerate(lines, 1):
        m = re.search(r"\[\s*(\w+)\s*(\+\s*\w+)?\]\s*(?:,|=)", line)
        if not m:
            continue
        var = m.group(1)
        # 写点行的链 ID 快照
        snap = snapshots[ln - 1] if ln - 1 < len(snapshots) else {}
        write_cid = snap.get(var)
        if write_cid is None:
            # 无法取得写点链 ID, 保守跳过
            continue
        # 查该链 ID 的原始分配点 (malloc 变量)
        alloc_cid = chain.get(var)
        if alloc_cid is None:
            # 写点变量不是直接分配变量, 检查是否通过 rax 间接获得
            verdict = "chain_clean"
            confidence = 0.8
        elif write_cid == alloc_cid:
            # 链 ID 一致: 检查中间是否有 call 导致链失效
            crossed = False
            for prev_idx in range(ln):
                prev_snap = snapshots[prev_idx] if prev_idx < len(snapshots) else {}
                prev_cid = prev_snap.get(var)
                if prev_cid is not None and prev_cid != write_cid:
                    crossed = True
                    break
            verdict = "chain_dirty" if crossed else "chain_clean"
            confidence = 0.4 if crossed else 0.8
        else:
            # 写点链 ID 与分配链 ID 不一致, 链已失效
            verdict = "chain_dirty"
            confidence = 0.4
        findings.append({
            "type": "heap_overflow",
            "function": func_name or "unknown",
            "severity": "medium",
            "cwe": "CWE-122",
            "confidence": confidence,
            "description": f"line{ln} var={var} cid={write_cid} "
                           f"alloc_cid={alloc_cid} verdict={verdict}",
            "verdict": verdict,
            "source": "chain_id_cross_func",
        })
    return findings


if __name__ == "__main__":
    demo = """\
p = malloc(64);
call foo;
mov [p+8], 0;
"""
    out = run_chain_id_cross_func(demo, "demo")
    for f in out:
        print(f["description"], f["verdict"])