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
    """链 ID 映射: rax 的当前链 ID."""
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


def run_chain_id_cross_func(
    pseudocode: str,
    func_name: str,
    existing_findings: Optional[List[dict]] = None,
) -> List[dict]:
    """跨函数链 ID 分析. 返回 findings."""
    findings: List[dict] = []
    chain = _chain_map(pseudocode)
    for ln, line in enumerate(pseudocode.splitlines(), 1):
        m = re.search(r"\[\s*(\w+)\s*(\+\s*\w+)?\]\s*(?:,|=)", line)
        if not m:
            continue
        var = m.group(1)
        cid = chain.get(var)
        if cid is None:
            continue
        # 写点前是否跨 call (链可能失效)
        crossed = False
        for prev in pseudocode.splitlines()[:ln]:
            if re.search(r"\bcall\s+\w+", prev):
                crossed = True
                break
        verdict = "chain_dirty" if crossed else "chain_clean"
        findings.append({
            "type": "heap_overflow",
            "function": func_name or "unknown",
            "severity": "medium",
            "cwe": "CWE-122",
            "confidence": 0.4 if crossed else 0.8,
            "description": f"line{ln} var={var} cid={cid} "
                           f"cross_call={crossed}",
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