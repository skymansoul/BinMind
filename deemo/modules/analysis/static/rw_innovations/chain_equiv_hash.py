"""ChainEquivHash - 溯源链等价哈希 (stage 71).

alloc 溯源链与 write 溯源链各自序列化后取滚动哈希, 哈希相等 ->
等价安全. 与 ACPE classify_pair 不同: 链序列哈希比较.

设计决策:
  - 分配链: 从分配点沿 def-use 收集变量序列
  - 写入链: 从写点沿 use-def 回溯变量序列
  - 两条链序列化后计算滚动哈希 (RK: base=131, mod=2**61-1)
  - 哈希相等 -> 分配链与写链等价 -> 安全
"""

import re
from typing import Dict, List, Optional


def _build_chain(pseudocode: str, start: str, direction: str) -> List[str]:
    """构造溯源链: direction='fwd' 沿 def-use, 'bwd' 沿 use-def 回溯."""
    chain: List[str] = []
    cur = start
    seen = set()
    lines = pseudocode.splitlines()
    seq = (list(enumerate(lines)) if direction == "fwd"
           else list(reversed(list(enumerate(lines)))))
    for _i, line in seq:
        if cur in seen:
            break
        seen.add(cur)
        chain.append(cur)
        m = re.search(r"\b(\w+)\s*=\s*([^;]+)", line)
        if not m:
            continue
        lhs, rhs = m.group(1), m.group(2)
        if direction == "fwd" and re.search(r"\b" + re.escape(cur) + r"\b", rhs):
            cur = lhs
        elif direction == "bwd" and lhs == cur:
            vars_in_rhs = re.findall(r"\b([a-z_]\w*)\b", rhs)
            if vars_in_rhs:
                cur = vars_in_rhs[0]
    return chain


def _roll_hash(seq: List[str]) -> int:
    """滚动哈希 (RK 风格)."""
    h = 0
    base = 131
    mod = (1 << 61) - 1
    for s in seq:
        h = (h * base + hash(s)) % mod
    return h


def run_chain_equiv_hash(
    pseudocode: str,
    func_name: str,
    existing_findings: Optional[List[dict]] = None,
) -> List[dict]:
    """溯源链等价哈希. 返回 findings."""
    findings: List[dict] = []
    m_alloc = re.search(
        r"\b(\w+)\s*=\s*(?:\([^)]*\)\s*)?(?:malloc|calloc|realloc)\s*\(",
        pseudocode)
    if not m_alloc:
        return findings
    alloc_var = m_alloc.group(1)
    alloc_chain = _build_chain(pseudocode, alloc_var, "fwd")
    alloc_hash = _roll_hash(alloc_chain)
    for ln, line in enumerate(pseudocode.splitlines(), 1):
        m = re.search(r"\[\s*(\w+)\s*(\+\s*\d+)?\]\s*(?:,|=)\s*(\w+)", line)
        if not m:
            continue
        write_var = m.group(3)
        write_chain = _build_chain(pseudocode, write_var, "bwd")
        write_hash = _roll_hash(write_chain)
        equiv = (alloc_hash == write_hash)
        findings.append({
            "type": "heap_overflow",
            "function": func_name or "unknown",
            "severity": "medium",
            "cwe": "CWE-122",
            "confidence": 0.9 if equiv else 0.4,
            "description": f"line{ln} alloc_hash={alloc_hash} "
                           f"write_hash={write_hash} equiv={equiv}",
            "verdict": "equiv_safe" if equiv else "not_equiv",
            "source": "chain_equiv_hash",
        })
    return findings


if __name__ == "__main__":
    demo = """\
p = malloc(64);
q = p;
r = q;
mov [r+8], 0;
"""
    out = run_chain_equiv_hash(demo, "demo")
    for f in out:
        print(f["description"], f["verdict"])