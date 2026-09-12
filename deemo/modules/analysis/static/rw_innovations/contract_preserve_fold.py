"""ContractPreserveFold - 契约保持折叠 (stage 72).

多个告警若共享同一 alloc 契约 (同 alloc 点 + 同 usable), 证据折叠成
组, 组内一票否决 (任一 OVERFLOW 全组保留). 与 ACFPC 五证据不同:
分组折叠一票否决.

设计决策:
  - 契约键 = (alloc 变量, alloc 大小)
  - 把 findings 按契约键分组
  - 组内任一 finding verdict=overflow -> 全组保留 (一票否决)
  - 否则全组折叠为代表性条目
"""

import re
from typing import Dict, List, Optional, Tuple


def _contract_key(pseudocode: str, var: str) -> Optional[Tuple[str, int]]:
    """提取 (分配变量, 分配大小) 契约键."""
    m = re.search(
        r"\b" + re.escape(var) + r"\s*=\s*(?:\([^)]*\)\s*)?"
        r"(?:malloc|calloc|realloc)\s*\(\s*(\d+)\s*\)", pseudocode)
    if not m:
        return None
    return (var, int(m.group(1)))


def run_contract_preserve_fold(
    pseudocode: str,
    func_name: str,
    existing_findings: Optional[List[dict]] = None,
) -> List[dict]:
    """契约保持折叠. 返回 findings."""
    findings: List[dict] = []
    # 从伪代码收集 (var, size) 契约
    contracts = {}
    for m in re.finditer(
            r"\b(\w+)\s*=\s*(?:\([^)]*\)\s*)?(?:malloc|calloc|realloc)"
            r"\s*\(\s*(\d+)\s*\)", pseudocode):
        contracts.setdefault((m.group(1), int(m.group(2))), [])
    targets = existing_findings or []
    if not targets:
        # 生成占位 finding: 每个契约一个
        for (var, size) in contracts:
            targets.append({
                "type": "heap_overflow", "function": func_name,
                "confidence": 0.5, "description": f"alloc {var} size {size}",
            })
    groups: Dict[Tuple[str, int], List[dict]] = {}
    for f in targets:
        desc = f.get("description", "")
        key = None
        for (var, size) in contracts:
            if var in desc:
                key = (var, size)
                break
        if key is None:
            # 无法归组 -> 原样保留
            findings.append(f)
            continue
        groups.setdefault(key, []).append(f)
    for key, members in groups.items():
        has_overflow = any(
            m.get("verdict") == "overflow"
            or m.get("confidence", 0) >= 0.8
            for m in members)
        if has_overflow:
            # 一票否决: 全组保留原样
            findings.extend(members)
        else:
            # 折叠为一个代表性条目
            rep = dict(members[0])
            rep["description"] = (f"contract({key[0]},{key[1]}) folded "
                                  f"{len(members)} findings")
            rep["verdict"] = "folded"
            rep["source"] = "contract_preserve_fold"
            findings.append(rep)
    return findings


if __name__ == "__main__":
    demo = """\
p = malloc(64);
q = malloc(64);
"""
    out = run_contract_preserve_fold(
        demo, "demo",
        [
            {"type": "heap_overflow", "confidence": 0.7,
             "description": "alloc p size 64 write overflow"},
            {"type": "heap_overflow", "confidence": 0.9,
             "description": "alloc p size 64 write overflow2"},
        ])
    for f in out:
        print(f["description"], f.get("verdict"))