"""CrossTypeEvidencePool - 跨类型证据池 (stage 85).

五类漏洞共享证据池, 同一函数多类型告警互相印证 (同函数 heap+fmt
告警 -> 双方 conf+0.1). 与 cross_pipeline 贝叶斯不同: 类型间互证
而非后验.

设计决策:
  - 证据池: {函数名: {漏洞类型集合}}
  - 同一函数出现 >=2 种类型告警时, 各类型 conf 提升 0.1
  - 单类型不提升
"""

import re
from typing import Dict, List, Optional, Set

_VULN_TYPES = ("heap_overflow", "use_after_free",
               "format_string", "integer_overflow", "double_free")


def run_cross_type_evidence_pool(
    pseudocode: str,
    func_name: str,
    existing_findings: Optional[List[dict]] = None,
) -> List[dict]:
    """跨类型证据池. 返回 findings."""
    findings: List[dict] = []
    ev = _pool_evidence(pseudocode, func_name)
    targets = existing_findings or []
    if not targets:
        for t in sorted(ev):
            targets.append({"type": t, "confidence": 0.5})
    n_types = len(ev)
    boost = 0.1 if n_types >= 2 else 0.0
    for f in targets:
        out = dict(f)
        if boost > 0 and f.get("type") in ev:
            out["confidence"] = round(min(1.0, out.get("confidence", 0.5) + boost), 2)
        out["source"] = "cross_type_evidence_pool"
        findings.append(out)
    return findings


def _pool_evidence(pseudocode: str, func_name: str) -> Set[str]:
    """收集伪代码中的漏洞类型证据."""
    ev: Set[str] = set()
    if re.search(r"malloc|calloc|realloc", pseudocode):
        ev.add("heap_overflow")
    if re.search(r"\bfree\s*\(", pseudocode):
        ev.add("use_after_free")
    if "%" in pseudocode:
        ev.add("format_string")
    if re.search(r"<<|>>", pseudocode):
        ev.add("integer_overflow")
    # 同一函数内 free 出现两次以上 -> double_free 证据
    if pseudocode.count("free(") >= 2:
        ev.add("double_free")
    return ev


if __name__ == "__main__":
    demo = """\
p = malloc(16);
printf("%s", p);
"""
    out = run_cross_type_evidence_pool(
        demo, "demo",
        [
            {"type": "heap_overflow", "confidence": 0.6},
            {"type": "format_string", "confidence": 0.6},
        ])
    for f in out:
        print(f["type"], f["confidence"], f["source"])