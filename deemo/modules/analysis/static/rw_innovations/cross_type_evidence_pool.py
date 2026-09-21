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
    """跨类型证据池. 返回 findings.

    就地加工 (in-place) 而非重建: 基础检测器 findings 保持对象身份,
    RW 弱告警打标 (innovation_bridge 按对象身份判定新注入) 不会把
    互证副本误标为弱告警; 重建 (dict(f)) 会产生新对象, 新对象按身份
    判定属于"RW 新注入"而被打 rw_weak, 基础检出被误杀成漏报.
    """
    targets = existing_findings or []
    if not targets:
        # 无既有 findings 时返回空: "伪代码里出现 malloc/free/% 即注入证据
        # 类型" 的自检逻辑把任意含堆操作的反编译函数判为漏洞证据, 会污染
        # 检出计数 (guard 保护的 safe 样本也命中). 证据池的语义是"对既有
        # 告警互证提升", 无告警时不产生新告警.
        return targets
    # 互证基于 findings 中的实际类型集合, 而非伪代码特征
    finding_types = {f.get("type", "") for f in targets if f.get("type")}
    boost = 0.1 if len(finding_types) >= 2 else 0.0
    for f in targets:
        if boost > 0 and f.get("type") in finding_types:
            f["confidence"] = round(min(1.0, f.get("confidence", 0.5) + boost), 2)
        f["source"] = "cross_type_evidence_pool"
    return targets


#[DEPRECATED] 自检注入逻辑已移除 (无既有 finding 时不产生新告警), 函数保留
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