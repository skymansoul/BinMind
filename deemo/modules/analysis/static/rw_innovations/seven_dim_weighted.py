"""SevenDimWeighted - 七维加权融合 (stage 90).

7 个独立证据维度加权投票: 常量差/守卫/slack/循环/别名/污点/阈值,
任一 SAFE 一票否决. 与 GAPSBV 维度不同: 本模块维度独立且投票.

设计决策:
  - 七维: const_diff, guard, slack, loop, alias, taint, threshold
  - 每维输出 SAFE/UNSAFE/UNKNOWN
  - 任一 SAFE -> 一票否决整体安全
  - 否则加权投票决定
"""

import re
from typing import Dict, List, Optional

_DIMS = ("const_diff", "guard", "slack", "loop", "alias", "taint", "threshold")
_WEIGHTS = {"const_diff": 0.2, "guard": 0.2, "slack": 0.1, "loop": 0.1,
            "alias": 0.15, "taint": 0.1, "threshold": 0.15}


def _dim_evidence(pseudocode: str, var: str) -> Dict[str, str]:
    """计算七维证据."""
    ev: Dict[str, str] = {}
    # 常量差: 分配与写大小差
    m_alloc = re.search(r"malloc\s*\(\s*(\d+)\s*\)", pseudocode)
    m_write = re.search(r"\[\s*" + re.escape(var) + r"\s*\+\s*(\d+)\s*\]\s*(?:,|=)\s*(\d+)", pseudocode)
    if m_alloc and m_write:
        ev["const_diff"] = "SAFE" if int(m_write.group(2)) <= int(m_alloc.group(1)) else "UNSAFE"
    else:
        ev["const_diff"] = "UNKNOWN"
    # 守卫
    ev["guard"] = "SAFE" if re.search(r"if\s*\([^)]*" + re.escape(var), pseudocode) else "UNKNOWN"
    # slack
    ev["slack"] = "SAFE" if re.search(r"slack", pseudocode, re.I) else "UNKNOWN"
    # 循环
    ev["loop"] = "UNSAFE" if re.search(r"while|for", pseudocode) else "UNKNOWN"
    # 别名
    ev["alias"] = "SAFE" if re.search(r"\b\w+\s*=\s*" + re.escape(var), pseudocode) else "UNKNOWN"
    # 污点
    ev["taint"] = "UNSAFE" if re.search(r"scanf|recv|argv", pseudocode) else "UNKNOWN"
    # 阈值
    ev["threshold"] = "SAFE" if re.search(r"<=\s*(\d+)", pseudocode) else "UNKNOWN"
    return ev


def run_seven_dim_weighted(
    pseudocode: str,
    func_name: str,
    existing_findings: Optional[List[dict]] = None,
) -> List[dict]:
    """七维加权融合. 返回 findings."""
    findings: List[dict] = []
    # 分配变量
    alloc_vars = re.findall(
        r"\b(\w+)\s*=\s*(?:\([^)]*\)\s*)?(?:malloc|calloc|realloc)\s*\(",
        pseudocode)
    if not alloc_vars:
        return findings
    var = alloc_vars[0]
    ev = _dim_evidence(pseudocode, var)
    # 一票否决
    if any(v == "SAFE" for v in ev.values()):
        verdict, conf = "veto_safe", 0.95
    else:
        # 加权投票
        score = sum(_WEIGHTS[d] for d, v in ev.items() if v == "UNSAFE")
        verdict = "weighted_unsafe" if score >= 0.4 else "weighted_unknown"
        conf = round(score, 2)
    findings.append({
        "type": "heap_overflow",
        "function": func_name or "unknown",
        "severity": "medium",
        "cwe": "CWE-122",
        "confidence": conf,
        "description": f"var={var} evidence={ev}",
        "verdict": verdict,
        "source": "seven_dim_weighted",
    })
    return findings


if __name__ == "__main__":
    demo = """\
p = malloc(64);
if (p != NULL) { }
mov [p+8], 0x4;
"""
    out = run_seven_dim_weighted(demo, "demo")
    for f in out:
        print(f["description"], f["verdict"], f["confidence"])