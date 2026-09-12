"""ReductionRateAudit - 削减率审计 (stage 92).

对管线每阶段过滤量做自审计, 过滤率 >70% 的阶段触发二次核验
(重新跑保守版). 与全部模块不同: 管线元审计.

设计决策:
  - 输入: 各阶段过滤量统计 {阶段: (输入数, 过滤数)}
  - 过滤率 = 过滤数 / 输入数
  - >70% -> 触发二次核验 (保守重跑标记)
  - 输出审计 finding
"""

import re
from typing import Dict, List, Optional

_THRESHOLD = 0.7


def run_reduction_rate_audit(
    pseudocode: str,
    func_name: str,
    existing_findings: Optional[List[dict]] = None,
    stage_stats: Optional[Dict[str, tuple]] = None,
) -> List[dict]:
    """削减率审计. 返回 findings."""
    findings: List[dict] = []
    # 从伪代码注释中解析阶段统计: # stage: in=10 filtered=8
    if stage_stats is None:
        stage_stats = {}
        for line in pseudocode.splitlines():
            m = re.search(r"#\s*(\w+):\s*in=(\d+)\s*filtered=(\d+)", line)
            if m:
                stage_stats[m.group(1)] = (int(m.group(2)), int(m.group(3)))
    if not stage_stats:
        # 无统计时生成一个汇总审计条目
        findings.append({
            "type": "meta_audit",
            "function": func_name or "unknown",
            "severity": "low",
            "cwe": "CWE-000",
            "confidence": 0.3,
            "description": "no stage stats provided",
            "verdict": "no_data",
            "source": "reduction_rate_audit",
        })
        return findings
    for stage, (inp, filt) in stage_stats.items():
        if inp == 0:
            continue
        rate = filt / inp
        if rate > _THRESHOLD:
            verdict, conf = "recheck", 0.9
        else:
            verdict, conf = "ok", 0.6
        findings.append({
            "type": "meta_audit",
            "function": func_name or "unknown",
            "severity": "low",
            "cwe": "CWE-000",
            "confidence": conf,
            "description": f"stage={stage} in={inp} filtered={filt} "
                           f"rate={rate:.2f}",
            "verdict": verdict,
            "source": "reduction_rate_audit",
        })
    return findings


if __name__ == "__main__":
    demo = """\
# stage_a: in=10 filtered=9
# stage_b: in=10 filtered=2
"""
    out = run_reduction_rate_audit(demo, "demo")
    for f in out:
        print(f["description"], f["verdict"])