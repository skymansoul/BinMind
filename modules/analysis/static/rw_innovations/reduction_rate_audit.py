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


def _c_audit(pseudocode: str, func_name: str) -> list:
    """C 风格减除率审计: 写长 vs 分配容量."""
    import re
    results = []
    # 常量分配
    m_alloc = re.search(r"(\w+)\s*=\s*(?:\([^)]*\)\s*)?malloc\s*\(\s*(\d+)\s*\)", pseudocode)
    alloc_const = int(m_alloc.group(2)) if m_alloc else None
    alloc_var = m_alloc.group(1) if m_alloc else None
    # 符号分配 malloc(n) / malloc(n*mul)
    m_sym = re.search(r"(\w+)\s*=\s*(?:\([^)]*\)\s*)?malloc\s*\(\s*(\w+)\s*\)", pseudocode)
    alloc_sym = m_sym.group(2) if m_sym and not m_alloc else None
    m_mul = re.search(r"malloc\s*\(\s*(\w+)\s*\*\s*(\d+)\s*\)", pseudocode)
    alloc_sym_mul = (m_mul.group(1), int(m_mul.group(2))) if m_mul else None
    # memcpy 写长
    m_mc = re.search(r"\bmemcpy\s*\(\s*(\w+)\s*,\s*\w+\s*,\s*(\d+)\s*\)", pseudocode)
    if m_mc and alloc_const is not None and m_mc.group(1) == alloc_var:
        write_sz = int(m_mc.group(2))
        rate = (write_sz - alloc_const) / max(write_sz, 1)
        verdict = "recheck" if write_sz > alloc_const else "ok"
        results.append((verdict, 0.9 if verdict == "recheck" else 0.6, f"memcpy_size={write_sz} alloc={alloc_const} rate={rate:.2f}"))
    # 下标写偏移
    m_idx = re.search(r"\b(\w+)\[\s*(\w+)\s*\+\s*(\d+)\s*\]\s*=", pseudocode)
    if m_idx and alloc_sym is not None and m_idx.group(2) == alloc_sym:
        results.append(("recheck", 0.9, f"index {alloc_sym}+{m_idx.group(3)} exceeds alloc({alloc_sym})"))
    # 归纳变量直接下标 + n*mul 分配 -> ok
    m_loop = re.search(r"for\s*\(\s*(\w+)\s*=\s*\d+\s*;\s*\1\s*<\s*(\w+)\s*;", pseudocode)
    m_direct = re.search(r"\b(\w+)\[\s*(\w+)\s*\]\s*=", pseudocode)
    if m_loop and m_direct and alloc_sym_mul is not None:
        if m_loop.group(2) == alloc_sym_mul[0] and m_direct.group(2) == m_loop.group(1):
            results.append(("ok", 0.6, f"loop_var={m_loop.group(1)} bounded by {alloc_sym_mul[0]}*{alloc_sym_mul[1]}"))
    return results


def run_reduction_rate_audit(
    pseudocode: str,
    func_name: str,
    existing_findings: Optional[List[dict]] = None,
    stage_stats: Optional[Dict[str, tuple]] = None,
) -> List[dict]:
    """削减率审计. 返回 findings."""
    findings: List[dict] = []
    # C 风格优先
    c_results = _c_audit(pseudocode, func_name)
    if c_results:
        for verdict, conf, desc in c_results:
            findings.append({
                "type": "heap_overflow" if verdict == "recheck" else "meta_audit",
                "function": func_name or "unknown",
                "severity": "medium" if verdict == "recheck" else "low",
                "cwe": "CWE-122" if verdict == "recheck" else "CWE-000",
                "confidence": conf,
                "description": desc + " mode=c",
                "verdict": verdict,
                "source": "reduction_rate_audit",
            })
        return findings
    # 汇编风格回退: 从伪代码注释中解析阶段统计
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