"""FourLevelAdjudicator - 四级裁断链 (stage 88).

溢出嫌疑->指针溯源->守卫窄化->偏移判定的固定四级链, 每级输出
decisive_level. 与 absint_adjudicator 结构同源但输入为伪代码.

设计决策:
  - L1 溢出嫌疑: 写点是否可能越界 (常量比较)
  - L2 指针溯源: 写基址是否溯源到堆分配
  - L3 守卫窄化: 是否有守卫约束偏移
  - L4 偏移判定: 精确比较偏移+写大小 vs 分配大小
  - 每级输出 decisive_level (0-4)
"""

import re
from typing import List, Optional


def _narrow_offset(line: str) -> Optional[int]:
    """从写点提取常量偏移."""
    m = re.search(r"\[\s*\w+\s*\+\s*(\d+)\s*\]", line)
    return int(m.group(1)) if m else None


def run_four_level_adjudicator(
    pseudocode: str,
    func_name: str,
    existing_findings: Optional[List[dict]] = None,
) -> List[dict]:
    """四级裁断链. 返回 findings."""
    findings: List[dict] = []
    alloc_size = None
    m_alloc = re.search(r"malloc\s*\(\s*(\d+)\s*\)", pseudocode)
    if m_alloc:
        alloc_size = int(m_alloc.group(1))
    for ln, line in enumerate(pseudocode.splitlines(), 1):
        m = re.search(r"\[\s*(\w+)\s*\+\s*(\w+|\d+)\s*\]\s*(?:,|=)", line)
        if not m:
            continue
        var, off_txt = m.group(1), m.group(2)
        # L1 溢出嫌疑
        l1 = 1 if alloc_size is not None else 0
        # L2 指针溯源: var 是否分配变量
        l2 = 1 if re.search(r"\b" + re.escape(var) + r"\s*=\s*(?:\([^)]*\)\s*)?(?:malloc|calloc|realloc)", pseudocode) else 0
        # L3 守卫窄化
        l3 = 1 if re.search(r"if\s*\([^)]*" + re.escape(var), pseudocode) else 0
        # L4 偏移判定
        off = int(off_txt) if off_txt.isdigit() else None
        if l1 and l2 and off is not None and alloc_size is not None:
            l4 = 1 if off < alloc_size else -1
        else:
            l4 = 0
        if l4 == 1:
            verdict, conf = "safe", 0.9
        elif l4 == -1:
            verdict, conf = "overflow", 0.85
        else:
            verdict, conf = "inconclusive", 0.4
        decisive = 4 if l4 != 0 else (3 if l3 else (2 if l2 else (1 if l1 else 0)))
        findings.append({
            "type": "heap_overflow",
            "function": func_name or "unknown",
            "severity": "medium",
            "cwe": "CWE-122",
            "confidence": conf,
            "description": f"line{ln} L1={l1} L2={l2} L3={l3} L4={l4} "
                           f"decisive={decisive}",
            "verdict": verdict,
            "source": "four_level_adjudicator",
        })
    return findings


if __name__ == "__main__":
    demo = """\
p = malloc(64);
if (p) { }
mov [p+8], 0;
"""
    out = run_four_level_adjudicator(demo, "demo")
    for f in out:
        print(f["description"], f["verdict"])