"""RdataConstRegion - .rdata 常量区判定 (stage 76).

格式串来源解析为 rodata 段地址 -> 常量安全. 与 FMT-SPEC 解析不同:
存储区域级别判定.

设计决策:
  - 识别伪代码中格式串所在地址/区域标注
  - 若格式串来自 .rdata/.rodata/.const 段 -> 常量安全
  - 来自栈/堆/可变区 -> 潜在风险
"""

import re
from typing import List, Optional

_CDATA_REGIONS = (".rdata", ".rodata", ".const", "rodata", "rdata")


def run_rdata_const_region(
    pseudocode: str,
    func_name: str,
    existing_findings: Optional[List[dict]] = None,
) -> List[dict]:
    """rdata 常量区判定. 返回 findings."""
    findings: List[dict] = []
    # 先扫描整个伪代码里的 rdata 段标注地址 (常量区基址)
    rdata_hits = [i for i, line in enumerate(pseudocode.splitlines(), 1)
                  if any(rn in line.lower() for rn in _CDATA_REGIONS)]
    for ln, line in enumerate(pseudocode.splitlines(), 1):
        # 找格式串调用 printf/sprintf/format (call printf; 或 printf(...))
        if not re.search(r"\b(printf|sprintf|snprintf|fprintf)\b", line):
            continue
        # 格式串来源: 字面量 / 段标注 / 变量
        src = "literal" if re.search(r'["\']', line) else "variable"
        region = next((rn for rn in _CDATA_REGIONS
                       if rn in line.lower()), None)
        # 若调用行本身无标注, 但该格式串来自前面 lea 的 rdata 地址
        if region is None and rdata_hits and src == "variable":
            # 前若干行出现过 rdata -> 视为常量区来源
            for hit_ln in rdata_hits:
                if hit_ln < ln:
                    region = ".rdata"
                    break
        if src == "literal" or region:
            verdict, conf = "const_safe", 0.9
        else:
            verdict, conf = "mutable", 0.5
        findings.append({
            "type": "format_string",
            "function": func_name or "unknown",
            "severity": "low" if verdict == "const_safe" else "medium",
            "cwe": "CWE-134",
            "confidence": conf,
            "description": f"line{ln} src={src} region={region}",
            "verdict": verdict,
            "source": "rdata_const_region",
        })
    return findings


if __name__ == "__main__":
    demo = """\
lea rdi, [.rdata+0x10];
call printf;
"""
    out = run_rdata_const_region(demo, "demo")
    for f in out:
        print(f["description"], f["verdict"])