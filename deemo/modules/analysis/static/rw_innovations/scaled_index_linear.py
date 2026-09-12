"""ScaledIndexLinear - scaled-index 线性化 (stage 62).

对 [base+idx*scale+off] 写地址做 scale 相容性判定, 若 idx 的
区间宽度可整除 scale 且 base+off 落在分配内则安全.
与 octagon 差界不同: 显式 scale 相容性数学.

设计决策:
  - 解析写地址 [base + idx*scale + off]
  - 分配大小 alloc_size 已知
  - idx 区间 [lo, hi], 宽度 = hi - lo + 1
  - 若 宽度 % scale == 0 且 base+off + (hi-lo)*scale <= alloc 则安全
"""

import re
from typing import List, Optional, Tuple


def _parse_indexed(addr: str) -> Optional[Tuple[str, str, int, int]]:
    """解析 [base + idx*scale + off] -> (base, idx, scale, off)."""
    m = re.fullmatch(
        r"\s*(\w+)\s*\+\s*(\w+)\s*\*\s*(\d+)\s*\+\s*(-?\d+)\s*", addr)
    if m:
        return m.group(1), m.group(2), int(m.group(3)), int(m.group(4))
    m2 = re.fullmatch(r"\s*(\w+)\s*\+\s*(\w+)\s*\*\s*(\d+)\s*", addr)
    if m2:
        return m2.group(1), m2.group(2), int(m2.group(3)), 0
    return None


def run_scaled_index_linear(
    pseudocode: str,
    func_name: str,
    existing_findings: Optional[List[dict]] = None,
) -> List[dict]:
    """scaled-index 线性化判定. 返回 findings."""
    findings: List[dict] = []
    alloc_size: Optional[int] = None
    m_alloc = re.search(r"malloc\s*\(\s*(\d+)\s*\)", pseudocode)
    if m_alloc:
        alloc_size = int(m_alloc.group(1))
    for ln, line in enumerate(pseudocode.splitlines(), 1):
        m = re.search(r"\[([^\]]+)\]\s*=", line)
        if not m:
            continue
        parsed = _parse_indexed(m.group(1))
        if not parsed:
            continue
        base, idx, scale, off = parsed
        # idx 区间估计: 常量 -> [v,v]; 否则默认 [0, alloc/scale]
        m_idx = re.search(r"\b" + re.escape(idx) + r"\s*=\s*(\d+)", pseudocode)
        if m_idx:
            lo = hi = int(m_idx.group(1))
        else:
            lo, hi = 0, (alloc_size // scale if alloc_size else 0)
        width = hi - lo + 1
        if alloc_size is not None and width % scale == 0:
            end = base + off + hi * scale
            verdict = "safe" if end <= alloc_size else "overflow"
        else:
            verdict = "unknown"
        findings.append({
            "type": "heap_overflow",
            "function": func_name or "unknown",
            "severity": "medium",
            "cwe": "CWE-122",
            "confidence": 0.9 if verdict == "safe" else (0.7 if verdict == "overflow" else 0.4),
            "description": (
                f"line{ln} [base={base} idx={idx} scale={scale} off={off}] "
                f"width={width} -> {verdict}"
            ),
            "verdict": verdict,
            "source": "scaled_index_linear",
        })
    return findings


if __name__ == "__main__":
    demo = """\
p = malloc(128);
idx = 2;
mov [p + idx*8 + 0], 0;
"""
    out = run_scaled_index_linear(demo, "demo")
    for item in out:
        print(item["description"], item["verdict"])