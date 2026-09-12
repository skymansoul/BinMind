"""ScaledIndexLinear - scaled-index 线性化 (stage 62).

对 [base+idx*scale+off] 写地址做 scale 相容性判定, 若 idx 的
区间宽度可整除 scale 且 end = off + hi*scale 落在分配内则安全.
与 octagon 差界不同: 显式 scale 相容性数学.

设计决策:
  - 解析写地址 [base + idx*scale + off]
  - base 是变量名(字符串), 不参与数值运算; 实际越界比较用 off + hi*scale
  - idx 区间估计: 常量赋值 -> [v,v]; 守卫 if(idx<N) -> hi=N; 否则保守默认
  - end = off + hi * scale; end <= alloc_size -> safe; end > alloc_size -> overflow
  - 无 alloc_size 或 scale 不整除 -> unknown
"""

import re
from typing import List, Optional, Tuple


def _parse_indexed(addr: str) -> Optional[Tuple[str, str, int, int]]:
    """解析 [base + idx*scale + off] -> (base, idx, scale, off).
    base 为变量名(字符串), 仅用于标识, 不参与数值运算.
    """
    m = re.fullmatch(
        r"\s*(\w+)\s*\+\s*(\w+)\s*\*\s*(\d+)\s*\+\s*(-?\d+)\s*", addr)
    if m:
        return m.group(1), m.group(2), int(m.group(3)), int(m.group(4))
    m2 = re.fullmatch(r"\s*(\w+)\s*\+\s*(\w+)\s*\*\s*(\d+)\s*", addr)
    if m2:
        return m2.group(1), m2.group(2), int(m2.group(3)), 0
    return None


def _estimate_idx_bounds(
    pseudocode: str, idx: str, alloc_size: Optional[int], scale: int
) -> Tuple[int, int]:
    """估计 idx 的区间 [lo, hi].
    优先级: 常量赋值 > 守卫上界 > 保守默认.
    """
    # 常量赋值: idx = C
    m_idx = re.search(r"\b" + re.escape(idx) + r"\s*=\s*(\d+)", pseudocode)
    if m_idx:
        v = int(m_idx.group(1))
        return v, v
    # 守卫上界: if (idx < N) 提取 N 作为 hi
    m_guard = re.search(
        r"\bif\s*\(\s*" + re.escape(idx) + r"\s*<\s*(\d+)\s*\)", pseudocode
    )
    if m_guard:
        n = int(m_guard.group(1))
        return 0, n
    # 保守默认: alloc_size // scale
    default_hi = (alloc_size // scale) if alloc_size and scale else 0
    return 0, default_hi


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
        m = re.search(r"\[([^\]]+)\]\s*[,=]", line)
        if not m:
            continue
        parsed = _parse_indexed(m.group(1))
        if not parsed:
            continue
        base, idx, scale, off = parsed
        # base 是变量名, 不参与数值运算; 实际比较用 off + hi*scale
        lo, hi = _estimate_idx_bounds(pseudocode, idx, alloc_size, scale)
        width = hi - lo + 1
        is_const_idx = (lo == hi)
        if alloc_size is not None:
            if is_const_idx:
                # 常量索引: 直接数值比较, 不要求 width % scale == 0
                end = off + hi * scale
            elif width % scale == 0:
                # 变量索引且宽度整除 scale: 越界判断
                end = off + hi * scale
            else:
                end = None
            if end is not None:
                verdict = "safe" if end <= alloc_size else "overflow"
            else:
                verdict = "unknown"
        else:
            end = None
            verdict = "unknown"
        findings.append({
            "type": "heap_overflow",
            "function": func_name or "unknown",
            "severity": "medium",
            "cwe": "CWE-122",
            "confidence": 0.9 if verdict == "safe" else (0.7 if verdict == "overflow" else 0.4),
            "description": (
                f"line{ln} [base={base} idx={idx} scale={scale} off={off}] "
                f"width={width} end={end if end is not None else '?'} -> {verdict}"
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