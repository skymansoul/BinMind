"""AffineMeetDomain - 仿射 meet 区间域 (stage 99).

区间域 meet/join/widen 仿射语义. 与 widen_threshold (stage 87) 不同:
本模块在仿射表达式 x = a*base + b 上做 meet/join 而非单纯常量区间.

设计决策:
  - 从 malloc(N)/calloc(M,N)/realloc(ptr,N) 解析实际分配大小构建分配区间
  - 无分配点时保守使用 [0, 2^31-1] 作为默认区间
  - meet(交): 取两个区间交集, 空 -> 空区间 (矛盾)
  - join(并): 取下界小者, 上界大者 (区间包络)
  - widen: 单边界扩张
  - 仿射表达式映射到区间后再做 meet, 多分配点分别判定
"""

import re
from typing import Dict, List, Optional, Tuple

# 无分配点时的保守默认上界: 2^31-1 (最大 32 位有符号整数)
_DEFAULT_MAX = 2**31 - 1


def _affine(line: str) -> Optional[Tuple[str, int, str, int]]:
    """解析 var = a*base + b 形式, 返回 (var, a, base_var, b)."""
    m = re.search(r"\b(\w+)\s*=\s*(\d+)\s*\*\s*(\w+)\s*\+\s*(\d+)", line)
    if m:
        return m.group(1), int(m.group(2)), m.group(3), int(m.group(4))
    m = re.search(r"\b(\w+)\s*=\s*(\w+)\s*\+\s*(\d+)", line)
    if m:
        return m.group(1), 1, m.group(2), int(m.group(3))
    return None


def _parse_alloc_sizes(pseudocode: str) -> List[Tuple[str, int]]:
    """从伪代码解析所有分配点的 (变量名, 分配大小).

    malloc(N) -> N
    calloc(M, N) -> M*N
    realloc(ptr, N) -> N
    """
    allocs: List[Tuple[str, int]] = []
    for line in pseudocode.splitlines():
        # malloc(N)
        m = re.search(
            r"\b(\w+)\s*=\s*(?:\([^)]*\)\s*)?malloc\s*\(\s*(\d+)\s*\)", line
        )
        if m:
            allocs.append((m.group(1), int(m.group(2))))
            continue
        # calloc(M, N) -> M*N
        m = re.search(
            r"\b(\w+)\s*=\s*(?:\([^)]*\)\s*)?calloc\s*\(\s*(\d+)\s*,\s*(\d+)\s*\)",
            line,
        )
        if m:
            allocs.append((m.group(1), int(m.group(2)) * int(m.group(3))))
            continue
        # realloc(ptr, N) -> N
        m = re.search(
            r"\b(\w+)\s*=\s*(?:\([^)]*\)\s*)?realloc\s*\(\s*\w+\s*,\s*(\d+)\s*\)",
            line,
        )
        if m:
            allocs.append((m.group(1), int(m.group(2))))
    return allocs


def _meet(a: Tuple[int, int], b: Tuple[int, int]) -> Optional[Tuple[int, int]]:
    """区间 meet: 交集."""
    lo = max(a[0], b[0])
    hi = min(a[1], b[1])
    return (lo, hi) if lo <= hi else None


def _join(a: Tuple[int, int], b: Tuple[int, int]) -> Tuple[int, int]:
    """区间 join: 包络."""
    return (min(a[0], b[0]), max(a[1], b[1]))


def run_affine_meet_domain(
    pseudocode: str,
    func_name: str,
    existing_findings: Optional[List[dict]] = None,
) -> List[dict]:
    """仿射 meet/join 区间域. 返回 findings."""
    findings: List[dict] = []
    ranges: Dict[str, Tuple[int, int]] = {}
    for line in pseudocode.splitlines():
        m = re.search(r"\b(\w+)\s*=\s*(\d+)", line)
        if m and m.group(1) not in ranges:
            ranges[m.group(1)] = (int(m.group(2)), int(m.group(2)))
    affines = []
    for line in pseudocode.splitlines():
        a = _affine(line)
        if a:
            affines.append(a)
    # 解析实际分配大小, 构建分配区间列表
    allocs = _parse_alloc_sizes(pseudocode)
    if allocs:
        alloc_ranges = [(0, size) for _, size in allocs]
    else:
        alloc_ranges = [(0, _DEFAULT_MAX)]
    for ln, line in enumerate(pseudocode.splitlines(), 1):
        m = re.search(r"\[\s*(\w+)\s*\+\s*(\w+)\s*\]\s*(?:,|=)", line)
        if not m:
            continue
        var, idx = m.group(1), m.group(2)
        base = ranges.get(idx)
        # 找含 idx 的仿射表达式 (即使 idx 无直接区间也可用)
        ex = None
        for name, mult, base_var, const in affines:
            if name == idx:
                ex = (mult, base_var, const)
                break
        if ex is None:
            if base is None:
                continue
            ex = (1, idx, 0)
        if base is None:
            base = ranges.get(ex[1])
        if base is None:
            continue
        # 仿射映射: idx 落在 [lo,hi] -> 写偏移 [mult*lo+const, mult*hi+const]
        # 负乘数时区间可能反向, 用 min/max 确保正确顺序
        lo, hi = base
        wlo = ex[0] * lo + ex[2]
        whi = ex[0] * hi + ex[2]
        wlo, whi = min(wlo, whi), max(wlo, whi)
        merged = _join(ranges.get(var, (wlo, whi)), (wlo, whi))
        # 对每个分配点分别做 meet 判定
        best_meet: Optional[Tuple[int, int]] = None
        best_alloc_range: Tuple[int, int] = (0, _DEFAULT_MAX)
        for ar in alloc_ranges:
            meet_result = _meet(merged, ar)
            if meet_result is not None:
                if best_meet is None or meet_result[1] < best_meet[1]:
                    best_meet = meet_result
                    best_alloc_range = ar
        if best_meet is not None:
            verdict = "affine_bounded"
            meet_str = str(best_meet)
            confidence = 0.75
        else:
            verdict = "affine_top"
            meet_str = "None"
            confidence = 0.3
        findings.append({
            "type": "heap_overflow",
            "function": func_name or "unknown",
            "severity": "medium",
            "cwe": "CWE-122",
            "confidence": confidence,
            "description": f"line{ln} idx={idx} base={base} affine={ex} "
                           f"write=[{wlo},{whi}] alloc={best_alloc_range} "
                           f"meet={meet_str}",
            "verdict": verdict,
            "source": "affine_meet_domain",
        })
    return findings


if __name__ == "__main__":
    demo = """\
p = malloc(64);
i = 0;
j = 2 * i + 4;
mov [p+j], 0;
"""
    out = run_affine_meet_domain(demo, "demo")
    for f in out:
        print(f["description"], f["verdict"])
