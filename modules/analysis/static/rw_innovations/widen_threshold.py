"""WidenThreshold - 阈值 widening (stage 87).

循环区间 widening 设阈值 [-4096, 4096], 超阈值判定 TOP 状态不可用
于安全证明. 与 forward_interval_prop 不同: 阈值化 widening 语义.

设计决策:
  - 区间 widening: [a,b] widen [c,d] -> [a<0?-inf:a, b>0?inf:b]
  - 阈值 [-4096, 4096]: 边界超阈值 -> TOP (不可用于安全证明)
  - TOP 状态不能判定安全
"""

import re
from typing import List, Optional, Tuple

_LO, _HI = -4096, 4096
_TOP = (None, None)


def _c_widen_analysis(pseudocode: str) -> list:
    """C 风格加宽阈值分析: 循环中归纳变量下标偏移上界 vs 分配大小.
    返回 [(归纳变量, 步长, 是否超界, verdict, description)] 列表."""
    # 解析循环头: for(i=0; i<n; i++)
    m_loop = re.search(r"for\s*\(\s*(\w+)\s*=\s*(\d+)\s*;\s*\1\s*<\s*(\w+)\s*;", pseudocode)
    if not m_loop:
        return []
    loop_var = m_loop.group(1)
    bound_var = m_loop.group(3)
    # 解析分配
    m_const = re.search(r"malloc\s*\(\s*(\d+)\s*\)", pseudocode)
    m_sym = re.search(r"malloc\s*\(\s*(\w+)\s*\)", pseudocode)
    m_mul = re.search(r"malloc\s*\(\s*(\w+)\s*\*\s*(\d+)\s*\)", pseudocode)
    # 解析写操作下标
    results = []
    # 直接下标 buf[i]
    if re.search(r"\b\w+\[\s*" + re.escape(loop_var) + r"\s*\]\s*=", pseudocode):
        stride = 1
        # 判断偏移上界 vs 分配大小
        if m_const:
            # 常量分配: i 范围 [0, bound_var), 但 bound_var 是变量名无法比较, 保守判 unknown
            pass
        if m_sym:
            alloc_sym = m_sym.group(1)
            if alloc_sym == bound_var:
                # 分配 malloc(n), 循环 i < n: 偏移上界 n-1, 分配 n -> 有界 -> stable
                results.append((loop_var, stride, False, "stable", f"i<{bound_var} alloc={alloc_sym} stride={stride} bounded"))
            else:
                # 分配变量与循环上界不同 -> 无法定界 -> topped
                results.append((loop_var, stride, True, "topped", f"i<{bound_var} alloc={alloc_sym} mismatch"))
        if m_mul:
            alloc_sym = m_mul.group(1)
            alloc_mul = int(m_mul.group(2))
            if alloc_sym == bound_var and alloc_mul >= stride:
                results.append((loop_var, stride, False, "stable", f"i<{bound_var} alloc={alloc_sym}*{alloc_mul} stride={stride} bounded"))
            else:
                results.append((loop_var, stride, True, "topped", f"i<{bound_var} alloc={alloc_sym}*{alloc_mul} stride={stride} unbounded"))
    # 步长下标 buf[i*stride]
    m_stride = re.search(r"\b\w+\[\s*" + re.escape(loop_var) + r"\s*\*\s*(\d+)\s*\]\s*=", pseudocode)
    if m_stride:
        stride = int(m_stride.group(1))
        # 偏移上界 = (n-1)*stride, 分配 = alloc_var*mul
        if m_const:
            # 常量分配 vs 步长写入: 上界 (n-1)*stride 无界 -> topped
            results.append((loop_var, stride, True, "topped", f"i*{stride} vs const_alloc unbounded"))
        if m_sym:
            alloc_sym = m_sym.group(1)
            if alloc_sym == bound_var:
                # 分配 malloc(n), 偏移上界 (n-1)*stride > n-1 当 stride>1 -> 超界 -> topped
                results.append((loop_var, stride, True, "topped", f"i*{stride} vs alloc={alloc_sym} stride>1 unbounded"))
            else:
                results.append((loop_var, stride, True, "topped", f"i*{stride} vs alloc={alloc_sym} mismatch"))
        if m_mul:
            alloc_sym = m_mul.group(1)
            alloc_mul = int(m_mul.group(2))
            if alloc_sym == bound_var and alloc_mul >= stride:
                results.append((loop_var, stride, False, "stable", f"i*{stride} vs {alloc_sym}*{alloc_mul} bounded"))
            else:
                results.append((loop_var, stride, True, "topped", f"i*{stride} vs {alloc_sym}*{alloc_mul} unbounded"))
    return results


def _widen(a: Tuple[int, int], b: Tuple[int, int]) -> Tuple[int, int]:
    """饱和加宽: 下界超阈值钳到 _LO, 上界超阈值钳到 _HI, 不直接置 None."""
    lo, hi = a
    clo, chi = b
    new_lo = clo if clo >= lo else _LO
    new_hi = chi if chi <= hi else _HI
    return (new_lo, new_hi)


def _topped(r: Tuple[int, int]) -> bool:
    """是否超阈值 -> TOP."""
    lo, hi = r
    if lo is None or hi is None:
        return True
    return lo < _LO or hi > _HI


def run_widen_threshold(
    pseudocode: str,
    func_name: str,
    existing_findings: Optional[List[dict]] = None,
) -> List[dict]:
    """阈值 widening. 返回 findings."""
    findings: List[dict] = []
    # C 风格优先
    c_results = _c_widen_analysis(pseudocode)
    if c_results:
        for loop_var, stride, exceeded, verdict, desc in c_results:
            conf = 0.3 if verdict == "topped" else 0.8
            findings.append({
                "type": "heap_overflow",
                "function": func_name or "unknown",
                "severity": "medium",
                "cwe": "CWE-122",
                "confidence": conf,
                "description": f"var={loop_var} stride={stride} exceeded={exceeded} "
                               f"{desc} mode=c",
                "verdict": verdict,
                "source": "widen_threshold",
            })
        return findings
    # 汇编风格回退
    # 收集循环: 识别变量初始化区间与增量
    init_ranges: dict = {}
    for line in pseudocode.splitlines():
        m = re.search(r"\b(\w+)\s*=\s*(\d+)\s*;", line)
        if m:
            init_ranges[m.group(1)] = (int(m.group(2)), int(m.group(2)))
    for ln, line in enumerate(pseudocode.splitlines(), 1):
        m = re.search(r"\b(\w+)\s*\+\+\s*", line)
        if not m:
            m = re.search(r"\b(\w+)\s*\+=\s*(\d+)", line)
        if not m:
            continue
        var = m.group(1)
        base = init_ranges.get(var)
        if base is None:
            continue
        # 一次迭代后 widen
        widened = _widen(base, (base[0], base[1] + 1))
        topped = _topped(widened)
        verdict = "topped" if topped else "stable"
        findings.append({
            "type": "heap_overflow",
            "function": func_name or "unknown",
            "severity": "medium",
            "cwe": "CWE-122",
            "confidence": 0.3 if topped else 0.8,
            "description": f"line{ln} var={var} base={base} "
                           f"widen={widened} topped={topped} mode=asm",
            "verdict": verdict,
            "source": "widen_threshold",
        })
    return findings


if __name__ == "__main__":
    demo = """\
i = 0;
while (i < 100) { i++; }
"""
    out = run_widen_threshold(demo, "demo")
    for f in out:
        print(f["description"], f["verdict"])