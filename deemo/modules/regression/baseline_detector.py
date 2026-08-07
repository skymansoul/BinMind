"""
基线检测器 — 无 HFP 过滤的机械比较.

决策逻辑: 基线复刻现有 heap_overflow_detector 的核心比较
语义: store offset >= alloc_size 即告警, 不做对齐松弛、
不做守卫窄化、不做污点分析. 用于量化 HFP 的误报抑制增益:
  FPR 下降百分比 = (baseline_fpr - hfp_fpr) / baseline_fpr
基线仅用于对比, 不参与最终交付检测.
"""

from __future__ import annotations

import re
from typing import Dict, List

_RE_ALLOC = re.compile(
    r'(\w+)\s*=\s*(malloc|calloc|realloc)\s*\(\s*(\d+)\s*\)', re.IGNORECASE)
_RE_STORE = re.compile(
    r'\[(\w+)\s*\+\s*(0x[0-9a-fA-F]+|\d+)\]\s*(?:=|,)', re.IGNORECASE)
_RE_COPY = re.compile(
    r'(memcpy|memset|strcpy)\s*\(\s*(\w+)\s*,\s*\w+\s*,\s*(\d+)\s*\)',
    re.IGNORECASE)


def baseline_detect(asm_lines: List[str]) -> bool:
    """机械比较基线: 任一写点 offset >= alloc_size 即告警."""
    allocs = {}  # var -> size
    for line in asm_lines:
        m = _RE_ALLOC.search(line)
        if m:
            allocs[m.group(1)] = int(m.group(3), 0)
    if not allocs:
        return False
    for line in asm_lines:
        m = _RE_STORE.search(line)
        if m and m.group(1) in allocs:
            off = int(m.group(2), 0)
            if off >= allocs[m.group(1)]:
                return True
        m = _RE_COPY.search(line)
        if m and m.group(2) in allocs:
            size = int(m.group(3), 0)
            if size > allocs[m.group(2)]:
                return True
    return False


def baseline_scan_all(asm_files: List[str]) -> Dict[str, bool]:
    """对全部样本跑基线, 返回 sample -> detected."""
    out = {}
    for f in asm_files:
        name = f.split('\\')[-2]
        try:
            text = open(f, encoding='utf-8', errors='replace').read()
            out[name] = baseline_detect(text.splitlines())
        except Exception:
            out[name] = False
    return out
