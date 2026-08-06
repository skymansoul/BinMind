# [DEPRECATED] — 功能已迁移至 modules/info/analysis/taint_propagation.py 或 src/taint_propagation.py
# 若确认无外部引用, 可安全删除
# Taint propagation for heap allocation size tracking
# Lightweight backward data-flow analysis from write sites to malloc sites
from __future__ import annotations
from typing import Dict, List, Tuple, Optional
import re

def extract_allocation_sites(code):
    allocs = {}
    pat = r"(\w+)\s*=\s*(?:malloc|calloc|realloc)\s*\(\s*([^)]+)\s*\)"
    for m in re.finditer(pat, code):
        allocs[m.group(1)] = m.group(2).strip()
    return allocs

def extract_write_sites(code):
    writes = []
    # memcpy/strcpy等函数调用写入
    pat1 = __import__('re').compile(r"(?:memcpy|strcpy|strncpy|sprintf|read|fread|recv)\s*\(\s*([^,]+),\s*[^,)]+(?:,\s*([^)]+))?\s*\)")
    for m in pat1.finditer(code):
        d = m.group(1).strip(); s = m.group(2).strip() if m.lastindex and m.group(2) else ''; writes.append((d, s, s))
    # 数组下标写入: buf[idx] = val
    pat2 = __import__('re').compile(r"(\w+)\s*\[\s*(\w+)\s*\]\s*=")
    for m in pat2.finditer(code): writes.append((m.group(1), '', m.group(2)))
    return writes
def propagate_sizes(code):
    c = {}
    for m in re.finditer(r"(\w+)\s*=\s*(\d+)\s*;", code):
        c[m.group(1)] = int(m.group(2))
    return c

def analyze_heap_risk(allocs, writes, consts):
    findings = []
    for dest, slen, third in writes:
        if dest not in allocs: continue
        wexpr = third if third else slen
        av = consts.get(allocs[dest])
        wv = consts.get(wexpr)
        if av is not None and wv is not None:
            if wv > av:
                findings.append({"dest":dest,"alloc":av,"write":wv,"overflow":wv-av,"conf":0.95})
        else:
            findings.append({"dest":dest,"alloc_expr":allocs[dest],"write_expr":wexpr,"conf":0.4})
    return findings

def detect_heap_overflow(code, func=""):
    a = extract_allocation_sites(code)
    w = extract_write_sites(code)
    c = propagate_sizes(code)
    fs = analyze_heap_risk(a, w, c)
    for fr in fs:
        fr["function"] = func
        fr["type"] = "heap-overflow"
        fr["severity"] = "Critical"
        fr["cwe"] = "CWE-122"
    return fs


def extract_array_writes(code):
    writes = []
    for m in __import__('re').finditer(r'(\w+)\s*\[\s*(\w+)\s*\]\s*=', code):
        writes.append((m.group(1), m.group(2), ''))
    return writes
