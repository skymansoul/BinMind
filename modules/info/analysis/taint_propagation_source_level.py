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
    pat = r"(?:memcpy|strcpy|strncpy|sprintf|read)\s*\(\s*([^,]+),\s*([^,)]+)(?:,\s*([^)]+))?\s*\)"
    for m in re.finditer(pat, code):
        d = m.group(1).strip()
        s = m.group(2).strip()
        t = m.group(3).strip() if m.group(3) else ""
        writes.append((d, s, t))
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
