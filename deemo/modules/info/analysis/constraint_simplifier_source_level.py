# Constraint simplifier — eliminate infeasible vulnerability conditions
from __future__ import annotations
from typing import Dict, List, Tuple, Optional
import re

def extract_constants(code):
    c = {}
    for m in re.finditer(r"(\w+)\s*=\s*(\d+)\s*;", code):
        c[m.group(1)] = int(m.group(2))
    return c

def parse_constraints(code):
    ap = re.compile(r"(\w+)\s*=\s*(?:malloc|calloc)\s*\(\s*(\w+(?:\s*\*\s*\w+)?)\s*\)")
    allocs = {m.group(1): m.group(2) for m in ap.finditer(code)}
    wp = re.compile(r"(?:memcpy|strcpy|strncpy|read)\s*\(\s*(\w+)\s*,\s*[^,]+\s*,\s*(\w+)\s*\)")
    writes = [(m.group(1), m.group(2)) for m in wp.finditer(code)]
    cs = []
    for dest, sv in writes:
        if dest in allocs:
            cs.append({"buffer":dest,"alloc":allocs[dest],"write":sv})
    return cs

def simplify(cs, cmap):
    r = []
    for c in cs:
        av = cmap.get(c["alloc"])
        wv = cmap.get(c["write"])
        if av is not None and wv is not None:
            r.append({**c,"verdict":"confirmed" if wv>av else "safe"})
        else:
            r.append({**c,"verdict":"unknown"})
    return r

def filter_false_positives(findings, code):
    cm = extract_constants(code)
    cs = parse_constraints(code)
    res = simplify(cs, cm)
    safe = {r["buffer"] for r in res if r["verdict"]=="safe"}
    return [f for f in findings if f.get("dest","") not in safe]
