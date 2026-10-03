# analysis/uaf_lifecycle -- heap ptr lifecycle state machine + alias graph
# Tracks each heap ptr through: ALLOCATED -> FREED -> DANGLING -> USED (UAF)
# v3.1: added array-index support (handlers[id]) for inter-procedural UAF
from __future__ import annotations
from typing import Dict, List, Set, Tuple, Optional
from enum import Enum
import re

class PtrState(Enum):
    ALLOCATED = "allocated"
    FREED = "freed"
    DANGLING = "dangling"
    REALLOCATED = "reallocated"
    ESCAPED = "escaped"

def _base_var(expr: str) -> str:
    """Extract base variable from ptr expression.
    'handlers[id]'->'handlers', 'handlers[id]->name'->'handlers', 'g->field'->'g'"""
    expr = re.sub(r'\[[^\]]*\]', '', expr)
    return expr.split('->')[0].split('.')[0].strip()

def build_alias_graph(code: str) -> Dict[str, Set[str]]:
    """Build intra-procedural pointer alias graph."""
    aliases: Dict[str, Set[str]] = {}
    # allocation points
    for m in re.finditer(r'(\w+(?:\s*\[[^\]]*\])?)\s*=\s*(?:malloc|calloc|realloc)\s*\(', code):
        aliases.setdefault(_base_var(m.group(1)), set()).add(_base_var(m.group(1)))
    # ptr assignment: q = p
    for m in re.finditer(r'(\w+)\s*=\s*(\w+)\s*;', code):
        lhs, rhs = m.group(1), m.group(2)
        if rhs in aliases:
            aliases.setdefault(lhs, set()).update(aliases[rhs]); aliases[lhs].add(lhs)
    # escape through function args
    for m in re.finditer(r'(?:send|write|fwrite|memcpy|strcpy|sprintf|printf)\s*'
                         r'\([^)]*(\w+)[^)]*\)', code):
        ev = m.group(1)
        if ev in aliases:
            for root in list(aliases.get(ev, set())): aliases.setdefault(root, set()).add("__escaped__")
    # escape through return
    for m in re.finditer(r'return\s+(\w+)\s*;', code):
        if m.group(1) in aliases: aliases[m.group(1)].add("__escaped__")
    return aliases

def track_lifecycle(code: str, func_name: str = "") -> List[Dict]:
    """Track heap ptr lifecycle: ALLOC/FREE/REALLOC/USE events in chronological order."""
    events = []
    # ALLOC: var = malloc/calloc/realloc(...)  AND  var[idx] = calloc(...)
    for m in re.finditer(r'(\w+(?:\s*\[[^\]]*\])?)\s*='
                         r'\s*(?:malloc|calloc|realloc|new)\s*\([^)]*\)', code):
        events.append({"var": _base_var(m.group(1)), "event": "ALLOC", "pos": m.start(),
                       "line": code[:m.start()].count('\n') + 1})
    # FREE: free(var) / free(var[idx]) / free(var->field)
    for m in re.finditer(r'free\s*\(\s*(\w+(?:\s*\[[^\]]*\])?(?:\s*->\s*\w+)?)\s*\)', code):
        events.append({"var": _base_var(m.group(1)), "event": "FREE",
                       "pos": m.start(), "line": code[:m.start()].count('\n') + 1})
    # REALLOC: var = malloc/calloc/realloc(...) after free
    for m in re.finditer(r'(\w+(?:\s*\[[^\]]*\])?)\s*=\s*(?:malloc|calloc|realloc)\s*\([^)]*\)', code):
        events.append({"var": _base_var(m.group(1)), "event": "REALLOC", "pos": m.start(),
                       "line": code[:m.start()].count('\n') + 1})
    # USE via strcpy/memcpy/sprintf/strcat/snprintf: func(var->field, ...)
    for m in re.finditer(r'(?:strcpy|memcpy|sprintf|strcat|snprintf)\s*\(\s*'
                         r'(\w+(?:\s*\[[^\]]*\])?(?:\s*->\s*\w+)?)\s*[,)]', code):
        events.append({"var": _base_var(m.group(1)), "event": "USE",
                       "pos": m.start(), "func": m.group(0).split('(')[0],
                       "line": code[:m.start()].count('\n') + 1})
    # USE via printf/puts/send/write -- with field access support
    for m in re.finditer(r'(?:printf|puts|send|write)\s*\([^)]*\)', code):
        call_text = m.group(0)
        # var->field patterns
        for fm in re.finditer(r'(\w+(?:\s*\[[^\]]*\])?)\s*->\s*\w+', call_text):
            v = _base_var(fm.group(1))
            if v not in ("stdout", "stderr", "NULL", "format", "fmt"):
                events.append({"var": v, "event": "USE", "pos": m.start(),
                               "func": m.group(0).split('(')[0],
                               "line": code[:m.start()].count('\n') + 1})
        # var.field patterns
        for dm in re.finditer(r'(\w+)\s*\.\s*\w+', call_text):
            v = dm.group(1)
            if v not in ("stdout", "stderr", "NULL", "format", "fmt"):
                events.append({"var": v, "event": "USE", "pos": m.start(),
                               "func": m.group(0).split('(')[0],
                               "line": code[:m.start()].count('\n') + 1})
    # if(ptr) / if(ptr[idx]) -- conditional check is USE of a heap ptr
    for m in re.finditer(r'if\s*\(\s*(\w+(?:\s*\[[^\]]*\])?)\s*\)', code):
        v = _base_var(m.group(1))
        if v in ("stdout", "stderr", "NULL", "format", "fmt"): continue
        alloc_vars = {e["var"] for e in events if e["event"] == "ALLOC"}
        if v in alloc_vars:
            events.append({"var": v, "event": "USE", "pos": m.start(),
                           "func": "if_check", "line": code[:m.start()].count('\n') + 1})
    events.sort(key=lambda e: e["pos"])
    return events

def detect_uaf_v3(code: str, func_name: str = "") -> List[Dict]:
    """UAF v3.1 main detection: lifecycle state machine + alias graph.
    Detects FREE->USE transitions without intervening REALLOC."""
    events = track_lifecycle(code, func_name)
    aliases = build_alias_graph(code)
    findings = []
    var_states: Dict[str, PtrState] = {}
    var_last_free: Dict[str, int] = {}

    for ev in events:
        v = ev["var"]
        if ev["event"] == "ALLOC":
            var_states[v] = PtrState.ALLOCATED
        elif ev["event"] == "FREE":
            if var_states.get(v) == PtrState.FREED:
                pass  # double free handled by double_free_analyzer
            var_states[v] = PtrState.FREED
            var_last_free[v] = ev["pos"]
        elif ev["event"] == "REALLOC":
            if var_states.get(v) == PtrState.FREED:
                var_states[v] = PtrState.REALLOCATED  # safe: realloc breaks UAF chain
            else:
                var_states[v] = PtrState.ALLOCATED
        elif ev["event"] == "USE":
            if var_states.get(v) in (PtrState.FREED, PtrState.DANGLING):
                dist = ev["pos"] - var_last_free.get(v, 0)
                escaped = "__escaped__" in aliases.get(v, set())
                conf = 0.90
                reasons = ["FREE->USE"]
                if escaped:
                    conf = min(0.98, conf + 0.05)
                    reasons.append("pointer escaped->external dangling ref")
                if dist < 100:
                    conf = min(0.95, conf + 0.05)
                    reasons.append(f"FREE-USE gap={dist}chars->tight window")
                alias_users = [a for a in aliases if v in aliases.get(a, set()) and a != v]
                if alias_users:
                    conf = min(0.98, conf + 0.05)
                    reasons.append(f"alias {','.join(alias_users[:3])} shares dangling ptr")
                findings.append({
                    "type": "use-after-free", "cwe": "CWE-416",
                    "function": func_name, "variable": v,
                    "aliases": list(aliases.get(v, {v})),
                    "escaped": escaped,
                    "free_at_line": code[:var_last_free[v]].count('\n') + 1,
                    "use_at_line": ev.get("line", 0),
                    "free_use_distance": dist,
                    "use_func": ev.get("func", "unknown"),
                    "severity": "Critical",
                    "confidence": round(conf, 2),
                    "description": f"UAF: {v} used via {ev.get('func','?')} "
                                   f"{dist} chars after free(); {'; '.join(reasons)}",
                })
                var_states[v] = PtrState.DANGLING
    findings.sort(key=lambda f: f["confidence"], reverse=True)
    return findings
