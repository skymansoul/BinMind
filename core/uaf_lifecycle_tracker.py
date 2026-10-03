"""
UAF 生命周期状态机 — 追踪堆指针从分配到释放到悬垂使用的状态。
"""
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List

class PtrState(Enum):
    ALLOC=0; LIVE=1; FREED=2; NULLED=3; DANGLING=4; DOUBLE_FREE=5

@dataclass
class PtrLifecycle:
    ptr_name: str=""; alloc_line: int=0; alloc_func: str=""
    aliases: List[str]=field(default_factory=list)
    state: PtrState=PtrState.ALLOC; freed_line: int=-1
    dangling_use_lines: List[int]=field(default_factory=list)
    double_free_line: int=-1

@dataclass
class UAFLifecycleReport:
    function_name: str=""; pointers: List[PtrLifecycle]=field(default_factory=list)
    uaf_count: int=0; double_free_count: int=0; details: List[str]=field(default_factory=list)

_ALLOC_RE = re.compile(r'(\w[\w\d_]*)\s*=\s*(?:\([^)]*\*\s*\))?\s*(malloc|calloc|realloc|strdup)\s*\(')
_FREE_RE = re.compile(r'(?:free|kfree)\s*\(\s*(\w[\w\d_]*)\s*\)')
_DEREF_RE = re.compile(r'(\w[\w\d_]*)\s*(?:->|\[)')
_ASSIGN_RE = re.compile(r'(\w[\w\d_]*)\s*=\s*(\w[\w\d_]*)\s*;')
_NULL_RE = re.compile(r'(\w[\w\d_]*)\s*=\s*(?:NULL|nullptr|0)\s*;')
# 修复: \w{1,31} 而非 \w[\w\d_]{1,31}, 后者至少需要2个字符, 遗漏单字符变量
_TOKEN_RE = re.compile(r'\b(\w{1,31})\b')
_SKIP = {'if','while','for','return','sizeof','void','int','char','long',
    'short','struct','typedef','include','define','const','static','extern','unsigned','signed'}

def _is_field_free(match_obj, line):
    end = match_obj.end()
    if end >= len(line): return False
    return line[end:].lstrip().startswith(('->','['))

def track_uaf_lifecycle(pseudocode, func_name="unknown"):
    lines = pseudocode.split('\n')
    pointers = {}
    alias_map = {}
    for line_no, line in enumerate(lines):
        s = line.strip()
        if not s or s.startswith('//') or s.startswith('#'): continue
        for fm in _FREE_RE.finditer(s):
            v = fm.group(1)
            if _is_field_free(fm, s): continue
            can = alias_map.get(v, v)
            if can in pointers:
                p = pointers[can]
                if p.state == PtrState.FREED:
                    p.state = PtrState.DOUBLE_FREE; p.double_free_line = line_no
                else:
                    p.state = PtrState.FREED; p.freed_line = line_no
        am = _ALLOC_RE.search(s)
        if am:
            v, func = am.group(1), am.group(2)
            pointers[v] = PtrLifecycle(ptr_name=v, alloc_line=line_no, alloc_func=func)
            alias_map[v] = v
        gm = _ASSIGN_RE.search(s)
        if gm:
            lhs, rhs = gm.group(1), gm.group(2)
            if rhs in alias_map and lhs not in _SKIP:
                alias_map[lhs] = alias_map[rhs]
                can = alias_map[rhs]
                if can in pointers and lhs not in pointers[can].aliases:
                    pointers[can].aliases.append(lhs)
        nm = _NULL_RE.search(s)
        if nm:
            v = nm.group(1)
            can = alias_map.get(v, v)
            if can in pointers and pointers[can].state == PtrState.FREED:
                pointers[can].state = PtrState.NULLED
        dm = _DEREF_RE.search(s)
        if dm:
            v = dm.group(1)
            can = alias_map.get(v, v)
            if can in pointers:
                p = pointers[can]
                if p.state == PtrState.FREED:
                    p.state = PtrState.DANGLING
                    if line_no not in p.dangling_use_lines:
                        p.dangling_use_lines.append(line_no)
                elif p.state not in (PtrState.NULLED, PtrState.DANGLING, PtrState.DOUBLE_FREE):
                    p.state = PtrState.LIVE
        cleaned = re.sub(r'(?:free|kfree)\s*\([^)]*\)', '', s)
        for token in _TOKEN_RE.findall(cleaned):
            if token in _SKIP: continue
            can = alias_map.get(token, token)
            if can in pointers and pointers[can].state == PtrState.FREED:
                pointers[can].state = PtrState.DANGLING
                if line_no not in pointers[can].dangling_use_lines:
                    pointers[can].dangling_use_lines.append(line_no)
    uaf = [p for p in pointers.values() if p.state == PtrState.DANGLING]
    df = [p for p in pointers.values() if p.state == PtrState.DOUBLE_FREE]
    details = []
    for p in uaf:
        details.append(f'UAF: {p.ptr_name} freed L{p.freed_line}, used L{p.dangling_use_lines}')
    for p in df:
        details.append(f'Double-free: {p.ptr_name} at L{p.double_free_line}')
    return UAFLifecycleReport(function_name=func_name, pointers=list(pointers.values()),
                              uaf_count=len(uaf), double_free_count=len(df), details=details)
