# coding: utf-8
"""
数组索引游走写检测单元测试. 覆盖 buf[idx++] 模式与渐近判定.
运行: python -m pytest tests/test_hosv_array_walk.py -q
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                ".."))

from analysis.hosv_array_walk import (  # noqa: E402
    collect_array_walks, verify_array_walk,
)
from analysis.hosv_ext_types import ExtAlloc  # noqa: E402
from analysis.heap_overflow_src_patterns import (  # noqa: E402
    _skip_block_comments, _ptmalloc2_usable,
)
from analysis.heap_overflow_src_phases import find_allocs  # noqa: E402


def _ext_alloc_for(src, alloc_var):
    lines = src.splitlines()
    valid = {ln for ln, _ in _skip_block_comments(lines)}
    for a in find_allocs(lines, valid):
        if a.var == alloc_var:
            return ExtAlloc(
                line=a.line, func=a.func, var=a.var,
                size_expr=a.size_expr, size_const=a.size_const,
                root=a.var,
                usable=_ptmalloc2_usable(a.size_const)
                if a.size_const > 0 else -1)
    return None


def test_array_walk_postinc_bounded_overflow():
    src = (
        "int main() {\n"
        "    char* buf = malloc(32);\n"
        "    int w = 0;\n"
        "    for (int i = 0; i < 40; i++) {\n"
        "        buf[w++] = 'x';\n"
        "    }\n"
        "    buf[w] = 0;\n"
        "    free(buf);\n"
        "    return 0;\n"
        "}\n")
    lines = src.splitlines()
    alloc = _ext_alloc_for(src, "buf")
    assert alloc is not None
    walks = collect_array_walks({"buf"}, lines, None)
    assert len(walks) == 1
    line, arr, idx, bound = walks[0]
    assert bound == 40
    r = verify_array_walk(alloc, line, idx, bound, lines)
    assert r is not None and r.verdict == "VULN"


def test_array_walk_safe_bounded():
    src = (
        "int main() {\n"
        "    char* buf = malloc(64);\n"
        "    int w = 0;\n"
        "    for (int i = 0; i < 32; i++) {\n"
        "        buf[w++] = 'x';\n"
        "    }\n"
        "    buf[w] = 0;\n"
        "    free(buf);\n"
        "    return 0;\n"
        "}\n")
    lines = src.splitlines()
    alloc = _ext_alloc_for(src, "buf")
    walks = collect_array_walks({"buf"}, lines, None)
    assert len(walks) == 1
    line, arr, idx, bound = walks[0]
    r = verify_array_walk(alloc, line, idx, bound, lines)
    assert r is not None and r.verdict == "SAFE"


def test_array_walk_asymptotic_strlen():
    src = (
        "char* dup(const char* s) {\n"
        "    size_t l = strlen(s);\n"
        "    size_t n = l + 1;\n"
        "    char* d = malloc(n);\n"
        "    int w = 0;\n"
        "    for (size_t i = 0; i < l; i++) {\n"
        "        d[w++] = s[i];\n"
        "        if (s[i] == '\\\\') { d[w++] = '\\\\'; }\n"
        "    }\n"
        "    d[w] = 0;\n"
        "    return d;\n"
        "}\n")
    lines = src.splitlines()
    alloc = _ext_alloc_for(src, "d")
    assert alloc is not None
    walks = collect_array_walks({"d"}, lines, None)
    assert walks, "expected array walk candidates"
    vuln = False
    for (line, arr, idx, bound) in walks:
        r = verify_array_walk(alloc, line, idx, bound, lines)
        if r and r.verdict == "VULN":
            vuln = True
    assert vuln, "asymptotic array walk should be VULN"


def test_sudo_cve_sample_detected():
    """CVE-2021-3156 sudo 简化复现应被检出."""
    base = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        "..", "samples", "cve_heap_overflow",
                        "cve_2021_3156_sudo")
    cf = [f for f in os.listdir(base) if f.endswith(".c")]
    assert cf, "sudo sample missing"
    src = open(os.path.join(base, cf[0]), encoding="utf-8",
               errors="replace").read()
    lines = src.splitlines()
    valid = {ln for ln, _ in _skip_block_comments(lines)}
    allocs = find_allocs(lines, valid)
    assert allocs, "sudo sample has no alloc"
    a = allocs[0]
    alloc = ExtAlloc(
        line=a.line, func=a.func, var=a.var, size_expr=a.size_expr,
        size_const=a.size_const, root=a.var, usable=-1)
    walks = collect_array_walks({a.var for a in allocs}, lines, valid)
    assert walks, "sudo array walks not collected"
    vuln = False
    for (line, arr, idx, bound) in walks:
        r = verify_array_walk(alloc, line, idx, bound, lines)
        if r and r.verdict == "VULN":
            vuln = True
            break
    assert vuln, "sudo CVE-2021-3156 should be detected as VULN"
