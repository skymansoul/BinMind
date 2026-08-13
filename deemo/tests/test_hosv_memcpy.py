# coding: utf-8
"""
memcpy 变量长度符号关联与守卫感知单元测试.
运行: python -m pytest tests/test_hosv_memcpy.py -q
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                ".."))

from analysis.hosv_memcpy_corr import (  # noqa: E402
    collect_memcpy_writes, verify_memcpy,
)
from analysis.hosv_sym_expr import trace_expr  # noqa: E402
from analysis.hosv_ext_types import ExtAlloc  # noqa: E402
from analysis.heap_overflow_src_patterns import (  # noqa: E402
    _skip_block_comments, _ptmalloc2_usable,
)
from analysis.heap_overflow_src_phases import find_allocs  # noqa: E402
from analysis.hosv_unbounded_io import _guard_upper_bound  # noqa: E402


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


def test_trace_expr_chain():
    lines = ["size_t len = strlen(s);", "size_t n = len + 8;"]
    e = trace_expr("n", lines, 3, 0)
    assert e is not None
    assert e.coeffs.get("strlen(s)") == 1
    assert e.const == 8


def test_memcpy_const_overflow():
    src = (
        "int main() {\n"
        "    char* buf = malloc(8);\n"
        "    memcpy(buf, \"payload-beyond\", 32);\n"
        "    free(buf);\n"
        "    return 0;\n"
        "}\n")
    lines = src.splitlines()
    alloc = _ext_alloc_for(src, "buf")
    assert alloc is not None
    writes = collect_memcpy_writes({"buf"}, lines, None)
    assert len(writes) == 1
    line, dst, size_arg, offset = writes[0]
    r = verify_memcpy(alloc, line, dst, size_arg, lines, offset)
    assert r is not None and r.verdict == "VULN"


def test_memcpy_const_safe():
    src = (
        "int main() {\n"
        "    char* buf = malloc(32);\n"
        "    memcpy(buf, \"hi\", 4);\n"
        "    free(buf);\n"
        "    return 0;\n"
        "}\n")
    lines = src.splitlines()
    alloc = _ext_alloc_for(src, "buf")
    writes = collect_memcpy_writes({"buf"}, lines, None)
    line, dst, size_arg, offset = writes[0]
    r = verify_memcpy(alloc, line, dst, size_arg, lines, offset)
    assert r is not None and r.verdict == "SAFE"


def test_memcpy_coef_overflow():
    src = (
        "int main(int c, char** v) {\n"
        "    size_t len = strlen(v[1]);\n"
        "    char* buf = malloc(len);\n"
        "    memcpy(buf, v[1], len * 2);\n"
        "    free(buf);\n"
        "    return 0;\n"
        "}\n")
    lines = src.splitlines()
    alloc = _ext_alloc_for(src, "buf")
    assert alloc is not None
    writes = collect_memcpy_writes({"buf"}, lines, None)
    assert len(writes) == 1
    line, dst, size_arg, offset = writes[0]
    r = verify_memcpy(alloc, line, dst, size_arg, lines, offset)
    assert r is not None and r.verdict == "VULN"


def test_guard_upper_bound_related_var():
    src = (
        "int len = 0;\n"
        "if (len < 32) {\n"
        "    char* b = malloc(len + 1);\n"
        "    read(0, b, len);\n"
        "}\n")
    lines = src.splitlines()
    assert _guard_upper_bound(3, 33, "len + 1", lines) == 32


def test_guard_upper_bound_unrelated_var():
    src = (
        "int count = 0;\n"
        "if (count < 10) {\n"
        "    char* b = malloc(64);\n"
        "    scanf(\"%s\", b);\n"
        "}\n")
    lines = src.splitlines()
    assert _guard_upper_bound(3, 64, "64", lines) is None
