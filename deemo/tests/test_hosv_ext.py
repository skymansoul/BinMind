# coding: utf-8
"""
堆溢出写模式检测单元测试 — 覆盖各写模式检测模块的判定路径.
运行: python -m pytest tests/test_hosv_ext.py -q
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                ".."))

from analysis.hosv_ext_verifier import HosvExtVerifier, HosvExtOutput  # noqa: E402
from analysis.hosv_walk_write import (  # noqa: E402
    collect_walk_writes, verify_walk, _find_strlen_var, _strlen_coef,
)
from analysis.hosv_struct_idx import (  # noqa: E402
    resolve_elem_size, _bound_int, _extract_index_bound, _loop_bound_var,
    collect_struct_idx_writes, verify_struct_idx,
)
from analysis.hosv_unbounded_io import (  # noqa: E402
    _parse_scanf_width, collect_unbounded_io,
)
from analysis.hosv_factory_bind import (  # noqa: E402
    build_factory_summaries, collect_factory_binds, _split_functions,
)
from analysis.hosv_null_terminator import (  # noqa: E402
    collect_terminator_writes, _alloc_offset_from_strlen,
)
from analysis.hosv_ext_types import ExtAlloc  # noqa: E402
from analysis.heap_overflow_src_patterns import _skip_block_comments  # noqa: E402
from analysis.heap_overflow_src_phases import find_allocs  # noqa: E402


def _ext_alloc_for(src, alloc_var):
    lines = src.splitlines()
    valid = {ln for ln, _ in _skip_block_comments(lines)}
    for a in find_allocs(lines, valid):
        if a.var == alloc_var:
            return ExtAlloc(
                line=a.line, func=a.func, var=a.var,
                size_expr=a.size_expr, size_const=a.size_const,
                root=a.var, usable=-1)
    return None


# M1: walk_write

def test_walk_asymptotic_overflow():
    src = (
        "char* escape(const char* s) {\n"
        "    size_t l = strlen(s);\n"
        "    char* b = malloc(l + 1);\n"
        "    char* p = b;\n"
        "    for (const char* q = s; *q; q++) {\n"
        "        if (*q == '\\\\') { *p++ = '\\\\'; }\n"
        "        *p++ = *q;\n"
        "    }\n"
        "    *p = 0;\n"
        "    return b;\n"
        "}\n")
    lines = src.splitlines()
    alloc = _ext_alloc_for(src, "b")
    assert alloc is not None
    walks = collect_walk_writes({"b"}, lines, None)
    assert len(walks) == 1
    r = verify_walk(walks[0], alloc, lines)
    assert r is not None and r.verdict == "VULN"
    assert r.kind == "walk_write_asymptotic"


def test_walk_safe_when_alloc_coef_ge_write():
    src = (
        "char* escape_ok(const char* s) {\n"
        "    size_t l = strlen(s);\n"
        "    char* b = malloc(l * 2 + 2);\n"
        "    char* p = b;\n"
        "    for (const char* q = s; *q; q++) {\n"
        "        if (*q == '\\\\') { *p++ = '\\\\'; }\n"
        "        *p++ = *q;\n"
        "    }\n"
        "    *p = 0;\n"
        "    return b;\n"
        "}\n")
    lines = src.splitlines()
    alloc = _ext_alloc_for(src, "b")
    walks = collect_walk_writes({"b"}, lines, None)
    r = verify_walk(walks[0], alloc, lines)
    assert r is not None and r.verdict == "SAFE"


def test_strlen_var_backtrack():
    src = "size_t l = strlen(s);\nchar* b = malloc(l + 1);\n"
    lines = src.splitlines()
    assert _find_strlen_var("l + 1", lines, 2) == "s"
    assert _strlen_coef("l * 2 + 2", lines, 2, "s") == 2


def test_walk_memcpy_advance():
    src = (
        "int main() {\n"
        "    char* b = malloc(64);\n"
        "    char* p = b;\n"
        "    for (int i = 0; i < 8; i++) {\n"
        "        memcpy(p, \"XXXX\", 16);\n"
        "        p += 16;\n"
        "    }\n"
        "    free(b);\n"
        "    return 0;\n"
        "}\n")
    lines = src.splitlines()
    alloc = _ext_alloc_for(src, "b")
    walks = collect_walk_writes({"b"}, lines, None)
    assert len(walks) == 1
    assert walks[0].max_steps_per_iter == 16
    assert walks[0].loop_bound == 8
    r = verify_walk(walks[0], alloc, lines)
    assert r is not None and r.verdict == "VULN"


# M2: struct_idx

def test_struct_off_by_one():
    src = (
        "typedef struct { int h; char d[64]; } Item;\n"
        "void fill(Item* arr, int n) {\n"
        "    for (int i = 0; i <= n; i++) arr[i].h = i;\n"
        "}\n"
        "int main() {\n"
        "    Item* arr = malloc(10 * sizeof(Item));\n"
        "    fill(arr, 10);\n"
        "    free(arr);\n"
        "    return 0;\n"
        "}\n")
    lines = src.splitlines()
    assert resolve_elem_size("Item", lines, 5) == 68
    writes = collect_struct_idx_writes(lines, None)
    assert writes, "expected struct write candidate"
    alloc = _ext_alloc_for(src, "arr")
    for (line, arr, idx) in writes:
        r = verify_struct_idx(alloc, line, idx, lines)
        if r is not None and r.verdict == "VULN":
            assert r.kind in ("struct_idx_off_by_one", "struct_idx")
            return
    pytest.fail("off-by-one not detected")


def test_struct_bound_int_guard():
    src = (
        "int n = 0;\n"
        "if (n <= 100) {\n"
        "    for (int i = 0; i < n; i++) {}\n"
        "}\n")
    lines = src.splitlines()
    assert _bound_int("n", lines, 3) == 100
    assert _loop_bound_var(3, "i", lines) == ("n", False)


# M3: unbounded_io

def test_scanf_width_parsing():
    assert _parse_scanf_width('"%s"') is None
    assert _parse_scanf_width('"%31s"') == 31
    assert _parse_scanf_width('"%d%s"') is None
    assert _parse_scanf_width('"%d%16s"') == 16


def test_gets_detected():
    src = (
        "int main() {\n"
        "    char* b = malloc(48);\n"
        "    gets(b);\n"
        "    free(b);\n"
        "    return 0;\n"
        "}\n")
    lines = src.splitlines()
    io = collect_unbounded_io(lines, None)
    assert any(t == "gets" for _, _, _, t in io)


# M4: factory_bind

def test_factory_split_and_summary():
    src = (
        "void* mat(int r, int c) {\n"
        "    return calloc(r, c);\n"
        "}\n"
        "int main() {\n"
        "    char* p = (char*)mat(65536, 65536);\n"
        "    return 0;\n"
        "}\n")
    lines = src.splitlines()
    funcs = _split_functions(lines)
    assert any(n == "mat" for n, _, _ in funcs)
    s = build_factory_summaries(lines, None)
    assert s.get("mat") == ("calloc", "r, c", "@ret")
    binds = collect_factory_binds(lines, s, None)
    assert len(binds) == 1
    assert binds[0][1] == "p"


def test_calloc_wraparound():
    src = (
        "void* mat(int r, int c) { return calloc(r, c); }\n"
        "int main() { char* p = (char*)mat(65536, 65536); return 0; }\n")
    lines = src.splitlines()
    v = HosvExtVerifier()
    res = v.verify(src)
    assert any(o.verdict == "VULN" and o.kind == "calloc_wraparound"
               for o in res)


# M5: null_terminator

def test_terminator_collect_and_offset():
    src = (
        "char* dup(const char* s) {\n"
        "    size_t l = strlen(s);\n"
        "    char* d = malloc(l);\n"
        "    memcpy(d, s, l);\n"
        "    d[l] = 0;\n"
        "    return d;\n"
        "}\n")
    lines = src.splitlines()
    terms = collect_terminator_writes(lines, None)
    assert len(terms) == 1
    assert _alloc_offset_from_strlen(lines, 3, "l") == 0


def test_terminator_safe_with_plus1():
    src = (
        "char* dup(const char* s) {\n"
        "    size_t l = strlen(s);\n"
        "    char* d = malloc(l + 1);\n"
        "    memcpy(d, s, l);\n"
        "    d[l] = 0;\n"
        "    return d;\n"
        "}\n")
    lines = src.splitlines()
    assert _alloc_offset_from_strlen(lines, 3, "l") == 1


# 端到端

def test_end_to_end_regression_samples():
    """跑完整 18 样本回归.

    写模式扩展单独: ≥10 TP, 0 FP (扩展不引入新误报).
    完整管线 (HOSV + 写模式扩展): 12 TP / 0 FP / 0 FN / 6 TN.
    """
    base = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        "hosv_benchmark", "samples")
    v = HosvExtVerifier()
    tp = fp = fn = tn = 0
    for entry in sorted(os.listdir(base)):
        d = os.path.join(base, entry)
        truth_p = os.path.join(d, "truth.json")
        src_p = os.path.join(d, "vuln.c")
        if not (os.path.exists(truth_p) and os.path.exists(src_p)):
            continue
        import json
        with open(truth_p, "r", encoding="utf-8") as f:
            truth = json.load(f)
        src = open(src_p, "r", encoding="utf-8", errors="replace").read()
        res = v.verify(src)
        det = any(o.verdict == "VULN" for o in res)
        exp = truth["verdict"]
        if exp == "VULN":
            if det:
                tp += 1
            else:
                fn += 1
        else:
            if det:
                fp += 1
            else:
                tn += 1
    assert tp >= 10 and fp == 0
    assert tn == 6
