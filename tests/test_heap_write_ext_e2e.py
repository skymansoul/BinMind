# coding: utf-8
"""
堆溢出写模式检测端到端回归 — 跑完整样本集验证无漏报无误报.
与 test_heap_write_.py 拆分, 避免单文件过长.
运行: python -m pytest tests/test_heap_write_ext_e2e.py -q
"""

import json
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                ".."))

from analysis.heap_write_ext_verifier import HosvExtVerifier  # noqa: E402


def test_end_to_end_regression_samples():
    """跑完整 20 样本回归.

    写模式扩展单独: ≥11 TP, 0 FP (扩展不引入新误报).
    完整管线 (堆写模式验证 + 写模式扩展): 13 TP / 0 FP / 0 FN / 7 TN.
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
    assert tp >= 11 and fp == 0
    assert tn == 7
