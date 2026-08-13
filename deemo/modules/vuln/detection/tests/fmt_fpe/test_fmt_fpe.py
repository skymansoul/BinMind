"""FPE 格式溯源核心模块 pytest 测试.

创建: 2024-09-02
覆盖:
  fmt_filter  溯源等价分类 (SAFE_CONST / VULN_PARAM / VULN_LOCAL)
  fmt_tracker 常量池/局部变量/栈槽标签传播
运行: pytest tests/fmt_fpe/test_fmt_fpe.py -q
"""

import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
for _anchor in _HERE.parents:
    if (_anchor / 'modules').exists():
        sys.path.insert(0, str(_anchor))
        break

from modules.vuln.detection.heap_analysis.fmt_fpe.fmt_types import (
    FmtCall, FmtVerdict)
from modules.vuln.detection.heap_analysis.fmt_fpe.fmt_filter import (
    evaluate_call, summarize)
from modules.vuln.detection.heap_analysis.fmt_fpe.fmt_tracker import FmtTracker
from modules.vuln.detection.heap_analysis.insn_parser import Instruction as I


def test_const_safe():
    r = evaluate_call(FmtCall(1, 'f', 'printf', '.rdata', 'rcx'))
    assert r.verdict == FmtVerdict.SAFE_CONST


def test_param_vuln():
    r = evaluate_call(FmtCall(1, 'f', 'printf', 'arg2', 'rdx'))
    assert r.verdict == FmtVerdict.VULN_PARAM


def test_local_vuln():
    r = evaluate_call(FmtCall(1, 'f', 'printf', 'stack', 'rcx'))
    assert r.verdict == FmtVerdict.VULN_LOCAL


def test_direct_const_lea():
    insns = [
        I(0x100, 'lea', 'rcx,[rip+0x37f0]', ''),
        I(0x108, 'call', 'printf', ''),
    ]
    res = FmtTracker().analyze_function('f', insns)
    assert res.calls and res.calls[0].fmt_label == '.rdata'


def test_local_var_const_propagation():
    insns = [
        I(0x100, 'lea', 'rax,[rip+0x37f0]', ''),
        I(0x108, 'mov', 'QWORD PTR [rbp-0x8],rax', ''),
        I(0x110, 'mov', 'rax,QWORD PTR [rbp-0x8]', ''),
        I(0x118, 'mov', 'rcx,rax', ''),
        I(0x120, 'call', 'printf', ''),
    ]
    res = FmtTracker().analyze_function('f', insns)
    assert res.calls and res.calls[0].fmt_label == '.rdata'


def test_arg_propagation():
    insns = [
        I(0x0f0, 'mov', 'QWORD PTR [rbp+0x18],rdx', ''),
        I(0x100, 'mov', 'rax,QWORD PTR [rbp+0x18]', ''),
        I(0x108, 'mov', 'rax,QWORD PTR [rax+0x8]', ''),
        I(0x110, 'mov', 'rcx,rax', ''),
        I(0x118, 'call', 'printf', ''),
    ]
    res = FmtTracker().analyze_function('f', insns)
    assert res.calls and res.calls[0].fmt_label == 'arg2'


def test_summary():
    rs = [
        evaluate_call(FmtCall(1, 'f', 'printf', '.rdata', 'rcx')),
        evaluate_call(FmtCall(2, 'f', 'printf', 'arg1', 'rcx')),
    ]
    s = summarize(rs)
    assert s['safe_const'] == 1 and s['kept'] == 1
