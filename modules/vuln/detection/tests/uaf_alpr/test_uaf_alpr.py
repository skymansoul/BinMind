"""ALPR UAF 核心模块 pytest 测试.

创建: 2025-05-12
覆盖:
  rebound_filter  溯源等价配对 (CONFIRMED / SAFE_REBOUND / 无关)
  interproc       参数摘要提取 (按标签映射)
  lifetime_tracker 解引用/写函数/尾调用事件识别

运行: pytest tests/uaf_alpr/test_uaf_alpr.py -q
"""

import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
for _anchor in _HERE.parents:
    if (_anchor / 'modules').exists():
        sys.path.insert(0, str(_anchor))
        break

from modules.vuln.detection.heap_analysis.uaf_alpr.uaf_types import (
    FreeRecord, UafUse, UseKind, UafVerdict)
from modules.vuln.detection.heap_analysis.uaf_alpr.rebound_filter import (
    evaluate_use, summarize)
from modules.vuln.detection.heap_analysis.uaf_alpr.interproc import (
    build_summary, _arg_index_from_label)
from modules.vuln.detection.heap_analysis.uaf_alpr.lifetime_tracker import (
    LifetimeTracker)
from modules.vuln.detection.heap_analysis.insn_parser import Instruction as I


def test_confirm_same_label():
    frees = [FreeRecord(0x100, 'f', 'rcx', 'alloc@1000')]
    use = UafUse(0x140, 'f', 'rcx', 'alloc@1000', UseKind.READ)
    rec = evaluate_use(use, frees)
    assert rec is not None and rec.verdict == UafVerdict.CONFIRMED


def test_rebound_filtered():
    frees = [FreeRecord(0x100, 'f', 'rcx', 'alloc@1000')]
    use = UafUse(0x150, 'f', 'rcx', 'alloc@2000', UseKind.READ)
    rec = evaluate_use(use, frees)
    assert rec is not None and rec.verdict == UafVerdict.SAFE_REBOUND


def test_unrelated_use_none():
    frees = [FreeRecord(0x100, 'f', 'rcx', 'alloc@1000')]
    use = UafUse(0x160, 'f', 'rax', 'arg1', UseKind.READ)
    assert evaluate_use(use, frees) is None


def test_summary_by_label():
    # 解引用发生在 rax 上, 但标签为 arg1 → 摘要 uses=[1]
    assert _arg_index_from_label('arg1') == 1
    assert _arg_index_from_label('alloc@1000') == 0


def test_tracker_write_call_use():
    insns = [
        I(0x100, 'call', '140003248 <malloc>', ''),
        I(0x108, 'mov', 'QWORD PTR [rbp-0x8],rax', ''),
        I(0x110, 'mov', 'rax,QWORD PTR [rbp-0x8]', ''),
        I(0x118, 'mov', 'rcx,rax', ''),
        I(0x120, 'call', '140003240 <free>', ''),
        I(0x128, 'mov', 'rcx,rax', ''),
        I(0x130, 'mov', 'r8d,0x4', ''),
        I(0x138, 'call', 'memcpy', ''),
    ]
    res = LifetimeTracker().analyze_function('f', insns)
    assert len(res.frees) == 1
    assert res.frees[0].freed_label.startswith('alloc@')
    assert any(u.use_kind == UseKind.WRITE for u in res.uses)


def test_tracker_tail_call_free():
    insns = [
        I(0x100, 'call', '140003248 <malloc>', ''),
        I(0x108, 'mov', 'rcx,rax', ''),
        I(0x110, 'jmp', '140003220 <free>', ''),
    ]
    res = LifetimeTracker().analyze_function('t', insns)
    assert len(res.frees) == 1


def test_summarize_counts():
    from modules.vuln.detection.heap_analysis.uaf_alpr.uaf_types import (
        UafVerdictRecord)
    recs = [
        UafVerdictRecord('f', 1, 'rcx', UseKind.READ, 'alloc@1', 'alloc@1',
                         UafVerdict.CONFIRMED, ''),
        UafVerdictRecord('f', 2, 'rcx', UseKind.READ, 'alloc@1', 'alloc@2',
                         UafVerdict.SAFE_REBOUND, ''),
    ]
    s = summarize(recs)
    assert s['confirmed'] == 1 and s['safe_rebound'] == 1
    assert s['fp_reduction_pct'] == 50.0
