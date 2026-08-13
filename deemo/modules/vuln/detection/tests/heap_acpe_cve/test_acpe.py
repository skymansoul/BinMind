"""ACPE 核心模块 pytest 测试 — 回归保护与 CI 集成.

创建: 2024-12-09
覆盖:
  capacity_model   ptmalloc2 可用容量/对齐/slack
  sym_size_tracker 符号追踪 (movzx 截断 / 掩码 / 栈目标 / 偏移)
  guard_dominance  早退/钳位/反例守卫
  equivalence      溯源等价分类
  verdict          判定映射与保守原则

运行: pytest tests/heap_acpe_cve/test_acpe.py -q
"""

import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
for _anchor in _HERE.parents:
    if (_anchor / 'modules').exists():
        sys.path.insert(0, str(_anchor))
        break

from modules.vuln.detection.heap_analysis.acpe.capacity_model import (
    CapExpr, usable_size, slack_bytes, const_relation, arith_relation,
    MAX_SLACK)
from modules.vuln.detection.heap_analysis.acpe.equivalence import classify_pair
from modules.vuln.detection.heap_analysis.acpe.verdict import (
    Verdict, evaluate, summarize)
from modules.vuln.detection.heap_analysis.acpe.guard_dominance import (
    GuardRecord, analyze_guards_for_write, guard_safety_check)
from modules.vuln.detection.heap_analysis.acpe.sym_size_tracker import (
    SymSizeTracker)
from modules.vuln.detection.heap_analysis.insn_parser import Instruction as I


# capacity_model
def test_usable_size_rounding():
    assert usable_size(100) == 112          # round_up(116,16)-16
    assert usable_size(64) == 64            # 恰好
    assert usable_size(1) == 16             # 最小块
    assert 0 <= slack_bytes(0xdead) <= MAX_SLACK


def test_const_relation():
    rel, _ = const_relation(CapExpr.const(100), CapExpr.const(112))
    assert rel == 'CONST_LE'
    rel2, _ = const_relation(CapExpr.const(64), CapExpr.const(128))
    assert rel2 == 'CONST_GT'


def test_arith_relation():
    assert arith_relation(CapExpr.sym('A:1'), CapExpr.arith('A:1', -8))[0] == 'ARITH_LE'
    assert arith_relation(CapExpr.sym('A:1'), CapExpr.arith('A:1', 8))[0] == 'ARITH_SLACK'
    assert arith_relation(CapExpr.sym('A:1'), CapExpr.arith('A:1', 32))[0] == 'ARITH_GT'


# sym_size_tracker
def _mk_insns():
    return [
        I(0x1000, 'mov', 'QWORD PTR [rbp+0x10],rcx', ''),
        I(0x1004, 'mov', 'rax,QWORD PTR [rbp+0x10]', ''),
        I(0x1008, 'mov', 'rcx,rax', ''),
        I(0x100c, 'call', '140003378 <malloc>', ''),
        I(0x1010, 'mov', 'QWORD PTR [rbp-0x8],rax', ''),
        I(0x1014, 'mov', 'rax,QWORD PTR [rbp+0x10]', ''),
        I(0x1018, 'mov', 'rcx,rax', ''),
        I(0x101a, 'mov', 'r8,rcx', ''),
        I(0x101c, 'call', '140003380 <memcpy>', ''),
    ]


def test_tracker_equivalence_size():
    res = SymSizeTracker().analyze_function('f', _mk_insns())
    assert res.allocs[0].size_expr.canonical() == 'A:1'
    assert res.writes[0].size_expr.canonical() == 'A:1'


def test_tracker_movzx_truncation():
    insns = [
        I(0x0ff8, 'mov', 'QWORD PTR [rbp+0x18],rdx', ''),
        I(0x1000, 'mov', 'rax,QWORD PTR [rbp+0x18]', ''),
        I(0x1004, 'movzx', 'eax,ax', ''),
        I(0x1008, 'mov', 'QWORD PTR [rbp-0x8],rax', ''),
        I(0x100c, 'mov', 'rax,QWORD PTR [rbp-0x8]', ''),
        I(0x1010, 'mov', 'rcx,rax', ''),
        I(0x1014, 'call', 'malloc', ''),
        I(0x1018, 'mov', 'rcx,QWORD PTR [rbp+0x18]', ''),
        I(0x101c, 'mov', 'r8,rcx', ''),
        I(0x1020, 'call', 'memcpy', ''),
    ]
    res = SymSizeTracker().analyze_function('g', insns)
    alloc = res.allocs[0].size_expr.canonical()
    write = res.writes[0].size_expr.canonical()
    assert alloc != write, (alloc, write)   # 截断破坏等价


def test_tracker_stack_target():
    insns = [
        I(0x1000, 'lea', 'rcx,[rsp+0x20]', ''),
        I(0x1008, 'mov', 'r8d,0x20', ''),
        I(0x1010, 'call', 'memset', ''),
    ]
    res = SymSizeTracker().analyze_function('s', insns)
    assert res.writes and res.writes[0].dst_is_stack


# guard_dominance
def test_guard_early_exit_safe():
    g = GuardRecord(0x100, 'A:1', 0x40, 'ja', 0x180, taken_le_bound=False)
    ev = analyze_guards_for_write(0x120, 'A:1', [g])
    v, _ = guard_safety_check(ev, CapExpr.const(64), 0)
    assert v == 'SAFE'


def test_guard_clamp_needs_evidence():
    g = GuardRecord(0x100, 'A:1', 0x40, 'jbe', 0x110,
                    taken_le_bound=True, operand_key='rbp:16')
    insns = [
        I(0x100, 'cmp', 'QWORD PTR [rbp+0x10],0x40', ''),
        I(0x108, 'jbe', '0x110', ''),
        I(0x10a, 'mov', 'QWORD PTR [rbp+0x10],0x40', ''),
        I(0x120, 'call', 'memcpy', ''),
    ]
    ev = analyze_guards_for_write(0x120, 'A:1', [g], insns)
    assert ev.safe_upper_bound == 0x40
    # 无钳位 → 不构成安全证据
    ev2 = analyze_guards_for_write(0x120, 'A:1', [g],
                                   insns[:2])
    assert ev2.safe_upper_bound is None


# equivalence
def test_equiv_self_consistent():
    r = classify_pair(CapExpr.sym('A:1'), CapExpr.sym('A:1'), False, None)
    assert r.relation == 'EQUIV'


def test_equiv_unrelated():
    r = classify_pair(CapExpr.sym('A:1'), CapExpr.sym('A:2'), False, None)
    assert r.relation == 'UNRELATED'


# verdict
def test_verdict_mapping():
    assert evaluate(CapExpr.sym('A:1'), CapExpr.sym('A:1'),
                    False, None).verdict == Verdict.SAFE
    assert evaluate(CapExpr.const(64), CapExpr.const(128),
                    False, None).verdict == Verdict.VULN_CONFIRMED
    assert evaluate(CapExpr.sym('A:1'), CapExpr.sym('A:2'),
                    False, None).verdict == Verdict.VULN_LIKELY


def test_verdict_offset():
    # size 32 + offset 200 超出 usable 208 → CONFIRMED
    v = evaluate(CapExpr.const(200), CapExpr.const(32), False, None,
                 write_offset=200)
    assert v.verdict == Verdict.VULN_CONFIRMED, v


def test_verdict_summary_conservative():
    vs = [
        evaluate(CapExpr.sym('A:1'), CapExpr.sym('A:1'), False, None),
        evaluate(CapExpr.const(64), CapExpr.const(128), False, None),
        evaluate(CapExpr.sym('A:1'), CapExpr.sym('A:2'), False, None),
    ]
    s = summarize(vs)
    assert s['safe_filtered'] == 1 and s['kept'] == 2
