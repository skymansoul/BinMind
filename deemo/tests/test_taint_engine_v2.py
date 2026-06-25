"""Tests for taint engine v2 (AirTaint-inspired BB-level taint)."""
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import pytest
from modules.dynamic_analysis.taint_engine_v2 import (
    TaintTag, TaintSource, TaintSink, Arch, RegTaintMap, MemTaintMap,
    MemTaintChunk, BBTaintRule, TaintPolicy, TaintEngineV2,
    TaintViolation, default_unix_policy, default_win32_policy
)


class TestRegTaintMap:
    def test_init_clean(self):
        rt = RegTaintMap(Arch.X64)
        for r in ['rax', 'rbx', 'rcx', 'rdx']:
            assert rt.get(r) == TaintTag.CLEAN

    def test_set_get(self):
        rt = RegTaintMap(Arch.X64)
        rt.set('rax', TaintTag.USER_INPUT)
        assert rt.get('rax') == TaintTag.USER_INPUT

    def test_union(self):
        rt = RegTaintMap(Arch.X64)
        rt.set('rdi', TaintTag.USER_INPUT)
        rt.set('rsi', TaintTag.NETWORK)
        merged = rt.union('rax', 'rdi', 'rsi')
        assert merged & TaintTag.USER_INPUT
        assert merged & TaintTag.NETWORK

    def test_snapshot_restore(self):
        rt = RegTaintMap(Arch.X64)
        rt.set('rax', TaintTag.FILE)
        snap = rt.snapshot()
        rt.clear('rax')
        assert rt.get('rax') == TaintTag.CLEAN
        rt.restore(snap)
        assert rt.get('rax') == TaintTag.FILE

    def test_x86_regs(self):
        rt = RegTaintMap(Arch.X86)
        assert 'eax' in rt._tags
        assert 'rax' not in rt._tags

    def test_flag_tags(self):
        rt = RegTaintMap(Arch.X64)
        rt.set('zf', TaintTag.USER_INPUT)
        assert rt.is_tainted('zf')


class TestMemTaintChunk:
    def test_set_get_single_byte(self):
        chunk = MemTaintChunk(0x1000)
        chunk.set(0, TaintTag.USER_INPUT)
        assert chunk.get(0) == TaintTag.USER_INPUT

    def test_set_range(self):
        chunk = MemTaintChunk(0x1000)
        chunk.set_range(100, 20, TaintTag.NETWORK)
        assert chunk.get(100) == TaintTag.NETWORK
        assert chunk.get(119) == TaintTag.NETWORK
        assert chunk.get(99) == TaintTag.CLEAN
        assert chunk.get(120) == TaintTag.CLEAN

    def test_any_tainted_in_range(self):
        chunk = MemTaintChunk(0x1000)
        chunk.set(500, TaintTag.FILE)
        assert chunk.any_tainted_in_range(490, 20)
        assert not chunk.any_tainted_in_range(0, 100)

    def test_collapse_at_threshold(self):
        # Create a chunk and fill >50% — it should collapse to full_taint
        chunk = MemTaintChunk(0x1000)
        # taint more than half
        for i in range(0, 4096, 2):
            chunk.set(i, TaintTag.USER_INPUT)
        # Now it should be collapsed
        assert chunk.full_taint != TaintTag.CLEAN
        # byte_tags should be gone
        assert len(chunk.byte_tags) == 0


class TestMemTaintMap:
    def test_sparse_allocation(self):
        mm = MemTaintMap()
        mm.set(0x7fff0000, TaintTag.USER_INPUT)
        assert mm.is_tainted(0x7fff0000)
        assert not mm.is_tainted(0x10000000)
        assert mm.chunk_count >= 1

    def test_set_range_cross_chunks(self):
        mm = MemTaintMap()
        # span across two 4KB chunks
        mm.set_range(0x1000 - 10, 30, TaintTag.NETWORK)
        assert mm.is_tainted(0xfff)  # end of first chunk
        assert mm.is_tainted(0x1005)  # start of second chunk

    def test_any_in_range(self):
        mm = MemTaintMap()
        mm.set(0x400000, TaintTag.FILE)
        assert mm.any_in_range(0x3ffff0, 20)
        assert not mm.any_in_range(0x401000, 100)

    def test_clear(self):
        mm = MemTaintMap()
        mm.set(0x500000, TaintTag.USER_INPUT)
        mm.clear()
        assert mm.chunk_count == 0
        assert not mm.is_tainted(0x500000)


class TestBBTaintRule:
    def test_match_on_tainted_input_reg(self):
        rt = RegTaintMap(Arch.X64)
        rt.set('rax', TaintTag.USER_INPUT)
        rule = BBTaintRule('r1', input_regs=frozenset(['rax']),
                           output_regs=frozenset(['rbx']))
        assert rule.match(rt, MemTaintMap(), {'rax': 0x1000})

    def test_no_match_on_clean(self):
        rt = RegTaintMap(Arch.X64)
        rule = BBTaintRule('r1', input_regs=frozenset(['rax']),
                           output_regs=frozenset(['rbx']))
        assert not rule.match(rt, MemTaintMap(), {'rax': 0})

    def test_apply_taints_output(self):
        rt = RegTaintMap(Arch.X64)
        rt.set('rax', TaintTag.USER_INPUT)
        rule = BBTaintRule('r1', input_regs=frozenset(['rax']),
                           output_regs=frozenset(['rbx', 'rcx']))
        rule.apply(rt, MemTaintMap(), {'rax': 0})
        assert rt.is_tainted('rbx')
        assert rt.is_tainted('rcx')


class TestTaintEngineV2:
    def test_source_detection(self):
        policy = default_unix_policy()
        eng = TaintEngineV2(policy)
        assert policy.is_source('read')
        assert policy.is_sink('execve')
        assert not policy.is_source('nonexistent')

    def test_process_bb_source(self):
        eng = TaintEngineV2(default_unix_policy())
        events = [{
            'type': 'syscall',
            'func_name': 'read',
            'args': [3, 0x7fff0000, 1024],
            'regs_out': {'rax': 1024, 'rdi': 3},
        }]
        eng.process_bb(events)
        assert eng.reg_taint.is_tainted('rax')

    def test_process_bb_sink_violation(self):
        eng = TaintEngineV2(default_unix_policy())
        # First: taint via 'recv'
        eng.process_bb([{
            'type': 'syscall',
            'func_name': 'recv',
            'args': [4, 0x7fff1000, 256, 0],
            'regs_out': {'rax': 128, 'rdi': 4},
        }])
        # rax is now tainted. simulate mov rax -> rdi
        eng.reg_taint.union('rdi', 'rax')
        # Second: sink check — 'execve'
        eng.process_bb([{
            'type': 'syscall',
            'func_name': 'execve',
            'args': [0x7fff1000, 0, 0],
            'regs_in': {'rdi': 0x7fff1000},
        }])
        violations = eng.check_violations()
        assert len(violations) >= 1

    def test_bb_rule_fires(self):
        policy = TaintPolicy("test")
        policy.add_rule(BBTaintRule(
            'mov_rax_rbx', input_regs=frozenset(['rax']),
            output_regs=frozenset(['rbx'])))
        eng = TaintEngineV2(policy)
        eng.reg_taint.set('rax', TaintTag.USER_INPUT)
        eng.process_bb([{
            'type': 'instr',
            'regs_in': {'rax': 42},
            'regs_out': {'rbx': 42},
        }])
        assert eng.reg_taint.is_tainted('rbx')
        assert eng.get_stats()['rules_fired'] >= 1


class TestPolicies:
    def test_unix_policy_has_sources(self):
        p = default_unix_policy()
        assert len(p.sources) > 0
        assert 'read' in p.sources

    def test_win32_policy_has_sinks(self):
        p = default_win32_policy()
        assert len(p.sinks) > 0
        assert 'CreateProcess' in p.sinks


class TestTaintTag:
    def test_flags_combined(self):
        combined = TaintTag.USER_INPUT | TaintTag.NETWORK
        assert combined & TaintTag.USER_INPUT
        assert combined & TaintTag.NETWORK
        assert not (combined & TaintTag.FILE)

    def test_any_matches(self):
        assert TaintTag.USER_INPUT & TaintTag.ANY
        assert TaintTag.POISON & TaintTag.ANY
