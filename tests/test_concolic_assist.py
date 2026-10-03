"""Tests for concolic_assist (TACE-inspired concolic execution assistant)."""
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import pytest
from modules.dynamic_analysis.concolic_assist import (
    SymbolicByte, SymbolType, PathConstraint, ConcolicState,
    TaintSymbolBridge, DependencyTracker, ConcolicAssistant,
    create_concolic_assistant
)


class TestTaintSymbolBridge:
    def test_mark_and_query(self):
        b = TaintSymbolBridge()
        b.mark_address_tainted(0x7fff0000, 0x01)
        assert b.is_tainted(0x7fff0000)
        assert not b.is_tainted(0x99990000)

    def test_register_taint(self):
        b = TaintSymbolBridge()
        b.mark_register_tainted('rdi', 0x02)
        assert b._tainted_regs['rdi'] == 0x02

    def test_classify_symbol(self):
        b = TaintSymbolBridge()
        b.mark_address_tainted(0x1000, 0x01)
        sb = SymbolicByte(address=0x1000, sym_type=SymbolType.SYMBOLIC,
                          symbol_name='test')
        new_type = b.classify_symbol(sb)
        assert new_type == SymbolType.TAINTED_SYMBOLIC
        assert sb.taint_tags == 0x01

    def test_classify_untainted(self):
        b = TaintSymbolBridge()
        sb = SymbolicByte(address=0x9999, sym_type=SymbolType.SYMBOLIC,
                          symbol_name='clean')
        new_type = b.classify_symbol(sb)
        assert new_type == SymbolType.SYMBOLIC
        assert sb.taint_tags == 0


class TestDependencyTracker:
    def test_record_move(self):
        dt = DependencyTracker()
        dt.record_symbolic_source('rax', 0x1000)
        dt.record_move('rbx', 'rax')
        deps = dt.get_dependencies('rbx')
        assert 0x1000 in deps

    def test_record_concrete(self):
        dt = DependencyTracker()
        dt.record_symbolic_source('rax', 0x2000)
        dt.record_concrete('rax')
        assert len(dt.get_dependencies('rax')) == 0

    def test_load_store_chain(self):
        dt = DependencyTracker()
        dt.record_symbolic_source('rax', 0x3000)
        dt.record_store(0x7fff0000, 'rax')
        dt.record_load('rcx', 0x7fff0000)
        deps = dt.get_dependencies('rcx')
        assert 0x3000 in deps


class TestConcolicAssistant:
    def test_create_symbolic_input(self):
        ca = ConcolicAssistant()
        addrs = ca.create_symbolic_input(0x7fff0000, 16, prefix='arg0')
        assert len(addrs) == 16
        assert ca._stats['symbols_created'] == 16

    def test_on_branch_no_taint(self):
        ca = ConcolicAssistant()
        sym_addrs = ca.create_symbolic_input(0x1000, 4)
        constraint = ca.on_branch(0x401000, 'eax == 0',
                                   involved_addrs=sym_addrs, taken=True)
        assert not constraint.is_tainted
        assert constraint.constraint_id == -1  # not sent to solver

    def test_on_branch_with_taint(self):
        bridge = TaintSymbolBridge()
        bridge.mark_address_tainted(0x1000, 1)
        ca = ConcolicAssistant(taint_bridge=bridge)
        sym_addrs = ca.create_symbolic_input(0x1000, 4)
        constraint = ca.on_branch(0x401000, 'eax == 1',
                                   involved_addrs=sym_addrs, taken=True)
        assert constraint.is_tainted
        assert constraint.constraint_id >= 0  # sent to solver

    def test_concretize_rate(self):
        ca = ConcolicAssistant()
        ca.create_symbolic_input(0x1000, 100)
        # concretize half
        for i in range(50):
            ca.mark_concrete(0x1000 + i)
        assert ca.get_concretization_rate() == 0.5

    def test_save_restore_state(self):
        ca = ConcolicAssistant()
        ca.create_symbolic_input(0x1000, 4)
        state = ca.save_state(0x401000)
        # concretize and save again
        ca.mark_concrete(0x1000)
        ca.restore_state(state)
        # should have all 4 symbolic again
        assert len(ca._symbolic_bytes) == 4

    def test_get_tainted_constraints(self):
        bridge = TaintSymbolBridge()
        bridge.mark_address_tainted(0x1000, 1)
        ca = ConcolicAssistant(taint_bridge=bridge)
        addrs = ca.create_symbolic_input(0x1000, 4)
        ca.on_branch(0x401000, 'x < 10', involved_addrs=addrs)
        ca.on_branch(0x401010, 'x < 10', involved_addrs=addrs[:2])
        tainted = ca.get_tainted_constraints()
        assert len(tainted) == 2  # both involve tainted addr

    def test_factory_helper(self):
        ca = create_concolic_assistant(
            tainted_addrs=[0x7fff0000, 0x7fff0001],
            tainted_regs=['rdi'])
        assert ca.bridge.is_tainted(0x7fff0000)
        assert ca.bridge._tainted_regs.get('rdi') == 1

    def test_stats_accurate(self):
        ca = ConcolicAssistant()
        ca.create_symbolic_input(0x1000, 4)
        ca.on_branch(0x401000, 'test', involved_addrs=[0x1000])
        stats = ca.get_stats()
        assert stats['branches_total'] == 1
        assert stats['active_symbols'] == 4


class TestSymbolicByte:
    def test_default(self):
        sb = SymbolicByte()
        assert sb.sym_type == SymbolType.CONCRETE
        assert sb.concrete_value == 0

    def test_symbolic(self):
        sb = SymbolicByte(address=0x7fff0000,
                          sym_type=SymbolType.TAINTED_SYMBOLIC,
                          symbol_name='stdin_0',
                          taint_tags=0x03)
        assert sb.sym_type == SymbolType.TAINTED_SYMBOLIC
        assert sb.taint_tags == 0x03
