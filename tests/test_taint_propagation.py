"""Tests for taint propagation module (fixed version)."""
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import pytest
from modules.dynamic_analysis.taint_propagation import (
    TaintSource, TaintSink, TaintLevel, TaintInfo,
    BitSet, TaintEngine, TaintAnalysis, TaintChecker,
    create_taint_analysis, run_taint_analysis
)


class TestBitSet:
    def test_set_get(self):
        bs = BitSet(256)
        assert not bs.get(0)
        bs.set(0)
        assert bs.get(0)
        assert not bs.get(1)

    def test_set_range(self):
        bs = BitSet(256)
        bs.set_range(10, 16)
        for i in range(10, 26):
            assert bs.get(i), f"bit {i} should be set"
        assert not bs.get(9)
        assert not bs.get(26)

    def test_clear(self):
        bs = BitSet(256)
        bs.set(5)
        bs.clear(5)
        assert not bs.get(5)

    def test_union(self):
        a, b = BitSet(256), BitSet(256)
        a.set(1); b.set(2)
        u = a.union(b)
        assert u.get(1) and u.get(2)

    def test_difference(self):
        a, b = BitSet(256), BitSet(256)
        a.set(1); a.set(2); b.set(2)
        d = a.difference(b)
        assert d.get(1) and not d.get(2)

    def test_is_empty(self):
        assert BitSet(256).is_empty()
        bs = BitSet(256); bs.set(100)
        assert not bs.is_empty()

    def test_count(self):
        bs = BitSet(256)
        bs.set(0); bs.set(63); bs.set(64)
        assert bs.count() == 3

    def test_index_error(self):
        bs = BitSet(64)
        with pytest.raises(IndexError):
            bs.set(64)
        with pytest.raises(IndexError):
            bs.set(-1)

    def test_copy_independent(self):
        a = BitSet(256); a.set(42)
        b = a.copy()
        b.clear(42)
        assert a.get(42)
        assert not b.get(42)


class TestTaintEngine:
    def test_add_source(self):
        eng = TaintEngine(64)
        eng.add_taint_source(0, TaintSource.USER_INPUT)
        assert eng.is_tainted(0)
        assert eng.get_taint_info(0).source == TaintSource.USER_INPUT

    def test_propagation_basic(self):
        eng = TaintEngine(64)
        eng.add_taint_source(0, TaintSource.USER_INPUT)
        eng.add_propagation_rule([0], [1, 2])
        eng.propagate()
        assert eng.is_tainted(1)
        assert eng.is_tainted(2)

    def test_no_false_positive(self):
        eng = TaintEngine(64)
        eng.add_taint_source(0, TaintSource.USER_INPUT)
        eng.add_propagation_rule([1], [2])  # src 1 is clean
        eng.propagate()
        assert not eng.is_tainted(2)

    def test_transitive(self):
        eng = TaintEngine(64)
        eng.add_taint_source(0, TaintSource.NETWORK_DATA)
        eng.add_propagation_rule([0], [1])
        eng.add_propagation_rule([1], [2])
        eng.propagate()
        assert eng.is_tainted(2)

    def test_clear(self):
        eng = TaintEngine(64)
        eng.add_taint_source(0, TaintSource.USER_INPUT)
        eng.clear()
        assert not eng.is_tainted(0)
        assert len(eng.get_all_tainted()) == 0


class TestTaintAnalysis:
    def test_register_variable(self):
        ta = TaintAnalysis()
        assert ta.register_variable('eax') == 0
        assert ta.register_variable('ebx') == 1
        assert ta.register_variable('eax') == 0  # same id

    def test_taint_check(self):
        ta = TaintAnalysis()
        ta.taint_variable('buf', TaintSource.FILE_READ)
        ta.run()
        assert ta.check_taint('buf')
        assert not ta.check_taint('unknown')

    def test_propagation_by_name(self):
        ta = TaintAnalysis()
        ta.taint_variable('src', TaintSource.USER_INPUT)
        ta.add_propagation(['src'], ['dst'])
        ta.run()
        assert ta.check_taint('dst')

    def test_find_paths(self):
        ta = TaintAnalysis()
        ta.taint_variable('inp', TaintSource.USER_INPUT)
        ta.add_propagation(['inp'], ['mid'])
        ta.add_propagation(['mid'], ['sink'])
        ta.run()
        paths = ta.find_taint_paths('sink')
        assert len(paths) > 0

    def test_no_path_for_clean(self):
        ta = TaintAnalysis()
        paths = ta.find_taint_paths('nonexistent')
        assert paths == []


class TestTaintChecker:
    def test_check_sinks(self):
        ta = TaintAnalysis()
        ta.taint_variable('inp', TaintSource.NETWORK_DATA)
        ta.add_propagation(['inp'], ['system'])
        ta.run()

        checker = TaintChecker()
        checker.register_sink('system', TaintSink.SHELL_EXEC)
        results = checker.check_sinks(ta)
        assert len(results) == 1
        assert results[0]['is_vulnerable']


class TestConvenienceFunctions:
    def test_run_taint_analysis(self):
        results = run_taint_analysis(
            sources=[('net_data', TaintSource.NETWORK_DATA)],
            propagations=[(['net_data'], ['send_data'])],
            sinks=['send_data'])
        assert len(results) > 0
        assert results[0]['function'] == 'send_data'

    def test_create_taint_analysis(self):
        ta = create_taint_analysis()
        assert isinstance(ta, TaintAnalysis)
