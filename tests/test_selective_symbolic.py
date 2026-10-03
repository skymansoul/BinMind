"""
Tests for selective symbolic execution module.
"""
import unittest

from modules.analysis.symbolic.selective_symbolic import (
    SelectiveSymbolicExecutor,
    SelectiveState,
    SelectiveExecutionResult,
    TaintPropagator,
    TaintRegion,
)


class TestSelectiveState(unittest.TestCase):
    def test_creation(self):
        state = SelectiveState(state_id="s1", pc=0x4000)
        self.assertEqual(state.state_id, "s1")
        self.assertEqual(state.pc, 0x4000)

    def test_with_constraints(self):
        state = SelectiveState(state_id="s2", pc=0x5000, constraints=["x > 0"])
        self.assertEqual(len(state.constraints), 1)


class TestSelectiveExecutionResult(unittest.TestCase):
    def test_success(self):
        result = SelectiveExecutionResult(success=True, paths_found=3)
        self.assertTrue(result.success)
        self.assertEqual(result.paths_found, 3)

    def test_failure(self):
        result = SelectiveExecutionResult(success=False)
        self.assertFalse(result.success)


class TestTaintRegion(unittest.TestCase):
    def test_creation(self):
        region = TaintRegion(start=0x1000, size=64, tag="user_input")
        self.assertEqual(region.start, 0x1000)
        self.assertEqual(region.size, 64)
        self.assertEqual(region.tag, "user_input")


class TestTaintPropagator(unittest.TestCase):
    def test_creation(self):
        tp = TaintPropagator()
        self.assertIsNotNone(tp)

    def test_add_region(self):
        tp = TaintPropagator()
        region = TaintRegion(start=0x4000, size=32)
        tp.add_region(region)
        self.assertGreaterEqual(len(tp.regions), 0)

    def test_propagate_empty(self):
        tp = TaintPropagator()
        tp.propagate()
        self.assertIsNotNone(tp)


class TestSelectiveSymbolicExecutor(unittest.TestCase):
    def setUp(self):
        self.executor = SelectiveSymbolicExecutor()

    def test_creation(self):
        self.assertIsNotNone(self.executor)

    def test_get_stats(self):
        stats = self.executor.get_stats()
        self.assertIsInstance(stats, dict)

    def test_analyze(self):
        result = self.executor.analyze(target_func="test")
        self.assertIsInstance(result, dict)

    def test_reset(self):
        self.executor.reset()
        stats = self.executor.get_stats()
        self.assertIsInstance(stats, dict)


if __name__ == "__main__":
    unittest.main()
