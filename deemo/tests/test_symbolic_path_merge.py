"""
Tests for symbolic path merging strategies.
"""
import unittest

from modules.analysis.symbolic.symbolic_path_merge import (
    MergePolicyEngine,
    MergeStrategy,
    MergePolicy,
    MergeResult,
    MergeCandidate,
    PathMerger,
    SymbolicState,
    MergeHeuristic,
    MergeQualityReport,
)


class TestMergeStrategy(unittest.TestCase):
    def test_all_strategies(self):
        for s in [MergeStrategy.NONE, MergeStrategy.BY_PC,
                   MergeStrategy.BY_CONSTRAINTS, MergeStrategy.ADAPTIVE]:
            self.assertIsInstance(s.value, str)


class TestMergePolicy(unittest.TestCase):
    def test_default(self):
        policy = MergePolicy()
        self.assertEqual(policy.strategy, MergeStrategy.ADAPTIVE)

    def test_custom(self):
        policy = MergePolicy(strategy=MergeStrategy.BY_PC, max_states_before_merge=500)
        self.assertEqual(policy.max_states_before_merge, 500)


class TestSymbolicState(unittest.TestCase):
    def test_creation(self):
        state = SymbolicState(state_id="s1", pc=0x4000)
        self.assertEqual(state.state_id, "s1")
        self.assertEqual(state.pc, 0x4000)

    def test_with_constraints(self):
        state = SymbolicState(state_id="s2", pc=0x5000, constraints=["x > 0"])
        self.assertEqual(len(state.constraints), 1)


class TestMergeCandidate(unittest.TestCase):
    def test_creation(self):
        mc = MergeCandidate(states=["s1", "s2"], pc=0x4000)
        self.assertEqual(len(mc.states), 2)


class TestMergeResult(unittest.TestCase):
    def test_creation(self):
        result = MergeResult(merged_states=1, states_reduced=3)
        self.assertEqual(result.merged_states, 1)
        self.assertEqual(result.states_reduced, 3)


class TestPathMerger(unittest.TestCase):
    def test_merge_empty(self):
        merged = PathMerger.merge([])
        self.assertEqual(len(merged), 0)


class TestMergePolicyEngine(unittest.TestCase):
    def setUp(self):
        self.engine = MergePolicyEngine()

    def test_creation(self):
        self.assertIsNotNone(self.engine)

    def test_get_stats(self):
        stats = self.engine.get_stats()
        self.assertIsInstance(stats, dict)


class TestMergeHeuristic(unittest.TestCase):
    def test_all_heuristics(self):
        for h in MergeHeuristic:
            self.assertIsInstance(h.value, str)


class TestMergeQualityReport(unittest.TestCase):
    def test_creation(self):
        report = MergeQualityReport()
        self.assertIsNotNone(report)


if __name__ == "__main__":
    unittest.main()
