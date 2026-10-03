"""
Tests for coverage-guided symbolic exploration.

Covers: ExplorationStrategy, CoverageMetric, CoverageInfo, CoverageTracker,
CoverageGuidedSymbolicExecutor, CoverageDeltaTracker.
"""
import unittest

from modules.analysis.symbolic.coverage_guided_symbex import (
    ExplorationStrategy,
    CoverageMetric,
    CoverageInfo,
    PathState,
    CoverageTracker,
    CoverageGuidedSymbolicExecutor,
    CoverageDeltaTracker,
    DictionaryGenerator,
)


class TestExplorationStrategy(unittest.TestCase):
    def test_all_strategies(self):
        for s in [ExplorationStrategy.GREEDY, ExplorationStrategy.GENETIC,
                   ExplorationStrategy.RANDOM, ExplorationStrategy.HYBRID]:
            self.assertIsInstance(s.value, str)


class TestCoverageMetric(unittest.TestCase):
    def test_all_metrics(self):
        for m in [CoverageMetric.BLOCK, CoverageMetric.EDGE,
                   CoverageMetric.PATH, CoverageMetric.FUNCTION]:
            self.assertIsInstance(m.value, str)


class TestCoverageInfo(unittest.TestCase):
    def test_empty(self):
        ci = CoverageInfo()
        self.assertEqual(len(ci.blocks), 0)

    def test_with_blocks(self):
        ci = CoverageInfo(blocks={0x1000, 0x1005}, total_blocks=100)
        self.assertEqual(len(ci.blocks), 2)

    def test_coverage_ratio(self):
        ci = CoverageInfo(blocks={0x1000}, total_blocks=10)
        ratio = ci.coverage_ratio(CoverageMetric.BLOCK)
        self.assertAlmostEqual(ratio, 0.1)

    def test_coverage_ratio_zero_total(self):
        ci = CoverageInfo(total_blocks=0)
        self.assertEqual(ci.coverage_ratio(CoverageMetric.BLOCK), 0.0)


class TestPathState(unittest.TestCase):
    def test_default(self):
        ps = PathState(path_id="p1")
        self.assertFalse(ps.explored)

    def test_score(self):
        ps = PathState(path_id="p2", coverage_gain=0.5, risk_score=0.8)
        score = ps.score()
        self.assertAlmostEqual(score, 0.6 * 0.5 + 0.4 * 0.8)


class TestCoverageTracker(unittest.TestCase):
    def setUp(self):
        self.tracker = CoverageTracker()

    def test_initial_empty(self):
        ci = self.tracker.get_current()
        self.assertEqual(len(ci.blocks), 0)

    def test_record_new_blocks(self):
        new = self.tracker.record(blocks={0x1000, 0x1005}, edges=set())
        self.assertEqual(new, 2)

    def test_record_duplicates(self):
        self.tracker.record(blocks={0x1000}, edges=set())
        new = self.tracker.record(blocks={0x1000}, edges=set())
        self.assertEqual(new, 0)

    def test_set_total(self):
        self.tracker.set_total(total_blocks=100, total_edges=200)
        ci = self.tracker.get_current()
        self.assertEqual(ci.total_blocks, 100)


class TestCoverageGuidedSymbolicExecutor(unittest.TestCase):
    def setUp(self):
        self.executor = CoverageGuidedSymbolicExecutor()

    def test_creation(self):
        self.assertIsNotNone(self.executor)

    def test_get_stats(self):
        stats = self.executor.get_stats()
        self.assertIsInstance(stats, dict)

    def test_step(self):
        result = self.executor.step()
        self.assertIsInstance(result, dict)


class TestCoverageDeltaTracker(unittest.TestCase):
    def test_creation(self):
        tracker = CoverageDeltaTracker()
        self.assertIsNotNone(tracker)


class TestDictionaryGenerator(unittest.TestCase):
    def test_extract_tokens_empty(self):
        tokens = DictionaryGenerator.extract_tokens(b"")
        self.assertEqual(len(tokens), 0)


if __name__ == "__main__":
    unittest.main()
