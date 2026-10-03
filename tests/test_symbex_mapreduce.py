"""
Tests for MapReduce-style symbolic execution.
"""
import unittest

from modules.analysis.symbolic.symbex_mapreduce import (
    SymbExMapReduce,
    MapReduceResult,
    SubProblem,
    SubResult,
    PathMerger,
)


class TestSubProblem(unittest.TestCase):
    def test_creation(self):
        sp = SubProblem(problem_id="p1", function_name="vuln_func", address_range=(0x4000, 0x5000))
        self.assertEqual(sp.problem_id, "p1")
        self.assertEqual(sp.address_range, (0x4000, 0x5000))


class TestSubResult(unittest.TestCase):
    def test_creation(self):
        sr = SubResult(problem_id="p1", paths_found=10)
        self.assertEqual(sr.paths_found, 10)


class TestMapReduceResult(unittest.TestCase):
    def test_creation(self):
        result = MapReduceResult(
            total_paths=50,
            unique_constraints=["x > 0"],
            crash_inputs=[b"AAAA"],
        )
        self.assertEqual(result.total_paths, 50)
        self.assertEqual(len(result.crash_inputs), 1)


class TestPathMerger(unittest.TestCase):
    def test_merge_empty(self):
        result = PathMerger.merge([])
        self.assertEqual(len(result), 0)


class TestSymbExMapReduce(unittest.TestCase):
    def setUp(self):
        self.engine = SymbExMapReduce()

    def test_creation(self):
        self.assertIsNotNone(self.engine)

    def test_get_stats(self):
        stats = self.engine.get_stats()
        self.assertIsInstance(stats, dict)

    def test_run(self):
        result = self.engine.run()
        self.assertIsNotNone(result)

    def test_reset(self):
        self.engine.reset()
        self.assertIsNotNone(self.engine)


if __name__ == "__main__":
    unittest.main()
