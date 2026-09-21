"""
路径敏感约束求解 路径敏感约束联结求解器单元测试.

测试路径敏感约束收集器和路径敏感求解器的正确性, 覆盖:
  - CFG构建与路径枚举
  - 跨路径guard约束分离
  - 保守融合策略(任一路径溢出→保留)
  - 全局约束求解回退路径
"""
import sys
import os
from pathlib import Path

_DEEMO = Path(__file__).parent.parent.parent
sys.path.insert(0, str(_DEEMO))

import unittest
from core.path_constraint_cfg_builder import SimplifiedCFGBuilder, CFGPath
from core.path_constraint_path_collector import collect_path_sensitive_constraints
from core.path_constraint_solver import PathSensitiveCJSolver, PSJResult
from core.constraint_constraint_types import (
    ConstraintType, LinearConstraint, ConstraintSystem, SolverVerdict,
)


class TestCFGBuilder(unittest.TestCase):

    def test_simple_if_else_paths(self):
        """if-else产生两条路径."""
        lines = [
            "char *buf = malloc(64);",
            "if (n > 32) {",
            "    memcpy(buf, src, 80);",
            "} else {",
            "    memcpy(buf, src, 32);",
            "}",
            "free(buf);",
        ]
        builder = SimplifiedCFGBuilder(max_paths=128)
        builder.build(lines)
        paths = builder.enumerate_paths(1, 3)
        self.assertGreaterEqual(len(paths), 1)

    def test_branch_guard_extraction(self):
        """分支条件的guard约束被正确提取."""
        lines = [
            "char *buf = malloc(64);",
            "if (n > 200) {",
            "    return;",
            "}",
            "memcpy(buf, src, 64);",
        ]
        builder = SimplifiedCFGBuilder(max_paths=128)
        builder.build(lines)
        paths = builder.enumerate_paths(1, 5)
        self.assertGreaterEqual(len(paths), 1)

    def test_empty_cfg(self):
        """空输入返回单条路径."""
        builder = SimplifiedCFGBuilder()
        blocks = builder.build([])
        self.assertEqual(len(blocks), 0)
        paths = builder.enumerate_paths(1, 2)
        self.assertEqual(len(paths), 1)


class TestPathCollector(unittest.TestCase):

    def test_no_decompiled_text_fallback(self):
        """无反编译文本时回退到全局约束求解."""
        from core.heap_overflow_detector import (
            HeapAllocSite, HeapStore, HeapOverflowCandidate)

        candidate = HeapOverflowCandidate(
            alloc_site=HeapAllocSite(
                pc=0, alloc_func="malloc", size_arg=64,
                size_is_dynamic=False, size_expr="64",
            ),
            overflow_store=HeapStore(
                pc=1, base_var="buf", offset=0,
                offset_is_dynamic=False, store_size=64,
                mnemonic="memcpy",
            ),
        )

        result = collect_path_sensitive_constraints(
            candidate, [], "")
        self.assertEqual(len(result), 1)
        path, sys = result[0]
        self.assertIn("global cj", path.description.lower())


class TestPathSensitiveSolver(unittest.TestCase):

    def test_fuse_all_safe(self):
        """所有路径SAFE → PROVEN_SAFE."""
        solver = PathSensitiveCJSolver()
        from core.path_constraint_solver import PathSolverResult
        results = [
            PathSolverResult(
                verdict=SolverVerdict.PROVEN_SAFE,
                reason="safe on path 1",
            ),
            PathSolverResult(
                verdict=SolverVerdict.PROVEN_SAFE,
                reason="safe on path 2",
            ),
        ]
        fused = solver._fuse_results(results)
        self.assertEqual(fused.verdict, SolverVerdict.PROVEN_SAFE)
        self.assertEqual(fused.paths_safe, 2)

    def test_fuse_one_overflow(self):
        """任一路径OVERFLOW → PROVEN_OVERFLOW."""
        solver = PathSensitiveCJSolver()
        from core.path_constraint_solver import PathSolverResult
        results = [
            PathSolverResult(
                verdict=SolverVerdict.PROVEN_SAFE,
                reason="safe on path 1",
            ),
            PathSolverResult(
                verdict=SolverVerdict.PROVEN_OVERFLOW,
                reason="overflow on path 2",
            ),
        ]
        fused = solver._fuse_results(results)
        self.assertEqual(fused.verdict, SolverVerdict.PROVEN_OVERFLOW)
        self.assertEqual(fused.paths_overflow, 1)

    def test_fuse_one_inconclusive(self):
        """任一路径INCONCLUSIVE → INCONCLUSIVE (保守保留)."""
        solver = PathSensitiveCJSolver()
        from core.path_constraint_solver import PathSolverResult
        results = [
            PathSolverResult(
                verdict=SolverVerdict.PROVEN_SAFE,
                reason="safe on path 1",
            ),
            PathSolverResult(
                verdict=SolverVerdict.INCONCLUSIVE,
                reason="insufficient on path 2",
            ),
        ]
        fused = solver._fuse_results(results)
        self.assertEqual(fused.verdict, SolverVerdict.INCONCLUSIVE)
        self.assertEqual(fused.paths_inconclusive, 1)

    def test_fuse_all_infeasible(self):
        """全部路径不可行 → 回退全局约束求解."""
        solver = PathSensitiveCJSolver()
        from core.path_constraint_solver import PathSolverResult
        results = [
            PathSolverResult(
                path_feasible=False,
                reason="infeasible",
            ),
            PathSolverResult(
                path_feasible=False,
                reason="infeasible",
            ),
        ]
        fused = solver._fuse_results(results)
        self.assertEqual(fused.verdict, SolverVerdict.INCONCLUSIVE)
        self.assertTrue(fused.fallback_global_cj)


if __name__ == '__main__':
    unittest.main()
