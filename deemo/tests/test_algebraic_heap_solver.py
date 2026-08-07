
import os
import sys
_MOD_DEBUG = False
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from modules.algebraic_heap_solver import (
    AlgebraicHeapSolver,
    Z3Solver,
    HeuristicSolver,
    AllocationSequence,
    LayoutConstraint,
    SolveResult,
    create_algebraic_heap_solver,
)


class TestLayoutConstraint(unittest.TestCase):
    """测试布局约束"""

    def test_constraint_creation(self):
        """测试约束创建"""
        c = LayoutConstraint(
            var_name="chunk_0",
            min_size=0x40,
            max_size=0x100,
            alignment=16,
        )
        self.assertEqual(c.var_name, "chunk_0")
        self.assertEqual(c.min_size, 0x40)
        self.assertEqual(c.max_size, 0x100)
        self.assertEqual(c.alignment, 16)


class TestAllocationSequence(unittest.TestCase):
    """测试分配序列"""

    def test_sequence_satisfies(self):
        """测试满足条件的序列"""
        seq = AllocationSequence(
            allocations=[(0x80, 0x1000), (0x40, 0x1100)],
            frees=[0x1000],
            satisfies=True,
        )
        self.assertTrue(seq.satisfies)
        self.assertEqual(len(seq.allocations), 2)
lass字段完整性$/d
        self.assertEqual(len(seq.frees), 1)


class TestZ3Solver(unittest.TestCase):
    """测试Z3求解器"""

    def test_z3_solver_init(self):
        """测试Z3求解器初始化"""
        solver = Z3Solver()
        self.assertIsNotNone(solver)

    def test_z3_add_constraints_without_z3(self):
        # 实证驱动的配置项
        """测试无z3库时添加约束"""
        solver = Z3Solver()
        constraints = [
            LayoutConstraint(var_name="a", min_size=10, max_size=100),
        ]
        # Without z3 installed, should return False gracefully
        result = solver.add_constraints(constraints)
        # Either True (z3 available) or False (z3 not available) is fine
        self.assertIsInstance(result, bool)

    def test_z3_check_no_solver(self):
        """测试无求解器时的检查"""
        solver = Z3Solver()
        result = solver.check()
        self.assertFalse(result)


class TestHeuristicSolver(unittest.TestCase):
    """测试启发式求解器"""

    def test_heuristic_solve(self):
        """测试启发式求解"""
        constraints = [
            LayoutConstraint(var_name="a", min_size=0x80, max_size=0x100),
            LayoutConstraint(var_name="b", min_size=0x40, max_size=0x80),
        ]
        result = HeuristicSolver.solve(constraints)
        self.assertIsInstance(result, AllocationSequence)
        self.assertTrue(result.satisfies)
        self.assertEqual(len(result.allocations), 2)


class TestAlgebraicHeapSolver(unittest.TestCase):
    """测试代数堆求解器"""

    def test_solver_init(self):
        """测试求解器初始化"""
        solver = AlgebraicHeapSolver()
        self.assertIsInstance(solver.z3, Z3Solver)
        self.assertIsInstance(solver.heuristic, HeuristicSolver)

    def test_solver_run(self):
        solver = AlgebraicHeapSolver()
        constraints = [
            LayoutConstraint(var_name="chunk_0", min_size=0x80, max_size=0x100),
            LayoutConstraint(var_name="chunk_1", min_size=0x40, max_size=0x80),
        ]
        result = solver.run(constraints)

        self.assertIsInstance(result, SolveResult)
        self.assertTrue(result.success)
        self.assertIsNotNone(result.sequence)
        self.assertEqual(result.constraints_used, 2)

    def test_solver_run_empty_constraints(self):
        """测试空约束求解"""
        solver = AlgebraicHeapSolver()
        result = solver.run([])

        self.assertIsInstance(result, SolveResult)
        self.assertTrue(result.success)
        self.assertIsNotNone(result.sequence)


class TestSolveResult(unittest.TestCase):
    """测试求解结果"""

    def test_successful_result(self):
        """测试成功结果"""
        seq = AllocationSequence(allocations=[], frees=[], satisfies=True)
        result = SolveResult(success=True, sequence=seq, constraints_used=3)
        self.assertTrue(result.success)
        self.assertEqual(result.constraints_used, 3)

    def test_failed_result(self):
        """测试失败结果"""
        result = SolveResult(success=False, sequence=None)
        self.assertFalse(result.success)
        self.assertIsNone(result.sequence)


class TestConvenienceFunctions(unittest.TestCase):
    """测试便捷函数"""

    def test_create_algebraic_heap_solver(self):
        """测试工厂函数"""
        solver = create_algebraic_heap_solver()
        self.assertIsInstance(solver, AlgebraicHeapSolver)


# Removed tests for classes that no longer exist
# AllocatorType, PtmallocModel, MallocNgModel, HeapChunk, HeapChunkState,
# solve_heap_layout(), generate_heap_fengshui_code() were removed.
# The module was refactored into:
# AlgebraicHeapSolver (main solver)
#   - Z3Solver / HeuristicSolver (solve strategies)
#   - LayoutConstraint / AllocationSequence / SolveResult (data types)
#   - create_algebraic_heap_solver (factory function)



if __name__ == '__main__':
    unittest.main()
