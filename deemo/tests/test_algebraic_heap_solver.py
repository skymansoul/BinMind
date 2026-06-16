"""
测试代数堆求解器模块
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from modules.algebraic_heap_solver import (
    AlgebraicHeapSolver,
    AllocatorType,
    PtmallocModel,
    MallocNgModel,
    HeapChunk,
    HeapChunkState,
    solve_heap_layout,
    generate_heap_fengshui_code
)


class TestAllocatorModels(unittest.TestCase):
    """测试分配器模型"""
    
    def test_ptmalloc_model_init(self):
        """测试ptmalloc模型初始化"""
        model = PtmallocModel()
        self.assertEqual(model.allocator_type, AllocatorType.PTMALLOC)
        self.assertEqual(model.tcache_size, 7)
        self.assertEqual(model.fastbin_max_size, 0x80)
    
    def test_ptmalloc_solve_layout(self):
        """测试ptmalloc求解布局"""
        model = PtmallocModel()
        target_layout = {
            'target_size': 0x80,
            'num_chunks': 7
        }
        events = model.solve_layout(target_layout)
        self.assertIsNotNone(events)
        self.assertEqual(len(events), 13)  # 7 alloc + 6 free
    
    def test_mallocng_model_init(self):
        """测试mallocng模型初始化"""
        model = MallocNgModel()
        self.assertEqual(model.allocator_type, AllocatorType.MALLOC_NG)
        self.assertEqual(model.page_size, 0x1000)
    
    def test_mallocng_solve_layout(self):
        """测试mallocng求解布局"""
        model = MallocNgModel()
        target_layout = {
            'target_size': 0x80,
            'num_chunks': 5
        }
        events = model.solve_layout(target_layout)
        self.assertIsNotNone(events)
        self.assertGreater(len(events), 0)


class TestAlgebraicHeapSolver(unittest.TestCase):
    """测试代数堆求解器"""
    
    def test_solver_init_ptmalloc(self):
        """测试求解器初始化（ptmalloc）"""
        solver = AlgebraicHeapSolver(AllocatorType.PTMALLOC)
        self.assertEqual(solver.allocator_type, AllocatorType.PTMALLOC)
    
    def test_solver_init_mallocng(self):
        """测试求解器初始化（mallocng）"""
        solver = AlgebraicHeapSolver(AllocatorType.MALLOC_NG)
        self.assertEqual(solver.allocator_type, AllocatorType.MALLOC_NG)
    
    def test_set_target_layout(self):
        """测试设置目标布局"""
        solver = AlgebraicHeapSolver()
        target_layout = {
            'target_size': 0x100,
            'num_chunks': 5,
            'target_address': 0x12345678
        }
        solver.set_target_layout(target_layout)
        self.assertEqual(solver.target_layout, target_layout)
    
    def test_solve_ptmalloc(self):
        """测试求解ptmalloc布局"""
        solver = AlgebraicHeapSolver(AllocatorType.PTMALLOC)
        solver.set_target_layout({
            'target_size': 0x80,
            'num_chunks': 3
        })
        solutions = solver.solve()
        self.assertGreater(len(solutions), 0)
        self.assertIsInstance(solutions[0], list)
    
    def test_solve_mallocng(self):
        """测试求解mallocng布局"""
        solver = AlgebraicHeapSolver(AllocatorType.MALLOC_NG)
        solver.set_target_layout({
            'target_size': 64,
            'num_chunks': 3
        })
        solutions = solver.solve()
        self.assertGreater(len(solutions), 0)
    
    def test_generate_c_code(self):
        """测试生成C代码"""
        solver = AlgebraicHeapSolver()
        solver.set_target_layout({
            'target_size': 0x80,
            'num_chunks': 3
        })
        solutions = solver.solve()
        if solutions:
            c_code = solver.generate_c_code(solutions[0])
            self.assertIsInstance(c_code, str)
            self.assertIn('malloc', c_code)
            self.assertIn('free', c_code)
    
    def test_analyze_heap_state(self):
        """测试分析堆状态"""
        solver = AlgebraicHeapSolver()
        # 创建模拟堆转储数据
        heap_dump = b'\x90\x00\x00\x00\x00\x00\x00\x01'  # size=0x90, inuse=1
        heap_dump += b'\x41' * 0x80
        heap_dump += b'\x90\x00\x00\x00\x00\x00\x00\x00'  # size=0x90, inuse=0
        
        result = solver.analyze_heap_state(heap_dump)
        self.assertEqual(result['total_chunks'], 1)  # 第二个块还没完全包含


class TestConvenienceFunctions(unittest.TestCase):
    """测试便捷函数"""
    
    def test_solve_heap_layout_ptmalloc(self):
        """测试求解堆布局函数（ptmalloc）"""
        solutions = solve_heap_layout(0x80, 3, 'ptmalloc')
        self.assertGreater(len(solutions), 0)
    
    def test_solve_heap_layout_mallocng(self):
        """测试求解堆布局函数（mallocng）"""
        solutions = solve_heap_layout(64, 3, 'mallocng')
        self.assertGreater(len(solutions), 0)
    
    def test_generate_heap_fengshui_code(self):
        """测试生成堆风水代码"""
        code = generate_heap_fengshui_code(0x80, 3)
        self.assertIsInstance(code, str)
        self.assertIn('malloc', code)


if __name__ == '__main__':
    unittest.main()