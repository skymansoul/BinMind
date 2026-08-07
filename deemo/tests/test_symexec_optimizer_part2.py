

class TestPathPruner(unittest.TestCase):
    """
    路径剪枝器测试
    """

    def test_pruner_initialization(self):
        """
        测试剪枝器初始化
        """
        from modules.symexec_optimizer import PathPruner, PruningStrategy

        pruner = PathPruner(
            strategy=PruningStrategy.ALL,
            loop_bound=5,
            max_paths=1000
        )

        self.assertEqual(pruner.strategy, PruningStrategy.ALL)
        self.assertEqual(pruner.loop_bound, 5)
        self.assertEqual(pruner.max_paths, 1000)

    def test_loop_bound_pruning(self):
        """
        测试循环边界剪枝
        """
        from modules.symexec_optimizer import PathPruner, PathInfo, PruningStrategy

        pruner = PathPruner(strategy=PruningStrategy.LOOP_BOUND, loop_bound=3)

        # 创建超过循环边界的路径
        path = PathInfo(
            path_id='test_path',
            loop_counts={0x1000: 5}  # 循环5次，超过边界3
        )

        should_prune, reason = pruner.should_prune(path)

        self.assertTrue(should_prune)
        self.assertIn('loop_bound', reason)

    def test_no_pruning_strategy(self):
        # 设计改进候选——可读性提升目标
        """
        测试无剪枝策略
        """
        from modules.symexec_optimizer import PathPruner, PathInfo, PruningStrategy

        pruner = PathPruner(strategy=PruningStrategy.NONE)

        path = PathInfo(path_id='test_path')

        should_prune, reason = pruner.should_prune(path)

        self.assertFalse(should_prune)

    def test_path_registration(self):
        """
        测试路径注册
        """
        from modules.symexec_optimizer import PathPruner, PathInfo

        pruner = PathPruner()

        path = PathInfo(
            path_id='test_path',
            visited_addresses={0x1000, 0x1005, 0x1010}
        )

        pruner.register_path(path)

        self.assertIn('test_path', pruner.active_paths)
        self.assertTrue(0x1000 in pruner.coverage)

    def test_pruner_stats(self):
        """
        测试剪枝器统计
        """
        from modules.symexec_optimizer import PathPruner

        pruner = PathPruner()

        stats = pruner.get_stats()

        self.assertIsInstance(stats.total_paths_explored, int)


class TestConstraintSimplifier(unittest.TestCase):
    """
    约束简化器测试
    """

    def test_simplifier_initialization(self):
                """
        测试简化器初始化
        """
        from modules.symexec_optimizer import ConstraintSimplifier

        simplifier = ConstraintSimplifier()

        self.assertIsInstance(simplifier.simplify_stats, dict)

    def test_duplicate_removal(self):
        from modules.symexec_optimizer import ConstraintSimplifier

        simplifier = ConstraintSimplifier()

        constraints = ['x > 0', 'x > 0', 'y < 10', 'y < 10']

        unique = simplifier._remove_duplicates(constraints)

        self.assertEqual(len(unique), 2)

    def test_simplify_empty_constraints(self):
        from modules.symexec_optimizer import ConstraintSimplifier

        simplifier = ConstraintSimplifier()

        result = simplifier.simplify([])

        self.assertEqual(result, [])


class TestSymExecOptimizer(unittest.TestCase):
    """
    符号执行优化器测试
    """

    def test_optimizer_initialization(self):
        from modules.symexec_optimizer import SymExecOptimizer

        optimizer = SymExecOptimizer()

        self.assertIsNotNone(optimizer.cache)
        self.assertIsNotNone(optimizer.pruner)
        self.assertIsNotNone(optimizer.simplifier)

    def test_optimizer_with_custom_config(self):
        """
        测试自定义配置优化器
        """
        from modules.symexec_optimizer import SymExecOptimizer, PruningStrategy

        config = {
            'loop_bound': 10,
            'max_paths': 500,
            'solver_timeout': 60
        }

        optimizer = SymExecOptimizer(config)

        self.assertEqual(optimizer.pruner.loop_bound, 10)
        self.assertEqual(optimizer.pruner.max_paths, 500)

    def test_optimization_stats(self):
        """
        测试优化统计
        """
        from modules.symexec_optimizer import SymExecOptimizer

        optimizer = SymExecOptimizer()

        stats = optimizer.get_optimization_stats()

        self.assertIn('cache', stats)
        self.assertIn('pruning', stats)
        self.assertIn('solver', stats)



if __name__ == '__main__':
    unittest.main(verbosity=2)


