
"""
测试 AI辅助的符号执行路径优先级模块
"""

import pytest
_MOD_DEBUG = False
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from modules.ai_path_prioritizer import (
    AIPathPrioritizer, SymbolicPath, PathFeature, PathPriority,
    PrioritizationResult, prioritize_paths, format_prioritization_report
)


class TestAIPathPrioritizer:
    """测试路径优先级模块"""

    def test_initialization(self):
        """测试初始化"""
        prioritizer = AIPathPrioritizer(strategy="hybrid")
        assert prioritizer is not None
        assert prioritizer.strategy == "hybrid"

    def test_prioritize_empty_paths(self):
        """测试空路径列表"""
        prioritizer = AIPathPrioritizer(strategy="heuristic")
        result = prioritizer.prioritize([])

        assert isinstance(result, PrioritizationResult)
        assert result.total_paths == 0
        assert result.prioritized_paths == 0

    def test_prioritize_single_path(self):
        prioritizer = AIPathPrioritizer(strategy="heuristic")

        path = SymbolicPath(
            path_id="path_001",
            constraints=["x > 10", "y == 0"],
            instructions=["mov eax, 1"],
            registers={"pc": 0x401000, "sp": 0x7ffffff000},
            memory_access=[{"type": "write", "address": 0x1000, "size": 4}],
            reached_functions=["strcpy"],
            depth=10,
            coverage_ratio=0.3,
            features=[PathFeature.USER_INPUT, PathFeature.MEMORY_ACCESS]
        )

        result = prioritizer.prioritize([path])

        assert isinstance(result, PrioritizationResult)
        assert result.total_paths == 1
        assert result.prioritized_paths == 1
        assert len(result.paths) == 1

        analysis = result.paths[0]
        assert analysis.path_id == "path_001"
        assert analysis.priority_score >= 0
        assert analysis.priority_score <= 1.0

    def test_prioritize_multiple_paths(self):
        """测试多条路径"""
        prioritizer = AIPathPrioritizer(strategy="heuristic")

        paths = [
            SymbolicPath(
                path_id="path_high",
                constraints=["x > 100"],
                instructions=[],
                registers={},
                memory_access=[],
                reached_functions=["strcpy", "sprintf"],
                depth=20,
                coverage_ratio=0.5,
                features=[PathFeature.USER_INPUT, PathFeature.MEMORY_ACCESS]
            ),
            SymbolicPath(
                path_id="path_low",
                constraints=["x == 0"],
                instructions=[],
                registers={},
                memory_access=[],
                reached_functions=["printf"],
                depth=5,
                coverage_ratio=0.1,
                features=[]
            ),
            SymbolicPath(
                path_id="path_critical",
                constraints=["x > 1000"],
                instructions=[],
                registers={},
                memory_access=[],
                reached_functions=["gets", "system"],
                depth=30,
                coverage_ratio=0.8,
                features=[PathFeature.USER_INPUT, PathFeature.SYSTEM_CALL, PathFeature.PRIVILEGE_CHANGE]
            )
        ]

        result = prioritizer.prioritize(paths)

        assert len(result.paths) == 3
        # 关键路径应该排在前面
        assert result.paths[0].path_id == "path_critical"

        # 验证优先级级别
        critical_analysis = result.paths[0]
        assert critical_analysis.priority_level in [PathPriority.CRITICAL, PathPriority.HIGH]

    def test_hybrid_strategy(self):
        """测试混合策略"""
        prioritizer = AIPathPrioritizer(strategy="hybrid")

        paths = [
            SymbolicPath(
                path_id="path1",
                constraints=["x > 10"],
                instructions=[],
                registers={},
                memory_access=[],
                reached_functions=["strcpy"],
                depth=15,
                coverage_ratio=0.4,
                features=[PathFeature.USER_INPUT]
            )
        ]

        result = prioritizer.prioritize(paths)
        assert isinstance(result, PrioritizationResult)

    def test_prioritize_with_top_k(self):
        """测试top_k参数"""
        prioritizer = AIPathPrioritizer(strategy="heuristic")

        paths = [
            SymbolicPath(
                path_id=f"path_{i}",
                constraints=[],
                instructions=[],
                registers={},
                memory_access=[],
                reached_functions=[],
                depth=i,
                coverage_ratio=0.1 * i,
                features=[]
            ) for i in range(5)
        ]

        result = prioritizer.prioritize(paths, top_k=2)

        assert len(result.paths) == 2

    def test_get_path_analysis(self):
        prioritizer = AIPathPrioritizer(strategy="heuristic")

        path = SymbolicPath(
            path_id="test_path",
            constraints=["x > 0"],
            instructions=[],
            registers={},
            memory_access=[],
            reached_functions=[],
            depth=5,
            coverage_ratio=0.2,
            features=[]
        )

        prioritizer.prioritize([path])

        analysis = prioritizer.get_path_analysis("test_path")
        assert analysis is not None
        assert analysis.path_id == "test_path"

    def test_update_path_priority(self):
        prioritizer = AIPathPrioritizer(strategy="heuristic")

        path = SymbolicPath(
            path_id="update_test",
            constraints=[],
            instructions=[],
            registers={},
            memory_access=[],
            reached_functions=[],
            depth=5,
            coverage_ratio=0.2,
            features=[]
        )

        prioritizer.prioritize([path])
        prioritizer.update_path_priority("update_test", 0.95, "手动调整")

        analysis = prioritizer.get_path_analysis("update_test")
        assert analysis.priority_score == 0.95
        assert analysis.priority_level == PathPriority.CRITICAL
        assert "手动调整" in analysis.reasoning

    def test_format_report(self):
        """测试格式化报告"""
        result = PrioritizationResult(
            paths=[],
            total_paths=5,
            prioritized_paths=3,
            analysis_time=0.5,
            summary={
                'critical_paths': 1,
                'high_paths': 2,
                'avg_vulnerability_likelihood': 75.0,
                'avg_exploration_value': 60.0,
                'priority_distribution': {'critical': 1, 'high': 2}
            }
        )

        report = format_prioritization_report(result)
        assert "路径优先级分析报告" in report
        assert "分析路径总数: 5" in report
        assert "关键路径数: 1" in report

    def test_prioritize_paths_convenience(self):
        """测试便捷函数"""
        paths = [
            {
                'path_id': 'conv_path',
                'constraints': ['x > 5'],
                'reached_functions': ['memcpy'],
                'depth': 10,
                'coverage_ratio': 0.3,
                'features': ['user_input']
            }
        ]

        result = prioritize_paths(paths, strategy="heuristic")
        assert isinstance(result, PrioritizationResult)
        assert result.total_paths == 1



if __name__ == "__main__":
    pytest.main([__file__, "-v"])
