"""
测试 LLM 引导的符号执行分支选择模块
"""

import pytest
import sys
import os

# 添加模块路径
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.llm_guided_symbex import (
    LLMGuidedSymbolicExecutor,
    LLMBranchScorer,
    DefaultLLMBranchScorer,
    BranchPriority,
    BranchInfo,
    PathSummary,
    LLMBranchScore
)


class TestBranchPriority:
    """测试分支优先级枚举"""
    
    def test_priority_values(self):
        """测试优先级枚举值"""
        assert BranchPriority.HIGH.value == "high"
        assert BranchPriority.MEDIUM.value == "medium"
        assert BranchPriority.LOW.value == "low"
    
    def test_priority_comparison(self):
        """测试优先级比较"""
        # 验证枚举成员可以被正确识别
        priorities = [BranchPriority.HIGH, BranchPriority.MEDIUM, BranchPriority.LOW]
        assert len(priorities) == 3


class TestBranchInfo:
    """测试分支信息数据类"""
    
    def test_branch_info_creation(self):
        """测试分支信息创建"""
        branch = BranchInfo(
            address=0x401000,
            condition="buffer_length > 1024",
            true_branch_target=0x402000,
            false_branch_target=0x403000,
            path_history=["path_1", "path_2"],
            depth=3,
            constraint_count=5
        )
        
        assert branch.address == 0x401000
        assert branch.condition == "buffer_length > 1024"
        assert branch.true_branch_target == 0x402000
        assert branch.false_branch_target == 0x403000
        assert len(branch.path_history) == 2
        assert branch.depth == 3
        assert branch.constraint_count == 5
    
    def test_branch_info_defaults(self):
        """测试分支信息默认值"""
        branch = BranchInfo(address=0x401000, condition="test")
        
        assert branch.condition_ast is None
        assert branch.true_branch_target is None
        assert branch.false_branch_target is None
        assert branch.path_history == []
        assert branch.depth == 0
        assert branch.constraint_count == 0


class TestPathSummary:
    """测试路径摘要数据类"""
    
    def test_path_summary_creation(self):
        """测试路径摘要创建"""
        branch_info = BranchInfo(
            address=0x401000,
            condition="test_condition",
            depth=2
        )
        
        summary = PathSummary(
            current_address=0x401000,
            function_name="main",
            branch_info=branch_info,
            memory_access_patterns=["read: [esp]", "write: [ebp-0x4]"],
            register_values={"eax": "0x100"},
            symbolic_variables=["input", "length"],
            path_constraints=["input != NULL"],
            call_stack=["main", "sub_401000"]
        )
        
        assert summary.current_address == 0x401000
        assert summary.function_name == "main"
        assert summary.branch_info.address == 0x401000
        assert len(summary.memory_access_patterns) == 2
        assert len(summary.register_values) == 1
        assert len(summary.symbolic_variables) == 2
        assert len(summary.path_constraints) == 1
        assert len(summary.call_stack) == 2


class TestDefaultLLMBranchScorer:
    """测试默认 LLM 分支评分器"""
    
    def test_scorer_initialization(self):
        """测试评分器初始化"""
        scorer = DefaultLLMBranchScorer()
        assert scorer.ai_provider == "openai"
    
    def test_create_default_score(self):
        """测试创建默认评分"""
        scorer = DefaultLLMBranchScorer()
        score = scorer._create_default_score()
        
        assert score.true_branch_score == 50.0
        assert score.false_branch_score == 50.0
        assert score.true_branch_priority == BranchPriority.MEDIUM
        assert score.false_branch_priority == BranchPriority.MEDIUM
    
    def test_extract_score(self):
        """测试提取分数"""
        scorer = DefaultLLMBranchScorer()
        
        response = "TRUE_SCORE: 85\nFALSE_SCORE: 30"
        true_score = scorer._extract_score(response, "TRUE_SCORE")
        false_score = scorer._extract_score(response, "FALSE_SCORE")
        
        assert true_score == 85.0
        assert false_score == 30.0
    
    def test_extract_priority(self):
        """测试提取优先级"""
        scorer = DefaultLLMBranchScorer()
        
        response = "TRUE_PRIORITY: high\nFALSE_PRIORITY: low"
        true_priority = scorer._extract_priority(response, "TRUE_PRIORITY")
        false_priority = scorer._extract_priority(response, "FALSE_PRIORITY")
        
        assert true_priority == BranchPriority.HIGH
        assert false_priority == BranchPriority.LOW


class TestLLMGuidedSymbolicExecutor:
    """测试 LLM 引导的符号执行器"""
    
    def test_executor_initialization(self):
        """测试执行器初始化"""
        executor = LLMGuidedSymbolicExecutor(binary_path="/path/to/binary")
        
        assert executor.binary_path == "/path/to/binary"
        assert isinstance(executor.scorer, DefaultLLMBranchScorer)
        assert executor.explored_paths == []
        assert executor.current_path == []
    
    def test_validate_input_valid(self):
        """测试验证有效输入"""
        executor = LLMGuidedSymbolicExecutor()
        is_valid, error = executor.validate_input(binary_path="/path/to/binary")
        
        assert is_valid is True
        assert error is None
    
    def test_validate_input_missing_binary(self):
        """测试验证缺少二进制路径"""
        executor = LLMGuidedSymbolicExecutor()
        is_valid, error = executor.validate_input()
        
        assert is_valid is False
        assert error == "binary_path 是必需参数"
    
    def test_validate_input_invalid_type(self):
        """测试验证无效类型"""
        executor = LLMGuidedSymbolicExecutor()
        is_valid, error = executor.validate_input(binary_path=123)
        
        assert is_valid is False
        assert error == "binary_path 必须是字符串"
    
    def test_get_metadata(self):
        """测试获取元数据"""
        metadata = LLMGuidedSymbolicExecutor.get_metadata()
        
        assert metadata.name == "LLMGuidedSymbolicExecutor"
        assert metadata.type.value == "symbolic_executor"
        assert metadata.version == "1.0.0"
        assert "LLM 引导" in metadata.description
        assert "openai" in metadata.dependencies
        assert "x86" in metadata.supported_platforms
    
    def test_analyze_missing_binary(self):
        """测试分析缺少二进制路径"""
        executor = LLMGuidedSymbolicExecutor()
        result = executor.analyze()
        
        assert result["success"] is False
        assert "binary_path" in result["error"]
    
    def test_analyze_with_binary(self):
        """测试使用二进制路径分析"""
        executor = LLMGuidedSymbolicExecutor()
        
        # 使用模拟数据测试分析流程
        result = executor.analyze(binary_path="/path/to/test_binary", max_paths=10)
        
        assert result["success"] is True
        assert "result" in result
        assert "explored_paths" in result["result"]
        assert "high_priority_paths" in result["result"]
        assert "interesting_branches" in result["result"]
        assert "analysis_summary" in result["result"]
    
    def test_cleanup(self):
        """测试清理资源"""
        executor = LLMGuidedSymbolicExecutor()
        executor.explored_paths = [{"path": 1}, {"path": 2}]
        executor.current_path = [0x401000, 0x402000]
        
        executor.cleanup()
        
        assert executor.explored_paths == []
        assert executor.current_path == []


if __name__ == "__main__":
    pytest.main([__file__, "-v"])