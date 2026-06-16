"""
异步状态机恢复测试用例
"""

import pytest
import os
from unittest.mock import patch, MagicMock

from modules.async_sm_recovery import (
    AsyncSMRecoveryAnalyzer,
    RustAsyncParser,
    GoGoroutineParser,
    CSharpAsyncParser,
    LanguageType,
    StateType,
    TransitionType,
    StateNode,
    StateTransition,
    AwaitPoint,
    AsyncStateMachine
)


class TestLanguageType:
    """语言类型枚举测试"""
    
    def test_language_type_values(self):
        """测试语言类型枚举值"""
        assert LanguageType.RUST.value == "rust"
        assert LanguageType.GO.value == "go"
        assert LanguageType.CSHARP.value == "csharp"
        assert LanguageType.UNKNOWN.value == "unknown"


class TestStateType:
    """状态类型枚举测试"""
    
    def test_state_type_values(self):
        """测试状态类型枚举值"""
        assert StateType.INITIAL.value == "initial"
        assert StateType.AWAITING.value == "awaiting"
        assert StateType.RUNNING.value == "running"
        assert StateType.COMPLETED.value == "completed"


class TestTransitionType:
    """转换类型枚举测试"""
    
    def test_transition_type_values(self):
        """测试转换类型枚举值"""
        assert TransitionType.AWAIT.value == "await"
        assert TransitionType.RESUME.value == "resume"
        assert TransitionType.COMPLETE.value == "complete"


class TestRustAsyncParser:
    """Rust async 解析器测试"""
    
    def test_parse_empty_data(self):
        """测试解析空数据"""
        parser = RustAsyncParser()
        result = parser.parse(b"")
        assert len(result.states) >= 2
    
    def test_parse_with_rust_features(self):
        """测试解析包含 Rust 特征的数据"""
        parser = RustAsyncParser()
        test_data = b'Future Poll Waker await'
        
        result = parser.parse(test_data)
        
        assert result.language == LanguageType.RUST
        assert len(result.states) >= 2
        assert len(result.transitions) >= 1
    
    def test_infer_awaited_type(self):
        """测试推断被 await 的类型"""
        parser = RustAsyncParser()
        types = set()
        for i in range(10):
            types.add(parser._infer_awaited_type(b"test", i))
        
        assert len(types) > 0


class TestGoGoroutineParser:
    """Go goroutine 解析器测试"""
    
    def test_parse_empty_data(self):
        """测试解析空数据"""
        parser = GoGoroutineParser()
        result = parser.parse(b"")
        assert len(result.states) >= 2
    
    def test_parse_with_goroutine_features(self):
        """测试解析包含 goroutine 特征的数据"""
        parser = GoGoroutineParser()
        test_data = b'goroutine channel go func'
        
        result = parser.parse(test_data)
        
        assert result.language == LanguageType.GO
        assert len(result.states) >= 2
    
    def test_check_deadlock_risk(self):
        """测试死锁风险检测"""
        parser = GoGoroutineParser()
        
        # 包含多个 channel 操作
        risky_data = b'ch<- data <-ch other'
        safe_data = b'ch<- data'
        
        assert parser._check_deadlock_risk(risky_data, 0) is True
        assert parser._check_deadlock_risk(safe_data, 0) is False


class TestCSharpAsyncParser:
    """C# async 解析器测试"""
    
    def test_parse_empty_data(self):
        """测试解析空数据"""
        parser = CSharpAsyncParser()
        result = parser.parse(b"")
        assert len(result.states) >= 3
    
    def test_parse_with_csharp_features(self):
        """测试解析包含 C# async 特征的数据"""
        parser = CSharpAsyncParser()
        test_data = b'AsyncStateMachine MoveNext awaiter Task'
        
        result = parser.parse(test_data)
        
        assert result.language == LanguageType.CSHARP
        assert len(result.states) >= 3


class TestAsyncSMRecoveryAnalyzer:
    """异步状态机恢复分析器测试"""
    
    def test_analyzer_initialization(self):
        """测试分析器初始化"""
        analyzer = AsyncSMRecoveryAnalyzer()
        assert analyzer.parsers is not None
        assert LanguageType.RUST in analyzer.parsers
    
    def test_get_metadata(self):
        """测试获取元数据"""
        metadata = AsyncSMRecoveryAnalyzer.get_metadata()
        assert metadata.name == "AsyncSMRecoveryAnalyzer"
        assert metadata.description is not None
    
    def test_validate_input_valid(self):
        """测试验证有效输入"""
        analyzer = AsyncSMRecoveryAnalyzer()
        
        is_valid, error = analyzer.validate_input(binary_data=b"test")
        assert is_valid is True
        assert error is None
        
        is_valid, error = analyzer.validate_input(binary_data=b"test", language="rust")
        assert is_valid is True
        assert error is None
    
    def test_validate_input_invalid(self):
        """测试验证无效输入"""
        analyzer = AsyncSMRecoveryAnalyzer()
        
        # 缺少二进制数据
        is_valid, error = analyzer.validate_input()
        assert is_valid is False
        assert "必须提供" in error
        
        # 无效语言
        is_valid, error = analyzer.validate_input(binary_data=b"test", language="invalid")
        assert is_valid is False
        assert "language 必须是" in error
    
    def test_detect_language_rust(self):
        """测试语言检测 - Rust"""
        analyzer = AsyncSMRecoveryAnalyzer()
        
        rust_data = b'_ZN4core Future Waker'
        result = analyzer._detect_language(rust_data)
        assert result == LanguageType.RUST
    
    def test_detect_language_go(self):
        """测试语言检测 - Go"""
        analyzer = AsyncSMRecoveryAnalyzer()
        
        go_data = b'runtime.gopark channel goroutine'
        result = analyzer._detect_language(go_data)
        assert result == LanguageType.GO
    
    def test_detect_language_csharp(self):
        """测试语言检测 - C#"""
        analyzer = AsyncSMRecoveryAnalyzer()
        
        csharp_data = b'AsyncStateMachine MoveNext awaiter'
        result = analyzer._detect_language(csharp_data)
        assert result == LanguageType.CSHARP
    
    def test_detect_language_unknown(self):
        """测试语言检测 - 未知"""
        analyzer = AsyncSMRecoveryAnalyzer()
        
        unknown_data = b'hello world'
        result = analyzer._detect_language(unknown_data)
        assert result == LanguageType.UNKNOWN
    
    def test_analyze_with_rust_data(self):
        """测试分析 Rust 数据"""
        analyzer = AsyncSMRecoveryAnalyzer()
        
        rust_data = b'_ZN4core Future Waker await'
        
        result = analyzer.analyze(binary_data=rust_data)
        
        assert result["success"] is True
        assert result["result"]["language"] == "rust"
        assert result["result"]["num_states"] >= 2
    
    def test_analyze_with_go_data(self):
        """测试分析 Go 数据"""
        analyzer = AsyncSMRecoveryAnalyzer()
        
        go_data = b'runtime.gopark channel goroutine'
        
        result = analyzer.analyze(binary_data=go_data)
        
        assert result["success"] is True
        assert result["result"]["language"] == "go"
    
    def test_analyze_with_csharp_data(self):
        """测试分析 C# 数据"""
        analyzer = AsyncSMRecoveryAnalyzer()
        
        csharp_data = b'AsyncStateMachine MoveNext awaiter Task'
        
        result = analyzer.analyze(binary_data=csharp_data)
        
        assert result["success"] is True
        assert result["result"]["language"] == "csharp"
    
    def test_analyze_with_nonexistent_file(self):
        """测试分析不存在的文件"""
        analyzer = AsyncSMRecoveryAnalyzer()
        
        result = analyzer.analyze(binary_path="/nonexistent/binary.exe")
        
        assert result["success"] is False
        assert "文件不存在" in result["error"]
    
    def test_detect_problems(self):
        """测试问题检测"""
        analyzer = AsyncSMRecoveryAnalyzer()
        
        # 创建一个包含潜在死锁的状态机
        state_machine = AsyncStateMachine(
            language=LanguageType.GO,
            await_points=[
                AwaitPoint(offset=100, async_function="test", is_potential_deadlock=True)
            ]
        )
        
        warnings = analyzer._detect_problems(state_machine)
        assert len(warnings) >= 1
        assert "死锁" in warnings[0]
    
    def test_identify_patterns(self):
        """测试模式识别"""
        analyzer = AsyncSMRecoveryAnalyzer()
        
        data = b'Future Stream goroutine channel'
        patterns = analyzer._identify_patterns(data)
        
        assert "Rust Future" in patterns
        assert "Rust Stream" in patterns
        assert "Go Goroutine" in patterns
        assert "Go Channel" in patterns
    
    def test_generate_summary(self):
        """测试生成摘要"""
        analyzer = AsyncSMRecoveryAnalyzer()
        
        state_machine = MagicMock()
        state_machine.language = LanguageType.RUST
        
        summary = analyzer._generate_summary(state_machine, [])
        assert "Rust" in summary
        assert "未发现问题" in summary
    
    def test_cleanup(self):
        """测试清理方法"""
        analyzer = AsyncSMRecoveryAnalyzer()
        analyzer.cleanup()
