"""
所有权分析器测试用例
"""

import pytest
import os
from unittest.mock import patch, MagicMock

from modules.ownership_analyzer import (
    OwnershipAnalyzer,
    RustBorrowAnalyzer,
    GoLockSetAnalyzer,
    RaceDetector,
    LanguageType,
    BorrowInfo,
    LockInfo,
    RaceWarning,
    RaceConditionType
)


class TestLanguageType:
    """语言类型枚举测试"""
    
    def test_language_type_values(self):
        """测试语言类型枚举值"""
        assert LanguageType.RUST.value == "rust"
        assert LanguageType.GO.value == "go"
        assert LanguageType.UNKNOWN.value == "unknown"


class TestRustBorrowAnalyzer:
    """Rust 借用分析器测试"""
    
    def test_analyze_empty_data(self):
        """测试分析空数据"""
        analyzer = RustBorrowAnalyzer()
        result = analyzer.analyze(b"")
        assert len(result) == 0
    
    def test_analyze_with_borrow_patterns(self):
        """测试分析包含借用模式的数据"""
        analyzer = RustBorrowAnalyzer()
        # 创建包含借用模式的测试数据
        test_data = b'\x48\x8b\x05\x00\x00\x00\x00'  # mov rax, [rip+0]
        test_data += b'\x48\x89\x05\x00\x00\x00\x00'  # mov [rip+0], rax
        
        result = analyzer.analyze(test_data)
        assert len(result) >= 2
    
    def test_infer_lifetime(self):
        """测试生命周期推断"""
        analyzer = RustBorrowAnalyzer()
        lifetimes = set()
        for i in range(10):
            lifetimes.add(analyzer._infer_lifetime(i))
        
        assert len(lifetimes) <= 5  # 最多5种生命周期
    
    def test_check_unsafe_context(self):
        """测试 unsafe 上下文检测"""
        analyzer = RustBorrowAnalyzer()
        
        # 不包含 unsafe 模式的数据（不包含 unsafe 相关词汇）
        safe_data = b'normal code without dangerous operations'
        # 包含 unsafe 模式的数据
        unsafe_data = b'some code with unchecked operation'
        
        assert analyzer._check_unsafe_context(safe_data, 0) is False
        assert analyzer._check_unsafe_context(unsafe_data, 0) is True


class TestGoLockSetAnalyzer:
    """Go 锁集分析器测试"""
    
    def test_analyze_empty_data(self):
        """测试分析空数据"""
        analyzer = GoLockSetAnalyzer()
        locks, goroutine_points = analyzer.analyze(b"")
        assert len(locks) == 0
        assert len(goroutine_points) == 0
    
    def test_analyze_with_lock_patterns(self):
        """测试分析包含锁模式的数据"""
        analyzer = GoLockSetAnalyzer()
        # 创建包含锁模式的测试数据
        test_data = b'\x48\x8b\x0d\x00\x00\x00\x00'  # mov rcx, [rip+0]
        test_data += b'\x48\x89\x0d\x00\x00\x00\x00'  # mov [rip+0], rcx
        
        locks, goroutine_points = analyzer.analyze(test_data)
        assert len(locks) >= 2
    
    def test_is_goroutine_point(self):
        """测试 goroutine 调度点检测"""
        analyzer = GoLockSetAnalyzer()
        
        # 包含 goroutine 模式的数据
        data_with_goroutine = b'runtime.goexit'
        data_without = b'normal code'
        
        assert analyzer._is_goroutine_point(data_with_goroutine, 0) is True
        assert analyzer._is_goroutine_point(data_without, 0) is False
    
    def test_map_lock_type(self):
        """测试锁类型映射"""
        analyzer = GoLockSetAnalyzer()
        assert analyzer._map_lock_type("mutex_lock") == "mutex"
        assert analyzer._map_lock_type("rwlock_rlock") == "rwlock"
        assert analyzer._map_lock_type("unknown") == "mutex"


class TestRaceDetector:
    """数据竞争检测器测试"""
    
    def test_detect_uaf(self):
        """测试 UAF 检测"""
        detector = RaceDetector()
        
        # 创建包含 unsafe 可变借用的测试数据
        borrows = [
            BorrowInfo(
                variable_name="var_0",
                borrow_type="mut",
                borrow_scope=(0, 10),
                is_unsafe=True
            ),
            BorrowInfo(
                variable_name="var_1",
                borrow_type="immutable",
                borrow_scope=(5, 15),
                is_unsafe=False
            )
        ]
        
        warnings = detector._detect_uaf(borrows)
        assert len(warnings) == 1
        assert warnings[0].race_type == RaceConditionType.USE_AFTER_FREE
    
    def test_may_conflict(self):
        """测试冲突检测"""
        detector = RaceDetector()
        
        # 不重叠的借用
        borrow1 = BorrowInfo("var1", "mut", (0, 10))
        borrow2 = BorrowInfo("var2", "immutable", (15, 25))
        assert detector._may_conflict(borrow1, borrow2) is False
        
        # 重叠但都是不可变借用
        borrow3 = BorrowInfo("var3", "immutable", (0, 10))
        borrow4 = BorrowInfo("var4", "immutable", (5, 15))
        assert detector._may_conflict(borrow3, borrow4) is False
        
        # 重叠且有可变借用
        borrow5 = BorrowInfo("var5", "mut", (0, 10))
        borrow6 = BorrowInfo("var6", "immutable", (5, 15))
        assert detector._may_conflict(borrow5, borrow6) is True
    
    def test_has_lock_protection(self):
        """测试锁保护检测"""
        detector = RaceDetector()
        
        borrow = BorrowInfo("var1", "mut", (10, 20))
        
        # 没有锁
        locks = []
        assert detector._has_lock_protection(borrow, locks) is False
        
        # 有锁保护
        locks = [
            LockInfo("lock1", "mutex", acquire_offset=5, release_offset=25)
        ]
        assert detector._has_lock_protection(borrow, locks) is True
    
    def test_detect_deadlock(self):
        """测试死锁检测"""
        detector = RaceDetector()
        
        locks = [
            LockInfo("lock1", "mutex", acquire_offset=10),
            LockInfo("lock2", "mutex", acquire_offset=20)
        ]
        
        warnings = detector._detect_deadlock(locks)
        assert len(warnings) >= 1
        assert warnings[0].race_type == RaceConditionType.DEADLOCK


class TestOwnershipAnalyzer:
    """所有权分析器测试"""
    
    def test_analyzer_initialization(self):
        """测试分析器初始化"""
        analyzer = OwnershipAnalyzer()
        assert analyzer.rust_analyzer is not None
        assert analyzer.go_analyzer is not None
        assert analyzer.race_detector is not None
    
    def test_get_metadata(self):
        """测试获取元数据"""
        metadata = OwnershipAnalyzer.get_metadata()
        assert metadata.name == "OwnershipAnalyzer"
        assert metadata.description is not None
    
    def test_validate_input_valid(self):
        """测试验证有效输入"""
        analyzer = OwnershipAnalyzer()
        
        # 有效输入：提供 binary_data
        is_valid, error = analyzer.validate_input(binary_data=b"test")
        assert is_valid is True
        assert error is None
        
        # 有效输入：提供语言参数
        is_valid, error = analyzer.validate_input(binary_data=b"test", language="rust")
        assert is_valid is True
        assert error is None
    
    def test_validate_input_invalid(self):
        """测试验证无效输入"""
        analyzer = OwnershipAnalyzer()
        
        # 无效输入：缺少二进制数据
        is_valid, error = analyzer.validate_input()
        assert is_valid is False
        assert "必须提供" in error
        
        # 无效输入：不存在的文件
        is_valid, error = analyzer.validate_input(binary_path="/nonexistent/path")
        assert is_valid is False
        assert "文件不存在" in error
        
        # 无效输入：无效语言
        is_valid, error = analyzer.validate_input(binary_data=b"test", language="invalid")
        assert is_valid is False
        assert "language 必须是" in error
    
    def test_detect_language_rust(self):
        """测试语言检测 - Rust"""
        analyzer = OwnershipAnalyzer()
        
        # 包含 Rust 特征的数据
        rust_data = b'rust_xyz _ZN4core'
        result = analyzer._detect_language(rust_data)
        assert result == LanguageType.RUST
    
    def test_detect_language_go(self):
        """测试语言检测 - Go"""
        analyzer = OwnershipAnalyzer()
        
        # 包含 Go 特征的数据
        go_data = b'runtime.main go.func.0'
        result = analyzer._detect_language(go_data)
        assert result == LanguageType.GO
    
    def test_detect_language_unknown(self):
        """测试语言检测 - 未知"""
        analyzer = OwnershipAnalyzer()
        
        # 不包含任何特征的数据
        unknown_data = b'hello world'
        result = analyzer._detect_language(unknown_data)
        assert result == LanguageType.UNKNOWN
    
    def test_analyze_with_rust_data(self):
        """测试分析 Rust 数据"""
        analyzer = OwnershipAnalyzer()
        
        # 创建包含 Rust 特征的测试数据
        rust_data = b'rust_xyz _ZN4core'
        rust_data += b'\x48\x8b\x05\x00\x00\x00\x00'  # mov rax, [rip+0]
        
        result = analyzer.analyze(binary_data=rust_data)
        
        assert result["success"] is True
        assert result["result"]["language"] == "rust"
        assert result["result"]["num_borrows"] >= 1
    
    def test_analyze_with_go_data(self):
        """测试分析 Go 数据"""
        analyzer = OwnershipAnalyzer()
        
        # 创建包含 Go 特征的测试数据
        go_data = b'runtime.main go.func.0'
        go_data += b'\x48\x8b\x0d\x00\x00\x00\x00'  # mov rcx, [rip+0]
        
        result = analyzer.analyze(binary_data=go_data)
        
        assert result["success"] is True
        assert result["result"]["language"] == "go"
        assert result["result"]["num_locks"] >= 1
    
    def test_analyze_with_nonexistent_file(self):
        """测试分析不存在的文件"""
        analyzer = OwnershipAnalyzer()
        
        result = analyzer.analyze(binary_path="/nonexistent/binary.elf")
        
        assert result["success"] is False
        assert "文件不存在" in result["error"]
    
    def test_generate_summary(self):
        """测试生成摘要"""
        analyzer = OwnershipAnalyzer()
        
        # 测试不同数量警告的摘要
        result_no_warnings = MagicMock()
        result_no_warnings.language = LanguageType.RUST
        result_no_warnings.warnings = []
        summary = analyzer._generate_summary(result_no_warnings)
        assert "未发现并发问题" in summary
        
        result_with_warnings = MagicMock()
        result_with_warnings.language = LanguageType.GO
        result_with_warnings.warnings = [1, 2, 3]
        summary = analyzer._generate_summary(result_with_warnings)
        assert "3 个潜在并发问题" in summary
    
    def test_cleanup(self):
        """测试清理方法"""
        analyzer = OwnershipAnalyzer()
        # 应该不抛出异常
        analyzer.cleanup()
