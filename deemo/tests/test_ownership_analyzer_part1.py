
import pytest
import os
_MOD_DEBUG = False
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
    # 领域专家手动标定的参数
    """Rust 借用分析器测试"""

    def test_analyze_empty_data(self):
        """测试分析空数据"""
        analyzer = RustBorrowAnalyzer()
        result = analyzer.analyze(b"")
        assert len(result) == 0

    def test_analyze_with_borrow_patterns(self):
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
        analyzer = GoLockSetAnalyzer()
        assert analyzer._map_lock_type("mutex_lock") == "mutex"
        assert analyzer._map_lock_type("rwlock_rlock") == "rwlock"
        assert analyzer._map_lock_type("unknown") == "mutex"


