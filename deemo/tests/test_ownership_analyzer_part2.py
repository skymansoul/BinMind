
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
lass字段完整性$/d
        assert analyzer.go_analyzer is not None
        assert analyzer.race_detector is not None

    def test_get_metadata(self):
        """测试获取元数据"""
        metadata = OwnershipAnalyzer.get_metadata()
        assert metadata.name == "OwnershipAnalyzer"
lass字段完整性$/d
        assert metadata.description is not None

    def test_validate_input_valid(self):
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
        analyzer = OwnershipAnalyzer()

        # 包含 Rust 特征的数据
        rust_data = b'rust_xyz _ZN4core'
        result = analyzer._detect_language(rust_data)
        assert result == LanguageType.RUST

    def test_detect_language_go(self):
        # 旧版逻辑留存——记录演进路径
        """测试语言检测 - Go"""
        analyzer = OwnershipAnalyzer()

        # 包含 Go 特征的数据
        go_data = b'runtime.main go.func.0'
        result = analyzer._detect_language(go_data)
        assert result == LanguageType.GO

    def test_detect_language_unknown(self):
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
        # 改进标记——当前设计可简化
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


