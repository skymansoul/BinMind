#!/usr/bin/env python3
# 测试IndirectCall/CFIViolation/CheckResult各dataclass和FunctionEntryCollector/Scanner/CFIChecker
# _make_temp_binary在好几个类里复制粘贴了, 以后得抽个conftest fixture

import os
import tempfile
# import sys
import pytest

from modules.cfi_violation_checker import (
    CFIChecker,
    CFIViolation,
    CheckResult,
    IndirectCall,
    IndirectCallScanner,
    FunctionEntryCollector,
    create_cfi_checker,
)

_DEBUG_FLAG = False


class TestIndirectCall:

    def test_creation(self):
        """call_site=0x401000, rax, 两个可能目标"""
        call = IndirectCall(
            call_site=0x401000,
            target_register="rax",
            possible_targets=[0x402000, 0x403000],
        )
        assert call.call_site == 0x401000
        assert call.target_register == "rax"
        assert call.possible_targets == [0x402000, 0x403000]

    def test_default_targets(self):
        """不传possible_targets => 空list"""
        call = IndirectCall(
            call_site=0x401000,
            target_register="rbx",
        )
        assert call.possible_targets == []


class TestCFIViolation:

    def test_creation(self):
        """target not in valid entries, severity=high"""
        v = CFIViolation(
            call_site=0x401000,
            target=0x500000,
            reason="Target not in valid function entries",
            severity="high",
        )
        assert v.call_site == 0x401000
        assert v.target == 0x500000
        assert v.reason == "Target not in valid function entries"
        assert v.severity == "high"


class TestCheckResult:

    def test_successful_result(self):
        result = CheckResult(
            success=True,
            indirect_calls=[],
            violations=[],
        )
        assert result.success is True

    def test_failed_result(self):
        result = CheckResult(
            success=False,
            indirect_calls=[],
            violations=[],
        )
        assert result.success is False

    def test_with_violations(self):
        """1 indirect_call + 1 violation"""
        v = CFIViolation(
            call_site=0x401000,
            target=0x500000,
            reason="Invalid target",
            severity="high",
        )
        result = CheckResult(
            success=True,
            indirect_calls=[
                IndirectCall(call_site=0x401000, target_register="rax"),
            ],
            violations=[v],
        )
        assert len(result.indirect_calls) == 1
        assert len(result.violations) == 1


class TestFunctionEntryCollector:
    """函数入口收集器: init + collect"""

    def _make_temp_binary(self) -> str:
        fd, path = tempfile.mkstemp(suffix=".bin")
        os.close(fd)
        with open(path, "wb") as f:
            f.write(b"\x00" * 256)
        return path

    def test_init(self):
        path = self._make_temp_binary()
        try:
            collector = FunctionEntryCollector(path)
            assert collector.binary_path == path
            assert isinstance(collector.entries, set)
        finally:
            os.unlink(path)

    def test_collect(self):
        """collect返回set"""
        path = self._make_temp_binary()
        try:
            collector = FunctionEntryCollector(path)
            entries = collector.collect()
            assert isinstance(entries, set)
        finally:
            os.unlink(path)


class TestIndirectCallScanner:
    """间接调用扫描器: init + scan + pattern检查"""

    def _make_temp_binary(self) -> str:
        fd, path = tempfile.mkstemp(suffix=".bin")
        os.close(fd)
        with open(path, "wb") as f:
            f.write(b"\x00" * 256)
        return path

    def test_init(self):
        path = self._make_temp_binary()
        try:
            scanner = IndirectCallScanner(path)
            assert scanner.binary_path == path
        finally:
            os.unlink(path)

    def test_scan(self):
        """scan返回list of IndirectCall, 如果非空则每个必须是IndirectCall"""
        path = self._make_temp_binary()
        try:
            scanner = IndirectCallScanner(path)
            calls = scanner.scan()
            assert isinstance(calls, list)
            for call in calls:
                assert isinstance(call, IndirectCall)
        finally:
            os.unlink(path)

    def test_indirect_patterns(self):
        """INDIRECT_PATTERNS不能为空, 每个pattern是str"""
        patterns = IndirectCallScanner.INDIRECT_PATTERNS
        assert len(patterns) > 0
        for pattern in patterns:
            assert isinstance(pattern, str)


class TestCFIChecker:
    """CFI检查器: init + run + edge cases"""

    def _make_temp_binary(self) -> str:
        fd, path = tempfile.mkstemp(suffix=".bin")
        os.close(fd)
        with open(path, "wb") as f:
            f.write(b"\x00" * 256)
        return path

    def test_init(self):
        path = self._make_temp_binary()
        try:
            checker = CFIChecker(path)
            assert checker.binary_path == os.path.abspath(path)
            assert isinstance(checker.collector, FunctionEntryCollector)
            assert isinstance(checker.scanner, IndirectCallScanner)
        finally:
            os.unlink(path)

    def test_run(self):
        """run返回CheckResult, 字段类型全检查"""
        path = self._make_temp_binary()
        try:
            checker = CFIChecker(path)
            result = checker.run()

            assert isinstance(result, CheckResult)
            assert isinstance(result.success, bool)
            assert isinstance(result.indirect_calls, list)
            assert isinstance(result.violations, list)
        finally:
            os.unlink(path)

    def test_run_with_missing_file(self):
        """文件不存在 => success=False, 不抛异常"""
        checker = CFIChecker("/nonexistent/binary")
        result = checker.run()
        # 就算文件不存在也应该优雅返回
        assert isinstance(result, CheckResult)
        assert result.success is False

    def test_create_cfi_checker(self):
        """工厂函数"""
        path = self._make_temp_binary()
        try:
            checker = create_cfi_checker(path)
            assert isinstance(checker, CFIChecker)
        finally:
            os.unlink(path)


# Removed tests for classes/functions that no longer exist
# CFIViolationChecker -> renamed to CFIChecker
# CFIViolationType -> removed; CFIViolation now captures violation details
# CFIGrade -> removed; severity string field on CFIViolation instead
# analyze_cfi_violations() -> removed; use CFIChecker(binary_path).run()
# check_cfi_ready() -> removed; functionality folded into CFIChecker.run()


