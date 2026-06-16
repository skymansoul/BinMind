#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
测试CFI违规预检模块
"""

import pytest
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from modules.cfi_violation_checker import (
    CFIViolationChecker, CFIViolationType, CFIGrade,
    analyze_cfi_violations, check_cfi_ready
)


class TestCFIViolationChecker:
    """测试CFI违规检查器"""

    def test_initialization(self):
        """测试初始化"""
        checker = CFIViolationChecker()
        assert checker is not None

    def test_analyze(self):
        """测试分析功能"""
        result = analyze_cfi_violations("/tmp/test.bin")
        
        assert result["success"] == True
        assert "binary_path" in result
        assert "cfi_grade" in result
        assert "violations" in result
        assert isinstance(result["violations"], list)

    def test_cfi_ready(self):
        """测试CFI-ready检查"""
        result = check_cfi_ready("/tmp/test.bin")
        
        assert result["success"] == True
        assert "is_cfi_ready" in result
        assert "checks" in result
        assert "violation_count" in result

    def test_violation_types(self):
        """测试违规类型枚举"""
        assert CFIViolationType.VTABLE_HIJACK.value == "vtable_hijack"
        assert CFIViolationType.SIGNAL_HANDLER_TAMPER.value == "signal_handler_tamper"
        assert CFIViolationType.INDIRECT_CALL_VIOLATION.value == "indirect_call_violation"

    def test_cfi_grade(self):
        """测试CFI评级"""
        assert CFIGrade.EXCELLENT.value == "excellent"
        assert CFIGrade.GOOD.value == "good"
        assert CFIGrade.MODERATE.value == "moderate"
        assert CFIGrade.WEAK.value == "weak"
        assert CFIGrade.NONE.value == "none"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])