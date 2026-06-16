#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
测试错误路径探索模块
"""

import pytest
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from modules.error_path_explorer import (
    ErrorPathExplorer, ErrorType, VulnerabilityType, Severity,
    analyze_error_paths, explore_error_paths
)


class TestErrorPathExplorer:
    """测试错误路径探索器"""

    def test_initialization(self):
        """测试初始化"""
        explorer = ErrorPathExplorer()
        assert explorer is not None

    def test_analyze(self):
        """测试分析功能"""
        result = analyze_error_paths("/tmp/test.bin")
        
        assert result["success"] == True
        assert "binary_path" in result
        assert "findings" in result
        assert "total_system_calls" in result
        assert "error_injections" in result
        assert isinstance(result["findings"], list)

    def test_explore_specific_errors(self):
        """测试探索特定错误类型"""
        result = explore_error_paths("/tmp/test.bin", error_types=["permission_bypass"])
        
        assert result["success"] == True
        assert "findings" in result

    def test_error_types(self):
        """测试错误类型枚举"""
        assert ErrorType.PERMISSION_DENIED.value == "permission_denied"
        assert ErrorType.RESOURCE_UNAVAILABLE.value == "resource_unavailable"
        assert ErrorType.MEMORY_ERROR.value == "memory_error"

    def test_vulnerability_types(self):
        """测试漏洞类型枚举"""
        assert VulnerabilityType.PERMISSION_BYPASS.value == "permission_bypass"
        assert VulnerabilityType.RESOURCE_LEAK.value == "resource_leak"
        assert VulnerabilityType.NULL_POINTER_DEREFERENCE.value == "null_pointer_dereference"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])