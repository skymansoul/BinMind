#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
测试eBPF污点跟踪模块
"""

import pytest
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from modules.ebpf_taint_tracker import (
    EBPFTaintTracker, TaintSourceType, TaintViolationType,
    analyze_ebpf_taint
)


class TestEBPFTaintTracker:
    """测试eBPF污点跟踪器"""

    def test_initialization(self):
        """测试初始化"""
        tracker = EBPFTaintTracker()
        assert tracker is not None

    def test_analyze(self):
        """测试分析功能"""
        result = analyze_ebpf_taint("/tmp/test.bin")
        
        assert result["success"] == True
        assert "binary_path" in result
        assert "sources" in result
        assert "violations" in result
        assert isinstance(result["sources"], list)
        assert isinstance(result["violations"], list)

    def test_start_stop_tracking(self):
        """测试启动和停止跟踪"""
        tracker = EBPFTaintTracker()
        
        result = tracker.start_tracking(pid=1234)
        assert result == True
        
        result = tracker.stop_tracking()
        assert result == True

    def test_taint_source_types(self):
        """测试污点源类型枚举"""
        assert TaintSourceType.USER_INPUT.value == "user_input"
        assert TaintSourceType.NETWORK_DATA.value == "network_data"
        assert TaintSourceType.FILE_CONTENT.value == "file_content"

    def test_taint_violation_types(self):
        """测试污点违规类型枚举"""
        assert TaintViolationType.PRIVILEGE_ESCALATION.value == "privilege_escalation"
        assert TaintViolationType.INFORMATION_LEAK.value == "information_leak"
        assert TaintViolationType.BOUNDARY_VIOLATION.value == "boundary_violation"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])