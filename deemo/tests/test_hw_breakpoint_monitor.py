#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
测试硬件断点监控模块
"""

import pytest
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from modules.hw_breakpoint_monitor import (
    HWBreakpointMonitor, BreakpointType, BreakpointSize, TriggerAction,
    analyze_hw_breakpoint
)


class TestHWBreakpointMonitor:
    """测试硬件断点监控器"""

    def test_initialization(self):
        """测试初始化"""
        monitor = HWBreakpointMonitor()
        assert monitor is not None

    def test_analyze(self):
        """测试分析功能"""
        result = analyze_hw_breakpoint("/tmp/test.bin")
        
        assert result["success"] == True
        assert "target_pid" in result
        assert "breakpoints" in result
        assert "triggers" in result
        assert "memory_accesses" in result
        assert isinstance(result["breakpoints"], list)
        assert isinstance(result["triggers"], list)

    def test_analyze_with_breakpoints(self):
        """测试带断点配置的分析"""
        breakpoints = [
            {"id": "bp1", "address": 0x1000, "type": "write", "size": 4},
            {"id": "bp2", "address": 0x2000, "type": "read_write", "size": 8}
        ]
        
        result = analyze_hw_breakpoint("/tmp/test.bin", pid=1234, breakpoints=breakpoints)
        
        assert result["success"] == True
        assert len(result["breakpoints"]) == 2

    def test_add_remove_breakpoint(self):
        """测试添加和移除断点"""
        monitor = HWBreakpointMonitor()
        
        bp_id = monitor.add_breakpoint(0x1000, "write", 4, "log_only", "test breakpoint")
        assert bp_id != ""
        
        result = monitor.remove_breakpoint(bp_id)
        assert result == True

    def test_start_stop_monitoring(self):
        """测试启动和停止监控"""
        monitor = HWBreakpointMonitor()
        
        result = monitor.start_monitoring(pid=1234)
        assert result == True
        
        result = monitor.stop_monitoring()
        assert result == True

    def test_breakpoint_types(self):
        """测试断点类型枚举"""
        assert BreakpointType.EXECUTE.value == "execute"
        assert BreakpointType.WRITE.value == "write"
        assert BreakpointType.READ_WRITE.value == "read_write"

    def test_breakpoint_sizes(self):
        """测试断点大小枚举"""
        assert BreakpointSize.SIZE_1.value == 1
        assert BreakpointSize.SIZE_4.value == 4
        assert BreakpointSize.SIZE_8.value == 8

    def test_trigger_actions(self):
        """测试触发动作枚举"""
        assert TriggerAction.BREAK.value == "break"
        assert TriggerAction.LOG_ONLY.value == "log_only"
        assert TriggerAction.CALLBACK.value == "callback"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])