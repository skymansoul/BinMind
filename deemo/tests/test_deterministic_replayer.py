#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
测试确定性重放模块
"""

import pytest
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from modules.deterministic_replayer import (
    DeterministicReplayer, EventType, ReplayMode, RaceConditionType,
    analyze_deterministic_replay
)


class TestDeterministicReplayer:
    """测试确定性重放器"""

    def test_initialization(self):
        """测试初始化"""
        replayer = DeterministicReplayer()
        assert replayer is not None

    def test_analyze(self):
        """测试分析功能"""
        result = analyze_deterministic_replay("/tmp/test.bin")
        
        assert result["success"] == True
        assert "log_id" in result
        assert "replay_mode" in result
        assert "race_conditions" in result
        assert isinstance(result["race_conditions"], list)

    def test_analyze_with_mode(self):
        """测试不同重放模式"""
        result = analyze_deterministic_replay("/tmp/test.bin", replay_mode="perturb_schedule")
        assert result["success"] == True
        assert result["replay_mode"] == "perturb_schedule"

    def test_event_types(self):
        """测试事件类型枚举"""
        assert EventType.THREAD_CREATE.value == "thread_create"
        assert EventType.LOCK_ACQUIRE.value == "lock_acquire"
        assert EventType.MEMORY_WRITE.value == "memory_write"

    def test_replay_modes(self):
        """测试重放模式枚举"""
        assert ReplayMode.EXACT.value == "exact"
        assert ReplayMode.PERTURB_SCHEDULE.value == "perturb_schedule"
        assert ReplayMode.PARALLEL_EXPLORE.value == "parallel_explore"

    def test_race_condition_types(self):
        """测试竞争条件类型枚举"""
        assert RaceConditionType.DATA_RACE.value == "data_race"
        assert RaceConditionType.DEADLOCK.value == "deadlock"
        assert RaceConditionType.LOCK_ORDER_VIOLATION.value == "lock_order_violation"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])