
"""
测试状态机不一致检测模块
"""

import pytest
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from modules.state_machine_inconsistency import (
    StateMachineAnalyzer, StateTransitionType, InconsistencySeverity,
    analyze_state_machine
)


class TestStateMachineInconsistency:
    """测试状态机不一致检测器"""

    def test_initialization(self):
        analyzer = StateMachineAnalyzer()
        assert analyzer is not None

    def test_analyze(self):
        """测试分析功能"""
        result = analyze_state_machine("/tmp/test.bin")

        assert result["success"] == True
        assert "binary_path" in result
        assert "states" in result
        assert "transitions" in result
        assert "inconsistencies" in result
        assert isinstance(result["inconsistencies"], list)

    def test_state_transition_types(self):
        """测试状态转换类型"""
        assert StateTransitionType.VALID.value == "valid"
        assert StateTransitionType.INVALID.value == "invalid"
        assert StateTransitionType.UNDEFINED.value == "undefined"
        assert StateTransitionType.FORBIDDEN.value == "forbidden"

    def test_inconsistency_severity(self):
        """测试不一致严重程度"""
        assert InconsistencySeverity.CRITICAL.value == "critical"
        assert InconsistencySeverity.HIGH.value == "high"
        assert InconsistencySeverity.MEDIUM.value == "medium"
        assert InconsistencySeverity.LOW.value == "low"



if __name__ == "__main__":
    pytest.main([__file__, "-v"])


