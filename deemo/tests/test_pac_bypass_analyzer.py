#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
测试PAC绕过分析模块
"""

import pytest
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from modules.pac_bypass_analyzer import (
    PACAnalyzer, PACBypassType, PACStrength, BypassDifficulty,
    analyze_pac_bypass, evaluate_pac_strength
)


class TestPACBypassAnalyzer:
    """测试PAC绕过分析器"""

    def test_initialization(self):
        """测试初始化"""
        analyzer = PACAnalyzer()
        assert analyzer is not None

    def test_analyze(self):
        """测试分析功能"""
        result = analyze_pac_bypass("/tmp/test.bin")
        
        assert result["success"] == True
        assert "binary_path" in result
        assert "pac_strength" in result
        assert "bypass_findings" in result
        assert isinstance(result["bypass_findings"], list)

    def test_evaluate_strength(self):
        """测试强度评估"""
        result = evaluate_pac_strength("/tmp/test.bin")
        
        assert result["success"] == True
        assert "pac_strength" in result
        assert "overall_difficulty" in result
        assert "recommendation" in result

    def test_pac_bypass_types(self):
        """测试绕过类型枚举"""
        assert PACBypassType.PAC_LEAK.value == "pac_leak"
        assert PACBypassType.PAC_REUSE.value == "pac_reuse"
        assert PACBypassType.PAC_GADGET_REUSE.value == "pac_gadget_reuse"

    def test_bypass_difficulty(self):
        """测试绕过难度"""
        assert BypassDifficulty.EASY.value == "easy"
        assert BypassDifficulty.MEDIUM.value == "medium"
        assert BypassDifficulty.HARD.value == "hard"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])