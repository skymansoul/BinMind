"""
侧信道动态量化评估模块测试
"""

import pytest
import statistics
from modules.side_channel_evaluator import SideChannelEvaluator, LeakageType, LeakageSeverity


class TestSideChannelEvaluator:
    """侧信道评估器测试类"""
    
    def test_analyze_without_binary(self):
        """测试无二进制路径的分析"""
        evaluator = SideChannelEvaluator()
        
        result = evaluator.analyze(
            binary_path="",
            test_inputs=[b"test"]
        )
        
        assert result['success'] is False
        assert 'error' in result
    
    def test_determine_severity(self):
        """测试严重程度判断"""
        evaluator = SideChannelEvaluator()
        
        severity = evaluator._determine_severity(
            signal_strength=0.05,
            p_value=0.5,
            bandwidth=0.05
        )
        
        assert severity == LeakageSeverity.NONE
        
        severity = evaluator._determine_severity(
            signal_strength=3.0,
            p_value=0.001,
            bandwidth=3.0
        )
        
        assert severity == LeakageSeverity.HIGH
    
    def test_estimate_bandwidth(self):
        """测试带宽估计"""
        evaluator = SideChannelEvaluator()
        
        bandwidth = evaluator._estimate_bandwidth(0.05, 2)
        assert bandwidth == 0.0
        
        bandwidth = evaluator._estimate_bandwidth(2.0, 4)
        assert bandwidth > 0.0
    
    def test_generate_recommendations(self):
        """测试生成修复建议"""
        evaluator = SideChannelEvaluator()
        
        recommendations = evaluator._generate_recommendations(
            LeakageSeverity.HIGH,
            'timing'
        )
        
        assert isinstance(recommendations, list)
        assert len(recommendations) > 0
    
    def test_metadata(self):
        """测试元数据获取"""
        metadata = SideChannelEvaluator.get_metadata()
        
        assert metadata.name == "SideChannelEvaluator"
        assert metadata.type.value == "vulnerability_detector"


class TestLeakageSeverity:
    """泄露严重程度测试类"""
    
    def test_severity_order(self):
        """测试严重程度排序"""
        assert LeakageSeverity.NONE.value < LeakageSeverity.LOW.value
        assert LeakageSeverity.LOW.value < LeakageSeverity.MEDIUM.value
        assert LeakageSeverity.MEDIUM.value < LeakageSeverity.HIGH.value
        assert LeakageSeverity.HIGH.value < LeakageSeverity.CRITICAL.value