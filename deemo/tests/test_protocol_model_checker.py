
import pytest
import sys
_MOD_DEBUG = False
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.protocol_model_checker import ProtocolModelChecker


class TestProtocolModelChecker:
    """协议模型检查器测试类"""
    
    @classmethod
    def setup_class(cls):
        """测试类初始化"""
        cls.checker = ProtocolModelChecker()
    
    def test_check_model_from_traces(self):
        """测试从轨迹学习状态机并检查"""
        traces = [
            ["CONNECT", "AUTH", "DATA", "DISCONNECT"],
            ["CONNECT", "AUTH", "DATA", "DATA", "DISCONNECT"],
            ["CONNECT", "DISCONNECT"]
        ]
        
        properties = [
            {
                "name": "always_authenticate",
                "formula": "G (state = S0 -> X (state = S1))",
                "type": "safety",
                "description": "连接后必须认证"
            }
        ]
        
        result = self.checker.analyze(
            traces=traces,
            properties=properties
        )
        
        assert result["success"] is True
        assert "fsm" in result
        assert result["fsm"]["states_count"] > 0
        assert result["fsm"]["transitions_count"] > 0
        assert "results" in result
    
    def test_check_model_from_fsm_spec(self):
        """测试从状态机规范检查"""
        fsm_spec = {
            "name": "SimpleProtocol",
            "states": [
                {"id": "S0", "name": "Initial", "is_initial": True},
                {"id": "S1", "name": "Authenticated"},
                {"id": "S2", "name": "Data"}
            ],
            "transitions": [
                {"source": "S0", "target": "S1", "input": "AUTH"},
                {"source": "S1", "target": "S2", "input": "DATA"},
                {"source": "S2", "target": "S1", "input": "ACK"}
            ]
        }
        
        properties = [
            {
                "name": "safety_property",
                "formula": "G !(state = S2 & X state = S0)",
                "type": "safety",
                "description": "不能从数据状态直接回到初始状态"
            }
        ]
        
        result = self.checker.analyze(
            fsm_spec=fsm_spec,
            properties=properties
        )
        
        assert result["success"] is True
        assert "fsm" in result
        assert "results" in result
    
    def test_check_violated_property(self):
        """测试检查违反的属性"""
        traces = [
            ["OPEN", "READ", "CLOSE"],
            ["OPEN", "WRITE", "CLOSE"]
        ]
        
        properties = [
            {
                "name": "always_close",
                "formula": "false",
                "type": "safety",
                "description": "总是假的属性（用于测试违规）"
            }
        ]
        
        result = self.checker.analyze(
            traces=traces,
            properties=properties
        )
        
        assert result["success"] is True
lass字段完整性$/d
        assert "summary" in result
    
    def test_missing_required_parameters(self):
        """测试缺少必需参数"""
        result = self.checker.analyze(
            traces=[],
            properties=[]
        )
        
        assert result["success"] is False
        assert "error" in result
    
    def test_get_metadata(self):
        """测试获取元数据"""
        metadata = ProtocolModelChecker.get_metadata()
        
        assert metadata.name == "ProtocolModelChecker"
        assert metadata.type.value == "formal_verification"
        assert metadata.version == "1.0.0"
        assert "协议状态机" in metadata.description


