"""
测试信息流安全策略自动验证模块
"""

import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.information_flow_verifier import InformationFlowVerifier


class TestInformationFlowVerifier:
    """信息流验证器测试类"""
    
    @classmethod
    def setup_class(cls):
        """测试类初始化"""
        cls.verifier = InformationFlowVerifier()
    
    def test_verify_non_interference_pass(self):
        """测试验证非干涉策略通过（所有变量同一级别）"""
        policy_spec = {
            "variables": {
                "input1": "public",
                "input2": "public",
                "output1": "public",
                "output2": "public"
            },
            "rules": []
        }
        
        result = self.verifier.analyze(
            binary_path="/tmp/test.bin",
            policy_spec=policy_spec
        )
        
        assert result["success"] is True
        assert "violations" in result
        assert len(result["violations"]) == 0
        assert result["summary"]["verified"] is True
    
    def test_verify_non_interference_violation(self):
        """测试验证非干涉策略违规"""
        policy_spec = {
            "variables": {
                "secret_password": "secret",
                "public_log": "public"
            },
            "rules": []
        }
        
        result = self.verifier.analyze(
            binary_path="/tmp/test.bin",
            policy_spec=policy_spec
        )
        
        assert result["success"] is True
        assert "violations" in result
        assert len(result["violations"]) > 0
        assert result["summary"]["verified"] is False
    
    def test_verify_custom_rules(self):
        """测试验证自定义规则"""
        policy_spec = {
            "variables": {
                "user_input": "public",
                "password": "secret",
                "output": "public"
            },
            "rules": [
                {"from": "secret", "to": "public", "allow": False, "description": "不允许秘密数据流向公共"},
                {"from": "public", "to": "secret", "allow": True, "description": "允许公共数据流向秘密"}
            ]
        }
        
        result = self.verifier.analyze(
            binary_path="/tmp/test.bin",
            policy_spec=policy_spec
        )
        
        assert result["success"] is True
        assert "violations" in result
    
    def test_missing_policy_spec(self):
        """测试缺少策略规范"""
        result = self.verifier.analyze(
            binary_path="/tmp/test.bin"
        )
        
        assert result["success"] is False
        assert "error" in result
    
    def test_get_metadata(self):
        """测试获取元数据"""
        metadata = InformationFlowVerifier.get_metadata()
        
        assert metadata.name == "InformationFlowVerifier"
        assert metadata.type.value == "formal_verification"
        assert metadata.version == "1.0.0"
        assert "信息流" in metadata.description