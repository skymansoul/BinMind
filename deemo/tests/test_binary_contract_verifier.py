"""
测试关键函数微积分合约验证模块
"""

import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.binary_contract_verifier import BinaryContractVerifier


class TestBinaryContractVerifier:
    """合约验证器测试类"""
    
    @classmethod
    def setup_class(cls):
        """测试类初始化"""
        cls.verifier = BinaryContractVerifier()
    
    def test_verify_simple_contract(self):
        """测试验证简单合约"""
        contract_spec = {
            "function_name": "safe_add",
            "preconditions": [
                {"expression": "(>= x 0)", "description": "x非负"},
                {"expression": "(>= y 0)", "description": "y非负"}
            ],
            "postconditions": [
                {"expression": "(>= (+ x y) x)", "description": "结果大于等于x"}
            ]
        }
        
        result = self.verifier.analyze(contract_spec=contract_spec)
        
        assert result["success"] is True
        assert "results" in result
        assert len(result["results"]) > 0
        
        summary = result["summary"]
        assert summary["total_checks"] > 0
        assert summary["verified"] >= 0
    
    def test_verify_violated_contract(self):
        """测试验证被违反的合约"""
        contract_spec = {
            "function_name": "buggy_function",
            "preconditions": [
                {"expression": "(= x 5)", "description": "x等于5"}
            ],
            "postconditions": [
                {"expression": "(= x 0)", "description": "x应该变为0"}
            ]
        }
        
        result = self.verifier.analyze(contract_spec=contract_spec)
        
        assert result["success"] is True
        assert "results" in result
    
    def test_verify_with_invariants(self):
        """测试带不变式的合约验证"""
        contract_spec = {
            "function_name": "stack_operation",
            "preconditions": [
                {"expression": "(>= stack_ptr 0)", "description": "栈指针非负"}
            ],
            "postconditions": [
                {"expression": "(>= stack_ptr 0)", "description": "栈指针仍非负"}
            ],
            "invariants": [
                {"expression": "(< stack_ptr max_size)", "description": "栈指针小于最大尺寸"}
            ],
            "modifies": ["stack_ptr", "stack_data"]
        }
        
        result = self.verifier.analyze(contract_spec=contract_spec)
        
        assert result["success"] is True
        assert "z3_available" in result
    
    def test_missing_contract_spec(self):
        """测试缺少合约规范"""
        result = self.verifier.analyze()
        
        assert result["success"] is False
        assert "error" in result
    
    def test_get_metadata(self):
        """测试获取元数据"""
        metadata = BinaryContractVerifier.get_metadata()
        
        assert metadata.name == "BinaryContractVerifier"
        assert metadata.type.value == "formal_verification"
        assert metadata.version == "1.0.0"
        assert "合约验证" in metadata.description