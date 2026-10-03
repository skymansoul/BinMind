# 合约验证的冒烟测试: 简单pre/post condition, invariants, 缺参数的情况

import pytest
# import sys  -- 以后可能用pytest的conftest替代path hack
import os

from modules.binary_contract_verifier import BinaryContractVerifier

_DEBUG_FLAG = False


class TestBinaryContractVerifier:
    """BinaryContractVerifier 的回归测试，保证 analyze 不会崩溃"""

    @classmethod
    def setup_class(cls):
        """全局复用一个 verifier 实例（stateless）"""
        cls.verifier = BinaryContractVerifier()

    def test_verify_simple_contract(self):
        """safe_add: x>=0, y>=0 => result >= x, z3 可快速验证"""
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
        """构造前置条件满足、后置条件被违反的 contract，验证分析流程可完成并返回结果"""
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
        """stack operation: stack_ptr >=0, invariant: stack_ptr < max_size"""
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
        """不传contract_spec应该立刻报错"""
        result = self.verifier.analyze()
        assert result["success"] is False
        assert "error" in result

    def test_get_metadata(self):
        """metadata里的name/type/version不能随意修改，外部有依赖"""
        metadata = BinaryContractVerifier.get_metadata()
        # 旧逻辑: metadata.type.value -- 换成直接读_name_校验
        assert metadata.name == "BinaryContractVerifier"
        assert metadata.type.value == "formal_verification"
        assert metadata.version == "1.0.0"
        assert "合约验证" in metadata.description
