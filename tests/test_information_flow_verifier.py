# -*- coding: utf-8 -*-

import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.information_flow_verifier import InformationFlowVerifier


class TestInformationFlowVerifier:
    """Information flow verifier tests"""

    @classmethod
    def setup_class(cls):
        """class-level setup"""
        cls.verifier = InformationFlowVerifier()

    def test_verify_non_interference_pass(self):
        """All variables at same level -> should pass"""
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
        policy_spec = {
            "variables": {
                "user_input": "public",
                "password": "secret",
                "output": "public"
            },
            "rules": [
                {"from": "secret", "to": "public", "allow": False, "description": "no secret->public flow"},
                {"from": "public", "to": "secret", "allow": True, "description": "public->secret allowed"}
            ]
        }

        result = self.verifier.analyze(
            binary_path="/tmp/test.bin",
            policy_spec=policy_spec
        )

        assert result["success"] is True
        assert "violations" in result

    def test_missing_policy_spec(self):
        """Missing policy spec should fail"""
        result = self.verifier.analyze(
            binary_path="/tmp/test.bin"
        )

        assert result["success"] is False
        assert "error" in result

    def test_get_metadata(self):
        """Test metadata retrieval"""
        metadata = InformationFlowVerifier.get_metadata()

        assert metadata.name == "InformationFlowVerifier"
        assert metadata.type.value == "formal_verification"
        assert metadata.version == "1.0.0"
        assert "info流" in metadata.description
