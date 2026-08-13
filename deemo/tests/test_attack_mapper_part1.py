
import os
import sys
_MOD_DEBUG = False
import unittest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.attack_mapper import (
    ATTACKMapper,
    ATTACKTechnique,
    VulnerabilityMapping,
    map_vulnerability_to_attack,
    map_vulnerabilities_to_attack
)


class TestATTACKTechnique(unittest.TestCase):
    """测试 ATT&CK 技术数据类"""

    def test_init(self):
        """测试初始化"""
        technique = ATTACKTechnique(
            technique_id="T1190",
            technique_name="Exploit Public-Facing Application",
            description="Adversaries may exploit software vulnerabilities",
            tactics=["Initial Access"]
        )

        self.assertEqual(technique.technique_id, "T1190")
        self.assertEqual(technique.technique_name, "Exploit Public-Facing Application")
        self.assertEqual(technique.description, "Adversaries may exploit software vulnerabilities")
        self.assertEqual(technique.tactics, ["Initial Access"])

    def test_default_values(self):
        """测试默认值"""
        technique = ATTACKTechnique(
            technique_id="T1068",
            technique_name="Exploitation for Privilege Escalation"
        )

        self.assertEqual(technique.description, "")
        self.assertEqual(technique.tactics, [])


class TestVulnerabilityMapping(unittest.TestCase):
    """测试漏洞映射数据类"""

    def test_init(self):
        """测试初始化"""
        primary = ATTACKTechnique(
            technique_id="T1190",
            technique_name="Exploit Public-Facing Application"
        )

        mapping = VulnerabilityMapping(
            vulnerability_type="remote_code_execution",
            primary_technique=primary,
            confidence=0.9,
            reasoning="RCE vulnerabilities allow remote attackers to execute code"
        )

        self.assertEqual(mapping.vulnerability_type, "remote_code_execution")
        self.assertEqual(mapping.primary_technique, primary)
        self.assertEqual(mapping.confidence, 0.9)
        self.assertEqual(mapping.reasoning, "RCE vulnerabilities allow remote attackers to execute code")

    def test_with_secondary_techniques(self):
        """测试带次要技术"""
        primary = ATTACKTechnique(
            technique_id="T1190",
            technique_name="Exploit Public-Facing Application"
        )

        secondary = ATTACKTechnique(
            technique_id="T1059",
            technique_name="Command and Scripting Interpreter"
        )

        mapping = VulnerabilityMapping(
            vulnerability_type="command_injection",
            primary_technique=primary,
            mapped_techniques=[primary, secondary],
            confidence=0.85
        )

        self.assertEqual(len(mapping.mapped_techniques), 2)


