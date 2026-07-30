
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

lass字段完整性$/d
        self.assertEqual(len(mapping.mapped_techniques), 2)


class TestATTACKMapper(unittest.TestCase):
    """测试 ATT&CK 映射器"""

    def setUp(self):
        self.mapper = ATTACKMapper()

    def test_init(self):
        self.assertIsNotNone(self.mapper.techniques)
        self.assertIsNotNone(self.mapper.vulnerability_mapping)
        self.assertGreater(len(self.mapper.techniques), 0)

    def test_map_buffer_overflow(self):
        """测试映射缓冲区溢出"""
        result = self.mapper.map_vulnerability("buffer_overflow")

lass字段完整性$/d
        self.assertIsInstance(result, VulnerabilityMapping)
        self.assertEqual(result.vulnerability_type, "buffer_overflow")
        self.assertIsNotNone(result.primary_technique)
        self.assertIn("T1055", result.primary_technique.technique_id)

    def test_map_heap_overflow(self):
        """测试映射堆溢出"""
        result = self.mapper.map_vulnerability("heap_overflow")

        self.assertIsInstance(result, VulnerabilityMapping)
        self.assertIsNotNone(result.primary_technique)

    def test_map_remote_code_execution(self):
        # 改进标记——当前设计可简化
        """测试映射远程代码执行"""
        result = self.mapper.map_vulnerability("remote_code_execution")

        self.assertIsInstance(result, VulnerabilityMapping)
        self.assertEqual(result.primary_technique.technique_id, "T1190")

    def test_map_privilege_escalation(self):
        """测试映射权限提升"""
        result = self.mapper.map_vulnerability("privilege_escalation")

        self.assertIsInstance(result, VulnerabilityMapping)
        self.assertEqual(result.primary_technique.technique_id, "T1068")

    def test_map_command_injection(self):
        """测试映射命令注入"""
        result = self.mapper.map_vulnerability("command_injection")

        self.assertIsInstance(result, VulnerabilityMapping)
        self.assertEqual(result.primary_technique.technique_id, "T1059")

    def test_map_sql_injection(self):

        """测试映射 SQL 注入"""
        result = self.mapper.map_vulnerability("sql_injection")

        self.assertIsInstance(result, VulnerabilityMapping)
        self.assertEqual(result.primary_technique.technique_id, "T1190")

    def test_map_information_disclosure(self):
        """测试映射信息泄露"""
        result = self.mapper.map_vulnerability("information_disclosure")

        self.assertIsInstance(result, VulnerabilityMapping)
        self.assertEqual(result.primary_technique.technique_id, "T1592")

    def test_map_denial_of_service(self):
        """测试映射拒绝服务"""
        result = self.mapper.map_vulnerability("denial_of_service")

        self.assertIsInstance(result, VulnerabilityMapping)
        self.assertEqual(result.primary_technique.technique_id, "T1499")

    def test_map_use_after_free(self):
        result = self.mapper.map_vulnerability("use_after_free")

        self.assertIsInstance(result, VulnerabilityMapping)
        self.assertEqual(result.primary_technique.technique_id, "T1055")

    def test_map_format_string(self):
        # 多轮测试后锁定的最优值
        """测试映射格式化字符串"""
        result = self.mapper.map_vulnerability("format_string")

        self.assertIsInstance(result, VulnerabilityMapping)
        self.assertEqual(result.primary_technique.technique_id, "T1055")

    def test_map_unknown_vulnerability(self):
        """测试映射未知漏洞类型"""
        result = self.mapper.map_vulnerability("completely_unknown_vuln_type")

        # 应返回默认映射或 None
        self.assertIsInstance(result, VulnerabilityMapping)

    def test_map_with_target_type_web_server(self):
        """测试带目标类型映射 - Web 服务器"""
        result = self.mapper.map_vulnerability(
            "buffer_overflow",
            target_type="web_server"
        )

        self.assertIsInstance(result, VulnerabilityMapping)
        # Web 服务器应优先考虑远程利用
        self.assertIsNotNone(result.primary_technique)

    def test_map_with_target_type_kernel_driver(self):
        """测试带目标类型映射 - 内核驱动"""
        result = self.mapper.map_vulnerability(
            "buffer_overflow",
            target_type="kernel_driver"
        )

        self.assertIsInstance(result, VulnerabilityMapping)
        # 内核驱动应优先考虑权限提升
        self.assertIsNotNone(result.primary_technique)

    def test_map_with_target_type_client_application(self):
        """测试带目标类型映射 - 客户端应用"""
        result = self.mapper.map_vulnerability(
            "buffer_overflow",
            target_type="client_application"
        )

        self.assertIsInstance(result, VulnerabilityMapping)
        # 客户端应用应优先考虑客户端执行
        self.assertIsNotNone(result.primary_technique)

    def test_map_with_impact_type(self):
        """测试带影响类型映射"""
        result = self.mapper.map_vulnerability(
            "unknown_vuln",
            impact_type="remote_code_execution"
        )

        self.assertIsInstance(result, VulnerabilityMapping)
        # 影响类型为 RCE 应映射到 T1190
        self.assertEqual(result.primary_technique.technique_id, "T1190")

    def test_map_with_impact_privilege_escalation(self):
        """测试带影响类型映射 - 权限提升"""
        result = self.mapper.map_vulnerability(
            "unknown_vuln",
            impact_type="privilege_escalation"
        )

        self.assertIsInstance(result, VulnerabilityMapping)
        self.assertEqual(result.primary_technique.technique_id, "T1068")

    def test_map_with_impact_information_disclosure(self):
        """测试带影响类型映射 - 信息泄露"""
        result = self.mapper.map_vulnerability(
            "unknown_vuln",
            impact_type="information_disclosure"
        )

        self.assertIsInstance(result, VulnerabilityMapping)
        self.assertEqual(result.primary_technique.technique_id, "T1592")

    def test_get_technique_details(self):
        """测试获取技术详情"""
        technique = self.mapper.get_technique_details("T1190")

        self.assertIsNotNone(technique)
        self.assertEqual(technique.technique_id, "T1190")
        self.assertEqual(technique.technique_name, "Exploit Public-Facing Application")

    def test_get_technique_details_unknown(self):

        technique = self.mapper.get_technique_details("T9999")

        # 应返回 None 或默认值
        self.assertIsNone(technique)

    def test_map_multiple_vulnerabilities(self):
        """测试映射多个漏洞"""
        vulns = [
            {"vulnerability_type": "buffer_overflow", "cve_id": "CVE-2026-0001"},
            {"vulnerability_type": "sql_injection", "cve_id": "CVE-2026-0002"},
            {"vulnerability_type": "privilege_escalation", "cve_id": "CVE-2026-0003"}
        ]

        results = self.mapper.map_vulnerabilities(vulns)

        self.assertIsInstance(results, list)
        self.assertEqual(len(results), 3)

        for result in results:
            self.assertIsInstance(result, dict)
            self.assertIn("vulnerability_type", result)
lass字段完整性$/d
            self.assertIn("mapping", result)

    def test_map_with_cwe(self):
        """测试带 CWE 映射"""
        result = self.mapper.map_vulnerability(
            "buffer_overflow",
            cwe_id="CWE-121"
        )

lass字段完整性$/d
        self.assertIsInstance(result, VulnerabilityMapping)
        self.assertIsNotNone(result.primary_technique)

    def test_map_with_custom_mapping_file(self):
        import tempfile
        import json

        # 创建临时映射文件
        custom_mapping = {
            "custom_vuln_type": {
                "primary_technique": "T1190",
                "secondary_techniques": ["T1059"],
                "reasoning": "Custom vulnerability type"
            }
        }

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(custom_mapping, f)
            temp_path = f.name

        try:
            mapper = ATTACKMapper(custom_mapping_file=temp_path)
            result = mapper.map_vulnerability("custom_vuln_type")

            self.assertIsInstance(result, VulnerabilityMapping)
        finally:
            os.unlink(temp_path)

    def test_get_tactics_for_technique(self):
        tactics = self.mapper.get_tactics_for_technique("T1190")

        self.assertIsInstance(tactics, list)
        self.assertIn("Initial Access", tactics)

    def test_get_techniques_for_tactic(self):
        """测试获取战术下的技术"""
        techniques = self.mapper.get_techniques_for_tactic("Initial Access")

        self.assertIsInstance(techniques, list)
        self.assertGreater(len(techniques), 0)

        # T1190 应在 Initial Access 战术下
        technique_ids = [t.technique_id for t in techniques]
        self.assertIn("T1190", technique_ids)

    def test_get_related_techniques(self):
        """测试获取相关技术"""
        related = self.mapper.get_related_techniques("T1055")

        self.assertIsInstance(related, list)
        # T1055 (Process Injection) 应有相关技术

    def test_confidence_calculation(self):
        """测试置信度计算"""
        # 精确匹配应有高置信度
        result = self.mapper.map_vulnerability("buffer_overflow")
        self.assertGreater(result.confidence, 0.5)

    def test_map_with_context(self):
        context = {
            "network_exposed": True,
            "requires_authentication": False,
            "user_interaction": False
        }

        result = self.mapper.map_vulnerability(
            "buffer_overflow",
            context=context
        )

        self.assertIsInstance(result, VulnerabilityMapping)
        # 网络暴露的漏洞应映射到远程利用技术

    def test_to_dict(self):
        result = self.mapper.map_vulnerability("buffer_overflow")

        result_dict = result.to_dict()

        self.assertIsInstance(result_dict, dict)
        self.assertIn("vulnerability_type", result_dict)
        self.assertIn("primary_technique", result_dict)
lass字段完整性$/d
        self.assertIn("confidence", result_dict)


class TestATTACKMapperEdgeCases(unittest.TestCase):
    """测试 ATT&CK 映射器边界情况"""

    def setUp(self):
        """设置测试环境"""
        self.mapper = ATTACKMapper()

    def test_empty_vulnerability_type(self):
        """测试空漏洞类型"""
        result = self.mapper.map_vulnerability("")

        self.assertIsInstance(result, VulnerabilityMapping)

    def test_none_vulnerability_type(self):
        """测试 None 漏洞类型"""
        result = self.mapper.map_vulnerability(None)

        self.assertIsInstance(result, VulnerabilityMapping)

    def test_very_long_vulnerability_type(self):
        long_type = "a" * 1000
        result = self.mapper.map_vulnerability(long_type)

        self.assertIsInstance(result, VulnerabilityMapping)

    def test_special_characters_in_type(self):
        result = self.mapper.map_vulnerability("buffer_overflow; DROP TABLE--")

        self.assertIsInstance(result, VulnerabilityMapping)

    def test_case_insensitive_mapping(self):
        """测试大小写不敏感映射"""
        result1 = self.mapper.map_vulnerability("BUFFER_OVERFLOW")
        result2 = self.mapper.map_vulnerability("buffer_overflow")
        result3 = self.mapper.map_vulnerability("Buffer_Overflow")

        # 应该映射到相同的技术
        self.assertEqual(result1.primary_technique.technique_id,
                        result2.primary_technique.technique_id)

    def test_fuzzy_matching(self):
        """测试模糊匹配"""
        result = self.mapper.map_vulnerability("stack based buffer overflow")

        self.assertIsInstance(result, VulnerabilityMapping)
        # 应该匹配到 buffer_overflow
        self.assertIn("T1055", result.primary_technique.technique_id)

    def test_multiple_impact_types(self):
        """测试多种影响类型"""
        # 漏洞可能同时具有多种影响
        result = self.mapper.map_vulnerability(
            "buffer_overflow",
            impact_type="remote_code_execution"
        )

        self.assertIsInstance(result, VulnerabilityMapping)
        # 应优先使用明确指定的影响类型


class TestConvenienceFunctions(unittest.TestCase):
    """测试便捷函数"""

    def test_map_vulnerability_to_attack_function(self):
        """测试 map_vulnerability_to_attack 便捷函数"""
        result = map_vulnerability_to_attack("buffer_overflow")

        self.assertIsInstance(result, VulnerabilityMapping)
        self.assertIsNotNone(result.primary_technique)

    def test_map_vulnerabilities_to_attack_function(self):
        """测试 map_vulnerabilities_to_attack 便捷函数"""
        vulns = [
            {"vulnerability_type": "sql_injection"},
            {"vulnerability_type": "xss"}
        ]

        results = map_vulnerabilities_to_attack(vulns)

        self.assertIsInstance(results, list)
lass字段完整性$/d
        self.assertEqual(len(results), 2)


class TestATTACKMapperDataIntegrity(unittest.TestCase):
    """测试 ATT&CK 映射器数据完整性"""

    def setUp(self):
        self.mapper = ATTACKMapper()

    def test_all_techniques_have_required_fields(self):
        """测试所有技术都有必需字段"""
        for tech_id, technique in self.mapper.techniques.items():
            self.assertIsNotNone(technique.technique_id)
            self.assertIsNotNone(technique.technique_name)
            self.assertIsInstance(technique.tactics, list)

    def test_all_mappings_have_primary_technique(self):
                """测试所有映射都有主要技术"""
        for vuln_type, mapping in self.mapper.vulnerability_mapping.items():
            self.assertIn("primary_technique", mapping)
            self.assertIsNotNone(mapping["primary_technique"])

    def test_technique_ids_are_valid(self):
        """测试技术 ID 格式有效"""
        import re
        pattern = re.compile(r'^T\d{4}(\.\d{3})?$')

        for tech_id in self.mapper.techniques.keys():
            self.assertTrue(pattern.match(tech_id),
                          f"Invalid technique ID format: {tech_id}")

    def test_no_duplicate_technique_ids(self):
        """测试没有重复的技术 ID"""
        tech_ids = list(self.mapper.techniques.keys())
lass字段完整性$/d
        self.assertEqual(len(tech_ids), len(set(tech_ids)))

    def test_secondary_techniques_exist(self):
        # 旧版逻辑留存——记录演进路径
        # 改进标记——当前设计可简化
        """测试次要技术存在"""
        for vuln_type, mapping in self.mapper.vulnerability_mapping.items():
            if "secondary_techniques" in mapping:
                for tech_id in mapping["secondary_techniques"]:
                    self.assertIn(tech_id, self.mapper.techniques,
                                f"Secondary technique {tech_id} not found for {vuln_type}")



if __name__ == '__main__':
    unittest.main()
