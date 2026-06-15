"""
IDS 规则生成器模块单元测试
"""

import os
import sys
import tempfile
import unittest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.ids_rule_generator import (
    IDSRuleGenerator,
    IDSRuleContent,
    AttackSignature,
    NetworkFunctionInfo,
    generate_ids_rules
)


class TestIDSRuleContent(unittest.TestCase):
    """测试 IDS 规则内容数据类"""

    def test_init(self):
        """测试初始化"""
        rule = IDSRuleContent()
        self.assertEqual(rule.action, "alert")
        self.assertEqual(rule.protocol, "tcp")
        self.assertEqual(rule.source_ip, "$EXTERNAL_NET")
        self.assertEqual(rule.dest_ip, "$HOME_NET")
        self.assertEqual(rule.dest_port, "$SERVICE_PORTS")
        self.assertEqual(rule.sid, 0)
        self.assertEqual(rule.classtype, "attempted-admin")

    def test_custom_values(self):
        """测试自定义值"""
        rule = IDSRuleContent(
            action="drop",
            protocol="udp",
            source_ip="10.0.0.1",
            dest_ip="192.168.1.1",
            dest_port="8080",
            msg="Test rule",
            sid=1000001,
            classtype="attempted-recon"
        )
        self.assertEqual(rule.action, "drop")
        self.assertEqual(rule.protocol, "udp")
        self.assertEqual(rule.source_ip, "10.0.0.1")
        self.assertEqual(rule.dest_ip, "192.168.1.1")
        self.assertEqual(rule.dest_port, "8080")
        self.assertEqual(rule.msg, "Test rule")
        self.assertEqual(rule.sid, 1000001)
        self.assertEqual(rule.classtype, "attempted-recon")


class TestAttackSignature(unittest.TestCase):
    """测试攻击特征数据类"""

    def test_init(self):
        """测试初始化"""
        sig = AttackSignature(
            signature_type="buffer_overflow",
            pattern=b"AAAA" * 100,
            offset=0,
            description="Buffer overflow payload"
        )
        self.assertEqual(sig.signature_type, "buffer_overflow")
        self.assertEqual(sig.pattern, b"AAAA" * 100)
        self.assertEqual(sig.offset, 0)
        self.assertEqual(sig.description, "Buffer overflow payload")

    def test_to_content_dict(self):
        """测试转换为内容字典"""
        sig = AttackSignature(
            signature_type="pattern",
            pattern=b"\\x41\\x42\\x43",
            offset=10,
            description="Test pattern"
        )
        content_dict = sig.to_content_dict()
        
        self.assertIn("content", content_dict)
        self.assertIn("offset", content_dict)
        self.assertEqual(content_dict["offset"], 10)


class TestNetworkFunctionInfo(unittest.TestCase):
    """测试网络函数信息数据类"""

    def test_init(self):
        """测试初始化"""
        info = NetworkFunctionInfo(
            function_name="socket",
            category="socket_creation",
            is_server=True,
            is_client=False
        )
        self.assertEqual(info.function_name, "socket")
        self.assertEqual(info.category, "socket_creation")
        self.assertTrue(info.is_server)
        self.assertFalse(info.is_client)


class TestIDSRuleGenerator(unittest.TestCase):
    """测试 IDS 规则生成器"""

    def setUp(self):
        """设置测试环境"""
        self.temp_dir = tempfile.mkdtemp()
        self.generator = IDSRuleGenerator(output_dir=self.temp_dir)

    def tearDown(self):
        """清理测试环境"""
        import shutil
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)

    def test_init(self):
        """测试初始化"""
        self.assertIsNotNone(self.generator.output_dir)
        self.assertEqual(self.generator.format, "suricata")
        self.assertEqual(self.generator.base_sid, 1000000)
        self.assertIn("socket", self.generator.network_functions)

    def test_is_network_service_with_network_functions(self):
        """测试检测网络服务程序 - 包含网络函数"""
        binary_info = {
            "imports": ["socket", "bind", "listen", "accept", "recv", "send"]
        }
        
        result = self.generator.is_network_service(binary_info)
        self.assertTrue(result)

    def test_is_network_service_without_network_functions(self):
        """测试检测网络服务程序 - 不包含网络函数"""
        binary_info = {
            "imports": ["printf", "malloc", "free", "strcpy"]
        }
        
        result = self.generator.is_network_service(binary_info)
        self.assertFalse(result)

    def test_is_network_service_with_firmware_info(self):
        """测试检测网络服务程序 - 固件信息"""
        binary_info = {
            "imports": [],
            "firmware_info": {
                "device_type": "router"
            }
        }
        
        result = self.generator.is_network_service(binary_info)
        self.assertTrue(result)

    def test_is_network_service_with_protocol_info(self):
        """测试检测网络服务程序 - 协议信息"""
        binary_info = {
            "imports": [],
            "protocol_info": {
                "protocols": ["HTTP", "FTP"]
            }
        }
        
        result = self.generator.is_network_service(binary_info)
        self.assertTrue(result)

    def test_is_remote_triggerable_buffer_overflow(self):
        """测试检测远程可触发漏洞 - 缓冲区溢出"""
        vuln_info = {
            "vulnerability_type": "buffer_overflow",
            "trigger": "network_input",
            "location": "handle_client_request"
        }
        
        result = self.generator.is_remote_triggerable(vuln_info)
        self.assertTrue(result)

    def test_is_remote_triggerable_command_injection(self):
        """测试检测远程可触发漏洞 - 命令注入"""
        vuln_info = {
            "vulnerability_type": "command_injection",
            "trigger": "user_input"
        }
        
        result = self.generator.is_remote_triggerable(vuln_info)
        self.assertTrue(result)

    def test_is_remote_triggerable_local_vulnerability(self):
        """测试检测远程可触发漏洞 - 本地漏洞"""
        vuln_info = {
            "vulnerability_type": "buffer_overflow",
            "trigger": "local_file"
        }
        
        result = self.generator.is_remote_triggerable(vuln_info)
        self.assertFalse(result)

    def test_extract_attack_signature_from_crash(self):
        """测试从崩溃数据提取攻击特征"""
        crash_data = {
            "crash_type": "buffer_overflow",
            "crashing_input": b"A" * 200 + b"BBBB" + b"CCCCCCCC",
            "registers": {
                "eip": "0x42424242"
            },
            "stack_trace": ["0x42424242", "0x43434343"]
        }
        
        signatures = self.generator.extract_attack_signature(
            crash_data=crash_data,
            vuln_type="buffer_overflow"
        )
        
        self.assertIsInstance(signatures, list)
        self.assertGreater(len(signatures), 0)
        
        # 验证特征包含溢出模式
        has_overflow_pattern = any(
            sig.signature_type == "buffer_overflow" 
            for sig in signatures
        )
        self.assertTrue(has_overflow_pattern)

    def test_extract_attack_signature_from_symbolic(self):
        """测试从符号执行结果提取攻击特征"""
        symbolic_result = {
            "constraints": [
                {"type": "buffer_size", "value": 256},
                {"type": "offset", "value": 260}
            ],
            "input_pattern": {
                "data": b"GET /" + b"A" * 256 + b"XXXX",
                "offset": 0
            },
            "trigger_condition": "input_length > 256"
        }
        
        signatures = self.generator.extract_attack_signature(
            symbolic_result=symbolic_result,
            vuln_type="buffer_overflow"
        )
        
        self.assertIsInstance(signatures, list)
        self.assertGreater(len(signatures), 0)

    def test_extract_attack_signature_with_protocol(self):
        """测试从协议信息提取攻击特征"""
        protocol_info = {
            "fields": [
                {"name": "command", "offset": 0, "size": 4, "type": "string"},
                {"name": "length", "offset": 4, "size": 4, "type": "uint32"},
                {"name": "data", "offset": 8, "type": "variable"}
            ],
            "magic_bytes": b"CMD\x00"
        }
        
        signatures = self.generator.extract_attack_signature(
            protocol_info=protocol_info,
            vuln_type="buffer_overflow"
        )
        
        self.assertIsInstance(signatures, list)
        # 应该包含协议魔数特征
        has_magic = any(
            sig.signature_type == "protocol_magic" 
            for sig in signatures
        )
        self.assertTrue(has_magic)

    def test_generate_rule_suricata(self):
        """测试生成 Suricata 规则"""
        rule_content = IDSRuleContent(
            action="alert",
            protocol="tcp",
            source_ip="$EXTERNAL_NET",
            source_port="any",
            dest_ip="$HOME_NET",
            dest_port="$HTTP_PORTS",
            msg="CVE-2024-1234 Buffer overflow in HTTP server",
            sid=1000001,
            classtype="attempted-admin",
            reference="cve,CVE-2024-1234"
        )
        rule_content.content_matches = [
            {"content": "GET /", "offset": 0, "depth": 4},
            {"content": "|41 41 41 41|", "offset": 100}
        ]
        
        rule_str = self.generator.generate_rule(rule_content, format="suricata")
        
        self.assertIsInstance(rule_str, str)
        self.assertIn("alert tcp", rule_str)
        self.assertIn("$EXTERNAL_NET", rule_str)
        self.assertIn("$HOME_NET", rule_str)
        self.assertIn("msg:", rule_str)
        self.assertIn("sid:1000001", rule_str)
        self.assertIn("classtype:attempted-admin", rule_str)
        self.assertIn("content:", rule_str)

    def test_generate_rule_snort(self):
        """测试生成 Snort 规则"""
        rule_content = IDSRuleContent(
            action="alert",
            protocol="tcp",
            source_ip="$EXTERNAL_NET",
            source_port="any",
            dest_ip="$HOME_NET",
            dest_port="80",
            msg="Test Snort rule",
            sid=1000002,
            classtype="attempted-recon"
        )
        
        rule_str = self.generator.generate_rule(rule_content, format="snort")
        
        self.assertIsInstance(rule_str, str)
        self.assertIn("alert tcp", rule_str)
        self.assertIn("sid:1000002", rule_str)

    def test_validate_rule_syntax_valid(self):
        """测试验证规则语法 - 有效规则"""
        valid_rule = 'alert tcp $EXTERNAL_NET any -> $HOME_NET 80 (msg:"Test rule"; sid:1000001; classtype:attempted-admin;)'
        
        result = self.generator.validate_rule_syntax(valid_rule)
        self.assertTrue(result)

    def test_validate_rule_syntax_invalid(self):
        """测试验证规则语法 - 无效规则"""
        invalid_rule = 'alert tcp any -> any (msg:"Invalid rule"'
        
        result = self.generator.validate_rule_syntax(invalid_rule)
        self.assertFalse(result)

    def test_generate_rules_for_vulnerability(self):
        """测试为漏洞生成规则"""
        binary_info = {
            "imports": ["socket", "bind", "listen", "accept"],
            "binary_name": "test_server"
        }
        
        vuln_info = {
            "vulnerability_type": "buffer_overflow",
            "trigger": "network_input",
            "cve_id": "CVE-2024-1234",
            "description": "Buffer overflow in HTTP request handling",
            "location": "handle_http_request",
            "crash_data": {
                "crash_type": "buffer_overflow",
                "crashing_input": b"A" * 500
            }
        }
        
        rules = self.generator.generate_rules_for_vulnerability(
            binary_info=binary_info,
            vuln_info=vuln_info
        )
        
        self.assertIsInstance(rules, list)
        self.assertGreater(len(rules), 0)
        
        # 验证规则包含必要字段
        for rule in rules:
            self.assertIn("rule", rule)
            self.assertIn("sid", rule)
            self.assertIn("vulnerability_type", rule)

    def test_generate_rules_for_non_network_binary(self):
        """测试为非网络程序生成规则"""
        binary_info = {
            "imports": ["printf", "malloc"],
            "binary_name": "test_local"
        }
        
        vuln_info = {
            "vulnerability_type": "buffer_overflow",
            "trigger": "local_file"
        }
        
        rules = self.generator.generate_rules_for_vulnerability(
            binary_info=binary_info,
            vuln_info=vuln_info
        )
        
        # 非网络程序不应生成规则
        self.assertEqual(len(rules), 0)

    def test_save_rules_to_file(self):
        """测试保存规则到文件"""
        rules = [
            {
                "rule": 'alert tcp $EXTERNAL_NET any -> $HOME_NET 80 (msg:"Test rule 1"; sid:1000001;)',
                "sid": 1000001,
                "vulnerability_type": "buffer_overflow"
            },
            {
                "rule": 'alert tcp $EXTERNAL_NET any -> $HOME_NET 21 (msg:"Test rule 2"; sid:1000002;)',
                "sid": 1000002,
                "vulnerability_type": "command_injection"
            }
        ]
        
        output_path = self.generator.save_rules_to_file(
            rules=rules,
            binary_name="test_server",
            format="suricata"
        )
        
        self.assertTrue(os.path.exists(output_path))
        
        # 验证文件内容
        with open(output_path, 'r', encoding='utf-8') as f:
            content = f.read()
            self.assertIn("alert tcp", content)
            self.assertIn("sid:1000001", content)
            self.assertIn("sid:1000002", content)

    def test_generate_generic_rule(self):
        """测试生成通用规则框架"""
        vuln_info = {
            "vulnerability_type": "buffer_overflow",
            "cve_id": "CVE-2024-5678",
            "description": "Generic buffer overflow"
        }
        
        rule = self.generator._generate_generic_rule(vuln_info)
        
        self.assertIsNotNone(rule)
        self.assertIn("alert tcp", rule.rule)
        self.assertIn("CVE-2024-5678", rule.msg)
        self.assertIn("Manual review required", rule.msg)

    def test_generate_ids_rules_convenience_function(self):
        """测试便捷函数 generate_ids_rules"""
        binary_info = {
            "imports": ["socket", "bind", "listen"],
            "binary_name": "test_app"
        }
        
        vulns_info = [
            {
                "vulnerability_type": "buffer_overflow",
                "trigger": "network_input",
                "cve_id": "CVE-2024-9999"
            }
        ]
        
        result = generate_ids_rules(
            binary_info=binary_info,
            vulns_info=vulns_info,
            output_dir=self.temp_dir
        )
        
        self.assertIn("rules", result)
        self.assertIn("output_file", result)
        self.assertIn("total_rules", result)

    def test_determine_port_from_protocol(self):
        """测试从协议信息确定端口"""
        protocol_info = {
            "protocol_name": "HTTP",
            "default_port": 80
        }
        
        port = self.generator._determine_port(protocol_info)
        self.assertEqual(port, "80")

    def test_determine_port_from_vuln_info(self):
        """测试从漏洞信息确定端口"""
        vuln_info = {
            "network_service": {
                "port": 8080,
                "protocol": "TCP"
            }
        }
        
        port = self.generator._determine_port(None, vuln_info)
        self.assertEqual(port, "8080")

    def test_determine_port_default(self):
        """测试默认端口"""
        port = self.generator._determine_port(None, None)
        self.assertEqual(port, "$SERVICE_PORTS")

    def test_extract_content_from_input(self):
        """测试从输入数据提取内容特征"""
        input_data = b"GET /path HTTP/1.1\r\nHost: example.com\r\n\r\n"
        
        content = self.generator._extract_content_from_input(input_data)
        
        self.assertIsInstance(content, list)
        self.assertGreater(len(content), 0)
        
        # 应包含 HTTP 方法
        has_get = any("GET" in str(c) for c in content)
        self.assertTrue(has_get)

    def test_sid_generation(self):
        """测试 SID 生成"""
        sid1 = self.generator._generate_sid()
        sid2 = self.generator._generate_sid()
        
        self.assertGreater(sid1, 0)
        self.assertGreater(sid2, 0)
        self.assertEqual(sid2, sid1 + 1)  # SID 应递增


class TestIDSRuleGeneratorEdgeCases(unittest.TestCase):
    """测试 IDS 规则生成器边界情况"""

    def setUp(self):
        """设置测试环境"""
        self.temp_dir = tempfile.mkdtemp()
        self.generator = IDSRuleGenerator(output_dir=self.temp_dir)

    def tearDown(self):
        """清理测试环境"""
        import shutil
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)

    def test_empty_binary_info(self):
        """测试空二进制信息"""
        rules = self.generator.generate_rules_for_vulnerability(
            binary_info={},
            vuln_info={"vulnerability_type": "buffer_overflow"}
        )
        self.assertEqual(len(rules), 0)

    def test_empty_vuln_info(self):
        """测试空漏洞信息"""
        rules = self.generator.generate_rules_for_vulnerability(
            binary_info={"imports": ["socket"]},
            vuln_info={}
        )
        self.assertEqual(len(rules), 0)

    def test_unknown_vulnerability_type(self):
        """测试未知漏洞类型"""
        binary_info = {
            "imports": ["socket", "bind"],
            "binary_name": "test"
        }
        
        vuln_info = {
            "vulnerability_type": "unknown_type",
            "trigger": "network_input"
        }
        
        rules = self.generator.generate_rules_for_vulnerability(
            binary_info=binary_info,
            vuln_info=vuln_info
        )
        
        # 应生成通用规则
        self.assertGreaterEqual(len(rules), 0)

    def test_long_cve_id(self):
        """测试长 CVE ID"""
        vuln_info = {
            "vulnerability_type": "buffer_overflow",
            "cve_id": "CVE-2024-THIS-IS-A-VERY-LONG-ID",
            "trigger": "network_input"
        }
        
        binary_info = {"imports": ["socket"]}
        
        rules = self.generator.generate_rules_for_vulnerability(
            binary_info=binary_info,
            vuln_info=vuln_info
        )
        
        # 应正确处理长 ID
        for rule in rules:
            self.assertIn("rule", rule)

    def test_special_characters_in_description(self):
        """测试描述中的特殊字符"""
        vuln_info = {
            "vulnerability_type": "buffer_overflow",
            "description": "Buffer overflow with special chars: \"; | \\n \\t",
            "trigger": "network_input"
        }
        
        binary_info = {"imports": ["socket"]}
        
        rules = self.generator.generate_rules_for_vulnerability(
            binary_info=binary_info,
            vuln_info=vuln_info
        )
        
        # 应正确处理特殊字符
        for rule in rules:
            self.assertIn("rule", rule)


if __name__ == '__main__':
    unittest.main()