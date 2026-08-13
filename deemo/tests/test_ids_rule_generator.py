# Derive IDS rules from vulnerability info, the idea came from an internal company project
import os
import shutil
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch


from modules.ids_rule_generator import (
    AttackSignature,
    IDSRuleContent,
    IDSRuleGenerator,
    NetworkFunctionInfo,
    generate_ids_rules,
)


class TestIDSRuleContent(unittest.TestCase):
    """IDS rule content -- default value checks"""

    def setUp(self):
        pass

    def test_init(self):
        rule = IDSRuleContent()
        if rule is None:
            self.fail("IDSRuleContent is None")
        self.assertEqual(rule.action, "alert")
        self.assertEqual(rule.protocol, "tcp")
        self.assertEqual(rule.source_ip, "$EXTERNAL_NET")
        self.assertEqual(rule.dest_ip, "$HOME_NET")
        self.assertEqual(rule.dest_port, "$SERVICE_PORTS")
        self.assertEqual(rule.sid, 0)
        self.assertEqual(rule.classtype, "attempted-admin")

    def test_custom_values(self):
        """drop UDP 10.0.0.1 -> 192.168.1.1:8080"""
        rule = IDSRuleContent(
            action="drop",
            protocol="udp",
            source_ip="10.0.0.1",
            dest_ip="192.168.1.1",
            dest_port="8080",
            msg="Test rule",
            sid=1000001,
            classtype="attempted-recon",
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
    """Attack signature -- pattern + offset + signature_type"""

    def test_init(self):
        sig = AttackSignature(
            signature_type="buffer_overflow",
            pattern=b"AAAA" * 100,
            offset=0,
            description="Buffer overflow payload",
        )
        self.assertEqual(sig.signature_type, "buffer_overflow")
        self.assertEqual(sig.pattern, b"AAAA" * 100)
        self.assertEqual(sig.offset, 0)
        self.assertEqual(sig.description, "Buffer overflow payload")

    def test_to_content_dict(self):
        sig = AttackSignature(
            signature_type="pattern",
            pattern=b"\\x41\\x42\\x43",
            offset=10,
            description="Test pattern",
        )
        content_dict = sig.to_content_dict()
        self.assertIn("content", content_dict)
        self.assertIn("offset", content_dict)
        self.assertEqual(content_dict["offset"], 10)


class TestNetworkFunctionInfo(unittest.TestCase):
    def test_init(self):
        info = NetworkFunctionInfo(
            function_name="socket",
            category="socket_creation",
            is_server=True,
            is_client=False,
        )
        self.assertEqual(info.function_name, "socket")
        self.assertEqual(info.category, "socket_creation")
        self.assertTrue(info.is_server)
        self.assertFalse(info.is_client)


class TestIDSRuleGenerator(unittest.TestCase):
    """IDS rule generator -- core functionality"""

    def setUp(self):
        self.m_tmpdir = tempfile.mkdtemp()
        self.m_generator = IDSRuleGenerator(output_dir=self.m_tmpdir)

    def tearDown(self):
        if os.path.exists(self.m_tmpdir):
            shutil.rmtree(self.m_tmpdir)

    def test_init(self):
        self.assertIsNotNone(self.m_generator.output_dir)
        self.assertEqual(self.m_generator.format, "suricata")
        self.assertEqual(self.m_generator.base_sid, 1000000)
        self.assertIn("socket", self.m_generator.network_functions)

    def test_is_network_service_with_network_functions(self):
        """Has socket/bind/listen -> is network service"""
        binary_info = {
            "imports": ["socket", "bind", "listen", "accept", "recv", "send"]
        }
        result = self.m_generator.is_network_service(binary_info)
        self.assertTrue(result)

    def test_is_network_service_without_network_functions(self):
        """Only printf/malloc -> not a network service"""
        binary_info = {"imports": ["printf", "malloc", "free", "strcpy"]}
        result = self.m_generator.is_network_service(binary_info)
        self.assertFalse(result)

    def test_is_network_service_with_firmware_info(self):
        """firmware_info[device_type]=router -> network device -> yes"""
        binary_info = {"imports": [], "firmware_info": {"device_type": "router"}}
        result = self.m_generator.is_network_service(binary_info)
        self.assertTrue(result)

    def test_is_network_service_with_protocol_info(self):
        """protocol_info contains HTTP, FTP -> is network service"""
        binary_info = {"imports": [], "protocol_info": {"protocols": ["HTTP", "FTP"]}}
        result = self.m_generator.is_network_service(binary_info)
        self.assertTrue(result)

    def test_is_remote_triggerable_buffer_overflow(self):
        """network_input trigger -> remote triggerable"""
        vuln_info = {
            "vulnerability_type": "buffer_overflow",
            "trigger": "network_input",
            "location": "handle_client_request",
        }
        result = self.m_generator.is_remote_triggerable(vuln_info)
        self.assertTrue(result)

    def test_is_remote_triggerable_command_injection(self):
        vuln_info = {"vulnerability_type": "command_injection", "trigger": "user_input"}
        result = self.m_generator.is_remote_triggerable(vuln_info)
        self.assertTrue(result)

    def test_is_remote_triggerable_local_vulnerability(self):
        """local_file trigger -> not remote triggerable"""
        vuln_info = {"vulnerability_type": "buffer_overflow", "trigger": "local_file"}
        result = self.m_generator.is_remote_triggerable(vuln_info)
        self.assertFalse(result)

    def test_extract_attack_signature_from_crash(self):
        """Extract signature from crash data -- A*200 + BBBB + CCCCCCCC"""
        crash_data = {
            "crash_type": "buffer_overflow",
            "crashing_input": b"A" * 200 + b"BBBB" + b"CCCCCCCC",
            "registers": {"eip": "0x42424242"},
            "stack_trace": ["0x42424242", "0x43434343"],
        }
        sigs = self.m_generator.extract_attack_signature(
            crash_data=crash_data, vuln_type="buffer_overflow"
        )
        self.assertIsInstance(sigs, list)
        self.assertGreater(len(sigs), 0)
        has_overflow = any(s.signature_type == "buffer_overflow" for s in sigs)
        self.assertTrue(has_overflow)

    def test_extract_attack_signature_from_symbolic(self):
        """Constraints -> buffer_size=256, offset=260"""
        symbolic = {
            "constraints": [
                {"type": "buffer_size", "value": 256},
                {"type": "offset", "value": 260},
            ],
            "input_pattern": {"data": b"GET /" + b"A" * 256 + b"XXXX", "offset": 0},
            "trigger_condition": "input_length > 256",
        }
        sigs = self.m_generator.extract_attack_signature(
            symbolic_result=symbolic, vuln_type="buffer_overflow"
        )
        self.assertIsInstance(sigs, list)
        self.assertGreater(len(sigs), 0)

    def test_extract_attack_signature_with_protocol(self):
        """protocol_info -> magic_bytes + field definitions -> signature"""
        proto = {
            "fields": [
                {"name": "command", "offset": 0, "size": 4, "type": "string"},
                {"name": "length", "offset": 4, "size": 4, "type": "uint32"},
                {"name": "data", "offset": 8, "type": "variable"},
            ],
            "magic_bytes": b"CMD\x00",
        }
        sigs = self.m_generator.extract_attack_signature(
            protocol_info=proto, vuln_type="buffer_overflow"
        )
        self.assertIsInstance(sigs, list)
        has_magic = any(s.signature_type == "protocol_magic" for s in sigs)
        self.assertTrue(has_magic)

    def test_generate_rule_suricata(self):
        """Generate Suricata rule -- alert tcp ..."""
        rule_content = IDSRuleContent(
            action="alert",
            protocol="tcp",
            source_ip="$EXTERNAL_NET",
            source_port="any",
            dest_ip="$HOME_NET",
            dest_port="$HTTP_PORTS",
            msg="CVE-2026-1234 Buffer overflow in HTTP server",
            sid=1000001,
            classtype="attempted-admin",
            reference="cve,CVE-2026-1234",
        )
        rule_content.content_matches = [
            {"content": "GET /", "offset": 0, "depth": 4},
            {"content": "|41 41 41 41|", "offset": 100},
        ]
        rule_str = self.m_generator.generate_rule(rule_content, format="suricata")
        self.assertIsInstance(rule_str, str)
        self.assertIn("alert tcp", rule_str)
        self.assertIn("$EXTERNAL_NET", rule_str)
        self.assertIn("$HOME_NET", rule_str)
        self.assertIn("msg:", rule_str)
        self.assertIn("sid:1000001", rule_str)
        self.assertIn("classtype:attempted-admin", rule_str)
        self.assertIn("content:", rule_str)

    def test_generate_rule_snort(self):
        """Generate Snort rule"""
        rule_content = IDSRuleContent(
            action="alert",
            protocol="tcp",
            source_ip="$EXTERNAL_NET",
            source_port="any",
            dest_ip="$HOME_NET",
            dest_port="80",
            msg="Test Snort rule",
            sid=1000002,
            classtype="attempted-recon",
        )
        rule_str = self.m_generator.generate_rule(rule_content, format="snort")
        self.assertIsInstance(rule_str, str)
        self.assertIn("alert tcp", rule_str)
        self.assertIn("sid:1000002", rule_str)

    def test_validate_rule_syntax_valid(self):
        valid = 'alert tcp $EXTERNAL_NET any -> $HOME_NET 80 (msg:"Test rule"; sid:1000001; classtype:attempted-admin;)'
        result = self.m_generator.validate_rule_syntax(valid)
        self.assertTrue(result)

    def test_validate_rule_syntax_invalid(self):
        """Missing closing paren -> invalid"""
        invalid = 'alert tcp any -> any (msg:"Invalid rule"'
        result = self.m_generator.validate_rule_syntax(invalid)
        self.assertFalse(result)

    def test_generate_rules_for_vulnerability(self):
        """socket+bind+listen + buffer_overflow network_input -> rules"""
        binfo = {"imports": ["socket", "bind", "listen", "accept"], "binary_name": "test_server"}
        vinfo = {
            "vulnerability_type": "buffer_overflow",
            "trigger": "network_input",
            "cve_id": "CVE-2026-1234",
            "description": "Buffer overflow in HTTP request handling",
            "location": "handle_http_request",
            "crash_data": {"crash_type": "buffer_overflow", "crashing_input": b"A" * 500},
        }
        rules = self.m_generator.generate_rules_for_vulnerability(
            binary_info=binfo, vuln_info=vinfo
        )
        self.assertIsInstance(rules, list)
        self.assertGreater(len(rules), 0)
        for j in range(len(rules)):
            self.assertIn("rule", rules[j])
            self.assertIn("sid", rules[j])
            self.assertIn("vulnerability_type", rules[j])

    def test_generate_rules_for_non_network_binary(self):
        """printf+malloc non-network binary -> no rules generated"""
        binfo = {"imports": ["printf", "malloc"], "binary_name": "test_local"}
        vinfo = {"vulnerability_type": "buffer_overflow", "trigger": "local_file"}
        rules = self.m_generator.generate_rules_for_vulnerability(
            binary_info=binfo, vuln_info=vinfo
        )
        self.assertEqual(len(rules), 0)

    def test_save_rules_to_file(self):
        rules = [
            {
                "rule": 'alert tcp $EXTERNAL_NET any -> $HOME_NET 80 (msg:"Test rule 1"; sid:1000001;)',
                "sid": 1000001,
                "vulnerability_type": "buffer_overflow",
            },
            {
                "rule": 'alert tcp $EXTERNAL_NET any -> $HOME_NET 21 (msg:"Test rule 2"; sid:1000002;)',
                "sid": 1000002,
                "vulnerability_type": "command_injection",
            },
        ]
        output_path = self.m_generator.save_rules_to_file(
            rules=rules, binary_name="test_server", format="suricata"
        )
        self.assertTrue(os.path.exists(output_path))
        with open(output_path, "r", encoding="utf-8") as k:
            content = k.read()
            self.assertIn("alert tcp", content)
            self.assertIn("sid:1000001", content)
            self.assertIn("sid:1000002", content)

    def test_generate_generic_rule(self):
        vinfo = {
            "vulnerability_type": "buffer_overflow",
            "cve_id": "CVE-2026-5678",
            "description": "Generic buffer overflow",
        }
        rule = self.m_generator._generate_generic_rule(vinfo)
        self.assertIsNotNone(rule)
        self.assertIn("alert tcp", rule.rule)
        self.assertIn("CVE-2026-5678", rule.msg)
        self.assertIn("Manual review required", rule.msg)

    def test_generate_ids_rules_convenience_function(self):
        """generate_ids_rules -- convenience function"""
        binfo = {"imports": ["socket", "bind", "listen"], "binary_name": "test_app"}
        vulns = [
            {
                "vulnerability_type": "buffer_overflow",
                "trigger": "network_input",
                "cve_id": "CVE-2026-9999",
            }
        ]
        result = generate_ids_rules(
            binary_info=binfo, vulns_info=vulns, output_dir=self.m_tmpdir
        )
        self.assertIn("rules", result)
        self.assertIn("output_file", result)
        self.assertIn("total_rules", result)

    def test_determine_port_from_protocol(self):
        protocol_info = {"protocol_name": "HTTP", "default_port": 80}
        port = self.m_generator._determine_port(protocol_info)
        self.assertEqual(port, "80")

    def test_determine_port_from_vuln_info(self):
        vuln_info = {"network_service": {"port": 8080, "protocol": "TCP"}}
        port = self.m_generator._determine_port(None, vuln_info)
        self.assertEqual(port, "8080")

    def test_determine_port_default(self):
        port = self.m_generator._determine_port(None, None)
        self.assertEqual(port, "$SERVICE_PORTS")

    def test_extract_content_from_input(self):
        """HTTP request -> extract content rules"""
        input_data = b"GET /path HTTP/1.1\r\nHost: example.com\r\n\r\n"
        content = self.m_generator._extract_content_from_input(input_data)
        self.assertIsInstance(content, list)
        self.assertGreater(len(content), 0)
        has_get = any("GET" in str(c) for c in content)
        self.assertTrue(has_get)

    def test_sid_generation(self):
        """SID increments -- starts at 1000000"""
        sid1 = self.m_generator._generate_sid()
        sid2 = self.m_generator._generate_sid()
        self.assertGreater(sid1, 0)
        self.assertGreater(sid2, 0)
        self.assertEqual(sid2, sid1 + 1)


class TestIDSRuleGeneratorEdgeCases(unittest.TestCase):
    """Edge cases -- empty info, long CVE, special chars"""

    def setUp(self):
        self.m_tmpdir = tempfile.mkdtemp()
        self.m_generator = IDSRuleGenerator(output_dir=self.m_tmpdir)

    def tearDown(self):
        if os.path.exists(self.m_tmpdir):
            shutil.rmtree(self.m_tmpdir)

    def test_empty_binary_info(self):
        rules = self.m_generator.generate_rules_for_vulnerability(
            binary_info={}, vuln_info={"vulnerability_type": "buffer_overflow"}
        )
        self.assertEqual(len(rules), 0)

    def test_empty_vuln_info(self):
        rules = self.m_generator.generate_rules_for_vulnerability(
            binary_info={"imports": ["socket"]}, vuln_info={}
        )
        self.assertEqual(len(rules), 0)

    def test_unknown_vulnerability_type(self):
        """unknown_type -> generate generic rule"""
        binfo = {"imports": ["socket", "bind"], "binary_name": "test"}
        vinfo = {"vulnerability_type": "unknown_type", "trigger": "network_input"}
        rules = self.m_generator.generate_rules_for_vulnerability(
            binary_info=binfo, vuln_info=vinfo
        )
        self.assertGreaterEqual(len(rules), 0)

    def test_long_cve_id(self):
        vinfo = {
            "vulnerability_type": "buffer_overflow",
            "cve_id": "CVE-2026-THIS-IS-A-VERY-LONG-ID",
            "trigger": "network_input",
        }
        binfo = {"imports": ["socket"]}
        rules = self.m_generator.generate_rules_for_vulnerability(
            binary_info=binfo, vuln_info=vinfo
        )
        for j in range(len(rules)):
            self.assertIn("rule", rules[j])

    def test_special_characters_in_description(self):
        """Description with semicolons, pipes, newlines -- should handle"""
        vinfo = {
            "vulnerability_type": "buffer_overflow",
            "description": 'Buffer overflow with special chars: "; | \\n \\t',
            "trigger": "network_input",
        }
        binfo = {"imports": ["socket"]}
        rules = self.m_generator.generate_rules_for_vulnerability(
            binary_info=binfo, vuln_info=vinfo
        )
        for j in range(len(rules)):
            self.assertIn("rule", rules[j])


if __name__ == "__main__":
    unittest.main()
