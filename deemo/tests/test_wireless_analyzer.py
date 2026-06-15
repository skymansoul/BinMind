import unittest
import os
import sys
import importlib.util

def load_module(module_name, file_name):
    module_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "modules", file_name)
    spec = importlib.util.spec_from_file_location(module_name, module_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

wireless_analyzer = load_module("wireless_analyzer", "wireless_analyzer.py")
WirelessProtocolAnalyzer = wireless_analyzer.WirelessProtocolAnalyzer

class TestWirelessProtocolAnalyzer(unittest.TestCase):
    """无线协议栈分析器测试"""
    
    def setUp(self):
        """测试前准备"""
        self.analyzer = WirelessProtocolAnalyzer()
    
    def test_initialization(self):
        """测试初始化"""
        self.assertIsNotNone(self.analyzer)
        self.assertEqual(self.analyzer.firmware_path, None)
        self.assertEqual(self.analyzer.protocol_functions, [])
        self.assertEqual(self.analyzer.vulnerabilities, [])
        self.assertEqual(self.analyzer.fuzz_cases, [])
    
    def test_infer_bluetooth_layer(self):
        """测试推断蓝牙协议层"""
        self.assertEqual(self.analyzer._infer_bluetooth_layer('hci_recv'), 'HCI')
        self.assertEqual(self.analyzer._infer_bluetooth_layer('l2cap_process'), 'L2CAP')
        self.assertEqual(self.analyzer._infer_bluetooth_layer('sdp_search'), 'SDP')
        self.assertEqual(self.analyzer._infer_bluetooth_layer('rfcomm_connect'), 'RFCOMM')
        self.assertEqual(self.analyzer._infer_bluetooth_layer('smp_pair'), 'SMP')
        self.assertEqual(self.analyzer._infer_bluetooth_layer('unknown_func'), 'unknown')
    
    def test_infer_wifi_layer(self):
        """测试推断Wi-Fi协议层"""
        self.assertEqual(self.analyzer._infer_wifi_layer('ieee80211_rx'), 'MAC')
        self.assertEqual(self.analyzer._infer_wifi_layer('mac80211_process'), 'MAC')
        self.assertEqual(self.analyzer._infer_wifi_layer('wlan_scan'), 'management')
        self.assertEqual(self.analyzer._infer_wifi_layer('cfg80211_connect'), 'management')
        self.assertEqual(self.analyzer._infer_wifi_layer('wpa_handshake'), 'security')
        self.assertEqual(self.analyzer._infer_wifi_layer('eapol_process'), 'security')
        self.assertEqual(self.analyzer._infer_wifi_layer('hostap_start'), 'AP')
        self.assertEqual(self.analyzer._infer_wifi_layer('unknown_func'), 'unknown')
    
    def test_parse_frame_logic(self):
        """测试解析帧处理逻辑"""
        pseudocode_with_checks = """
            if (length > MAX_LEN) return -1;
            strncpy(buffer, data, length);
        """
        analysis = self.analyzer._parse_frame_logic(pseudocode_with_checks)
        
        self.assertTrue(analysis['has_length_check'])
        self.assertEqual(analysis['unsafe_operations'], [])
        
        pseudocode_unsafe = """
            strcpy(buffer, data);
            sprintf(buf, "%s", input);
        """
        analysis2 = self.analyzer._parse_frame_logic(pseudocode_unsafe)
        
        self.assertFalse(analysis2['has_length_check'])
        self.assertIn('无长度限制的strcpy', analysis2['unsafe_operations'])
        self.assertIn('无长度限制的sprintf', analysis2['unsafe_operations'])
    
    def test_calculate_risk_level(self):
        """测试计算风险等级"""
        self.analyzer.vulnerabilities = []
        self.assertEqual(self.analyzer._calculate_risk_level(), 'none')
        
        self.analyzer.vulnerabilities = [{'severity': 'low'}]
        self.assertEqual(self.analyzer._calculate_risk_level(), 'low')
        
        self.analyzer.vulnerabilities = [{'severity': 'medium'}, {'severity': 'medium'}, {'severity': 'medium'}]
        self.assertEqual(self.analyzer._calculate_risk_level(), 'medium')
        
        self.analyzer.vulnerabilities = [{'severity': 'high'}]
        self.assertEqual(self.analyzer._calculate_risk_level(), 'medium')
        
        self.analyzer.vulnerabilities = [{'severity': 'high'}, {'severity': 'high'}]
        self.assertEqual(self.analyzer._calculate_risk_level(), 'high')
    
    def test_generate_bluetooth_fuzz_cases(self):
        """测试生成蓝牙模糊测试用例"""
        cases = self.analyzer._generate_bluetooth_fuzz_cases()
        
        self.assertIsInstance(cases, list)
        self.assertGreaterEqual(len(cases), 1)
        
        for case in cases:
            self.assertIn('protocol', case)
            self.assertEqual(case['protocol'], 'bluetooth')
            self.assertIn('layer', case)
            self.assertIn('name', case)
            self.assertIn('description', case)
            self.assertIn('target_function', case)
    
    def test_generate_wifi_fuzz_cases(self):
        """测试生成Wi-Fi模糊测试用例"""
        cases = self.analyzer._generate_wifi_fuzz_cases()
        
        self.assertIsInstance(cases, list)
        self.assertGreaterEqual(len(cases), 1)
        
        for case in cases:
            self.assertIn('protocol', case)
            self.assertEqual(case['protocol'], 'wifi')
            self.assertIn('layer', case)
            self.assertIn('name', case)
            self.assertIn('description', case)
            self.assertIn('target_function', case)
    
    def test_analyze(self):
        """测试分析方法"""
        analyzer = WirelessProtocolAnalyzer('/tmp/nonexistent_firmware')
        result = analyzer.analyze()
        
        self.assertIsInstance(result, dict)
        self.assertIn('protocol_functions', result)
        self.assertIn('vulnerabilities', result)
        self.assertIn('fuzz_cases', result)
        self.assertIn('risk_level', result)
        
        self.assertGreaterEqual(len(result['fuzz_cases']), 1)

if __name__ == '__main__':
    unittest.main()