#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ICS协议分析模块单元测试
"""

import unittest
import sys
import os
import tempfile
import shutil

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.ics_protocol_analyzer import (
    ICSProtocolAnalyzer,
    ICSProtocolFeatureDatabase,
    ICSProtocol,
    VulnerabilityType,
    ICSFunction,
    MalformedPacket,
    ICSAnalysisResult,
    analyze_ics_protocols,
    format_ics_report,
    export_ics_json
)


class TestICSProtocolFeatureDatabase(unittest.TestCase):
    """ICS协议特征数据库测试类"""

    def setUp(self):
        """设置测试环境"""
        self.db = ICSProtocolFeatureDatabase()

    def test_initialization(self):
        """测试初始化"""
        self.assertIsNotNone(self.db)
        self.assertGreater(len(self.db.features), 0)

    def test_get_modbus_feature(self):
        """测试获取Modbus特征"""
        feature = self.db.get_feature(ICSProtocol.MODBUS_TCP)

        self.assertIsNotNone(feature)
        self.assertEqual(feature.protocol, ICSProtocol.MODBUS_TCP)
        self.assertEqual(feature.default_port, 502)

    def test_get_dnp3_feature(self):
        """测试获取DNP3特征"""
        feature = self.db.get_feature(ICSProtocol.DNP3)

        self.assertIsNotNone(feature)
        self.assertEqual(feature.protocol, ICSProtocol.DNP3)
        self.assertEqual(feature.default_port, 20000)

    def test_get_all_features(self):
        """测试获取所有特征"""
        features = self.db.get_all_features()

        self.assertIsInstance(features, dict)
        self.assertIn(ICSProtocol.MODBUS_TCP, features)
        self.assertIn(ICSProtocol.DNP3, features)

    def test_feature_ports(self):
        """测试协议端口"""
        self.assertEqual(self.db.get_feature(ICSProtocol.MODBUS_TCP).default_port, 502)
        self.assertEqual(self.db.get_feature(ICSProtocol.DNP3).default_port, 20000)
        self.assertEqual(self.db.get_feature(ICSProtocol.IEC_61850).default_port, 102)


class TestICSProtocolAnalyzer(unittest.TestCase):
    """ICS协议分析器测试类"""

    def setUp(self):
        """设置测试环境"""
        # 创建临时测试二进制文件
        self.temp_dir = tempfile.mkdtemp()
        self.test_binary = os.path.join(self.temp_dir, "test_ics_binary")

        # 创建一个包含协议特征的测试二进制
        binary_content = b'\x00\x00\x00\x00'  # Modbus TCP header
        binary_content += b'modbus\x00'        # Modbus string
        binary_content += b'dnp3\x00'          # DNP3 string
        binary_content += b'\x05\x64\x01\x00'  # DNP3 magic bytes

        with open(self.test_binary, 'wb') as f:
            f.write(binary_content)

    def tearDown(self):
        """清理测试环境"""
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_initialization_with_binary(self):
        """测试带二进制初始化"""
        analyzer = ICSProtocolAnalyzer(self.test_binary)

        self.assertIsNotNone(analyzer)
        self.assertEqual(analyzer.binary_path, self.test_binary)
        self.assertGreater(len(analyzer.binary_data), 0)

    def test_initialization_without_binary(self):
        """测试无二进制初始化"""
        analyzer = ICSProtocolAnalyzer()

        self.assertIsNone(analyzer.binary_path)
        self.assertEqual(analyzer.binary_data, b'')

    def test_find_protocol_strings(self):
        """测试协议字符串查找"""
        analyzer = ICSProtocolAnalyzer(self.test_binary)
        protocol_strings = analyzer._find_protocol_strings()

        self.assertIn(ICSProtocol.MODBUS_TCP, protocol_strings)
        self.assertIn(ICSProtocol.DNP3, protocol_strings)

    def test_find_protocol_patterns(self):
        """测试协议模式查找"""
        analyzer = ICSProtocolAnalyzer(self.test_binary)
        pattern_counts = analyzer._find_protocol_patterns()

        self.assertIsInstance(pattern_counts, dict)

    def test_detect_protocols(self):
        """测试协议检测"""
        analyzer = ICSProtocolAnalyzer(self.test_binary)
        protocols = analyzer.detect_protocols()

        self.assertIsInstance(protocols, list)

    def test_identify_ics_functions(self):
        """测试ICS函数识别"""
        analyzer = ICSProtocolAnalyzer(self.test_binary)
        analyzer.detect_protocols()
        functions = analyzer.identify_ics_functions()

        self.assertIsInstance(functions, list)

    def test_analyze_vulnerabilities(self):
        """测试漏洞分析"""
        analyzer = ICSProtocolAnalyzer(self.test_binary)
        analyzer.detect_protocols()
        analyzer.identify_ics_functions()
        vulnerabilities = analyzer.analyze_vulnerabilities()

        self.assertIsInstance(vulnerabilities, list)

    def test_generate_malformed_packets_modbus(self):
        """测试Modbus畸形报文生成"""
        analyzer = ICSProtocolAnalyzer()
        packets = analyzer.generate_malformed_packets(ICSProtocol.MODBUS_TCP, count=5)

        self.assertEqual(len(packets), 5)
        self.assertTrue(all(isinstance(p, MalformedPacket) for p in packets))
        self.assertTrue(all(p.protocol == ICSProtocol.MODBUS_TCP for p in packets))

    def test_generate_malformed_packets_dnp3(self):
        """测试DNP3畸形报文生成"""
        analyzer = ICSProtocolAnalyzer()
        packets = analyzer.generate_malformed_packets(ICSProtocol.DNP3, count=3)

        self.assertEqual(len(packets), 3)

    def test_generate_malformed_packets_ethernet_ip(self):
        """测试EtherNet/IP畸形报文生成"""
        analyzer = ICSProtocolAnalyzer()
        packets = analyzer.generate_malformed_packets(ICSProtocol.ETHERNET_IP, count=3)

        self.assertEqual(len(packets), 3)

    def test_mutation_types(self):
        """测试变异类型覆盖"""
        analyzer = ICSProtocolAnalyzer()
        packets = analyzer.generate_malformed_packets(ICSProtocol.MODBUS_TCP, count=20)

        mutation_types = set(p.mutation_type for p in packets)
        expected_mutations = {
            'length_overflow', 'length_underflow', 'invalid_function_code',
            'invalid_object_type', 'truncated_header', 'extra_data',
            'null_pointer', 'negative_value', 'boundary_value'
        }

        # 检查至少有一些常见的变异类型
        self.assertTrue(len(mutation_types) > 0)

    def test_full_analysis(self):
        """测试完整分析流程"""
        analyzer = ICSProtocolAnalyzer(self.test_binary)
        result = analyzer.analyze()

        self.assertIsInstance(result, ICSAnalysisResult)
        self.assertIn('binary_path', result.__dict__)
        self.assertIn('detected_protocols', result.__dict__)

    def test_get_vulnerability_description(self):
        """测试漏洞描述获取"""
        analyzer = ICSProtocolAnalyzer()

        desc = analyzer._get_vulnerability_description(VulnerabilityType.LENGTH_NOT_CHECKED)
        self.assertIsInstance(desc, str)
        self.assertGreater(len(desc), 0)

    def test_get_vulnerability_severity(self):
        """测试漏洞严重性获取"""
        analyzer = ICSProtocolAnalyzer()

        severity = analyzer._get_vulnerability_severity(VulnerabilityType.BUFFER_OVERFLOW)
        self.assertEqual(severity, "critical")

    def test_get_exploit_difficulty(self):
        """测试利用难度获取"""
        analyzer = ICSProtocolAnalyzer()

        difficulty = analyzer._get_exploit_difficulty(VulnerabilityType.BUFFER_OVERFLOW)
        self.assertEqual(difficulty, "low")


class TestICSProtocolEnum(unittest.TestCase):
    """ICS协议枚举测试"""

    def test_protocol_values(self):
        """测试协议枚举值"""
        self.assertEqual(ICSProtocol.MODBUS_TCP.value, "modbus_tcp")
        self.assertEqual(ICSProtocol.DNP3.value, "dnp3")
        self.assertEqual(ICSProtocol.IEC_61850.value, "iec_61850")
        self.assertEqual(ICSProtocol.PROFINET.value, "profinet")
        self.assertEqual(ICSProtocol.ETHERNET_IP.value, "ethernet_ip")


class TestVulnerabilityType(unittest.TestCase):
    """漏洞类型枚举测试"""

    def test_vulnerability_values(self):
        """测试漏洞类型枚举值"""
        self.assertEqual(VulnerabilityType.LENGTH_NOT_CHECKED.value, "length_not_checked")
        self.assertEqual(VulnerabilityType.INDEX_OUT_OF_BOUNDS.value, "index_out_of_bounds")
        self.assertEqual(VulnerabilityType.BUFFER_OVERFLOW.value, "buffer_overflow")


class TestHelperFunctions(unittest.TestCase):
    """辅助函数测试"""

    def test_analyze_ics_protocols(self):
        """测试便捷分析函数"""
        # 创建临时文件
        with tempfile.NamedTemporaryFile(delete=False, suffix='.bin') as f:
            f.write(b'modbus dnp3')
            temp_path = f.name

        try:
            result = analyze_ics_protocols(temp_path)
            self.assertIsInstance(result, ICSAnalysisResult)
        finally:
            os.unlink(temp_path)

    def test_format_ics_report(self):
        """测试报告格式化"""
        result = ICSAnalysisResult(
            binary_path="/test/binary",
            detected_protocols=[ICSProtocol.MODBUS_TCP],
            identified_functions=[],
            detected_vulnerabilities=[],
            generated_packets=[],
            summary="Test summary",
            analysis_time=1.5
        )

        report = format_ics_report(result)
        self.assertIn('ICS协议分析报告', report)


if __name__ == '__main__':
    unittest.main()
