#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Modbus TCP/DNP3/IEC 61850/PROFINET/EtherNet/IP -- Industrie 4.0 nightmare fuel
import os
import shutil
import sys
import tempfile
import unittest


from modules.ics_protocol_analyzer import (
    ICSAnalysisResult,
    ICSFunction,
    ICSProtocol,
    ICSProtocolAnalyzer,
    ICSProtocolFeatureDatabase,
    MalformedPacket,
    VulnerabilityType,
    analyze_ics_protocols,
    export_ics_json,
    format_ics_report,
)


class TestICSProtocolFeatureDatabase(unittest.TestCase):
    """ICS protocol feature database -- Modbus/DNP3/IEC61850"""

    def setUp(self):
        self.m_db = ICSProtocolFeatureDatabase()

    def test_initialization(self):
        self.assertIsNotNone(self.m_db)
        self.assertGreater(len(self.m_db.features), 0)

    def test_get_modbus_feature(self):
        """Modbus -> port 502"""
        feature = self.m_db.get_feature(ICSProtocol.MODBUS_TCP)
        if feature is None:
            self.fail("Modbus feature is None")
        self.assertIsNotNone(feature)
        self.assertEqual(feature.protocol, ICSProtocol.MODBUS_TCP)
        self.assertEqual(feature.default_port, 502)

    def test_get_dnp3_feature(self):
        """DNP3 -> port 20000"""
        feature = self.m_db.get_feature(ICSProtocol.DNP3)
        self.assertIsNotNone(feature)
        self.assertEqual(feature.protocol, ICSProtocol.DNP3)
        self.assertEqual(feature.default_port, 20000)

    def test_get_all_features(self):
        features = self.m_db.get_all_features()
        self.assertIsInstance(features, dict)
        self.assertIn(ICSProtocol.MODBUS_TCP, features)
        self.assertIn(ICSProtocol.DNP3, features)

    def test_feature_ports(self):
        """Default ports: Modbus=502, DNP3=20000, IEC_61850=102"""
        self.assertEqual(
            self.m_db.get_feature(ICSProtocol.MODBUS_TCP).default_port, 502
        )
        self.assertEqual(self.m_db.get_feature(ICSProtocol.DNP3).default_port, 20000)
        self.assertEqual(self.m_db.get_feature(ICSProtocol.IEC_61850).default_port, 102)


class TestICSProtocolAnalyzer(unittest.TestCase):
    """ICS protocol analyzer -- detect + identify + vuln analysis + malformed packets"""

    def setUp(self):
        self.m_tmpdir = tempfile.mkdtemp()
        self.m_binpath = os.path.join(self.m_tmpdir, "test_ics_binary")
        binary = b"\x00\x00\x00\x00" + b"modbus\x00" + b"dnp3\x00" + b"\x05\x64\x01\x00"
        with open(self.m_binpath, "wb") as j:
            j.write(binary)

    def tearDown(self):
        shutil.rmtree(self.m_tmpdir, ignore_errors=True)

    def test_initialization_with_binary(self):
        analyzer = ICSProtocolAnalyzer(self.m_binpath)
        self.assertIsNotNone(analyzer)
        self.assertEqual(analyzer.binary_path, self.m_binpath)
        self.assertGreater(len(analyzer.binary_data), 0)

    def test_initialization_without_binary(self):
        analyzer = ICSProtocolAnalyzer()
        self.assertIsNone(analyzer.binary_path)
        self.assertEqual(analyzer.binary_data, b"")

    def test_find_protocol_strings(self):
        analyzer = ICSProtocolAnalyzer(self.m_binpath)
        protocol_strings = analyzer._find_protocol_strings()
        self.assertIn(ICSProtocol.MODBUS_TCP, protocol_strings)
        self.assertIn(ICSProtocol.DNP3, protocol_strings)

    def test_find_protocol_patterns(self):
        analyzer = ICSProtocolAnalyzer(self.m_binpath)
        pattern_counts = analyzer._find_protocol_patterns()
        self.assertIsInstance(pattern_counts, dict)

    def test_detect_protocols(self):
        analyzer = ICSProtocolAnalyzer(self.m_binpath)
        protocols = analyzer.detect_protocols()
        self.assertIsInstance(protocols, list)

    def test_identify_ics_functions(self):
        analyzer = ICSProtocolAnalyzer(self.m_binpath)
        analyzer.detect_protocols()
        functions = analyzer.identify_ics_functions()
        self.assertIsInstance(functions, list)

    def test_analyze_vulnerabilities(self):
        analyzer = ICSProtocolAnalyzer(self.m_binpath)
        analyzer.detect_protocols()
        analyzer.identify_ics_functions()
        vulns = analyzer.analyze_vulnerabilities()
        self.assertIsInstance(vulns, list)

    def test_generate_malformed_packets_modbus(self):
        analyzer = ICSProtocolAnalyzer()
        packets = analyzer.generate_malformed_packets(ICSProtocol.MODBUS_TCP, count=5)
        self.assertEqual(len(packets), 5)
        self.assertTrue(all(isinstance(p, MalformedPacket) for p in packets))
        self.assertTrue(all(p.protocol == ICSProtocol.MODBUS_TCP for p in packets))

    def test_generate_malformed_packets_dnp3(self):
        analyzer = ICSProtocolAnalyzer()
        packets = analyzer.generate_malformed_packets(ICSProtocol.DNP3, count=3)
        self.assertEqual(len(packets), 3)

    def test_generate_malformed_packets_ethernet_ip(self):
        analyzer = ICSProtocolAnalyzer()
        packets = analyzer.generate_malformed_packets(ICSProtocol.ETHERNET_IP, count=3)
        self.assertEqual(len(packets), 3)

    def test_mutation_types(self):
        """Make sure poison packets cover common mutation types"""
        analyzer = ICSProtocolAnalyzer()
        packets = analyzer.generate_malformed_packets(ICSProtocol.MODBUS_TCP, count=20)
        mutation_types = set(p.mutation_type for p in packets)
        self.assertTrue(len(mutation_types) > 0)

    def test_full_analysis(self):
        analyzer = ICSProtocolAnalyzer(self.m_binpath)
        result = analyzer.analyze()
        self.assertIsInstance(result, ICSAnalysisResult)
        self.assertIn("binary_path", result.__dict__)
        self.assertIn("detected_protocols", result.__dict__)

    def test_get_vulnerability_description(self):
        analyzer = ICSProtocolAnalyzer()
        desc = analyzer._get_vulnerability_description(VulnerabilityType.LENGTH_NOT_CHECKED)
        self.assertIsInstance(desc, str)
        self.assertGreater(len(desc), 0)

    def test_get_vulnerability_severity(self):
        analyzer = ICSProtocolAnalyzer()
        severity = analyzer._get_vulnerability_severity(VulnerabilityType.BUFFER_OVERFLOW)
        self.assertEqual(severity, "critical")

    def test_get_exploit_difficulty(self):
        analyzer = ICSProtocolAnalyzer()
        difficulty = analyzer._get_exploit_difficulty(VulnerabilityType.BUFFER_OVERFLOW)
        self.assertEqual(difficulty, "low")


class TestICSProtocolEnum(unittest.TestCase):
    """ICS protocol enum values"""

    def setUp(self):
        pass

    def test_protocol_values(self):
        self.assertEqual(ICSProtocol.MODBUS_TCP.value, "modbus_tcp")
        self.assertEqual(ICSProtocol.DNP3.value, "dnp3")
        self.assertEqual(ICSProtocol.IEC_61850.value, "iec_61850")
        self.assertEqual(ICSProtocol.PROFINET.value, "profinet")
        self.assertEqual(ICSProtocol.ETHERNET_IP.value, "ethernet_ip")


class TestVulnerabilityType(unittest.TestCase):
    """Vulnerability type enum -- length/index/buffer overflow"""

    def test_vulnerability_values(self):
        self.assertEqual(VulnerabilityType.LENGTH_NOT_CHECKED.value, "length_not_checked")
        self.assertEqual(VulnerabilityType.INDEX_OUT_OF_BOUNDS.value, "index_out_of_bounds")
        self.assertEqual(VulnerabilityType.BUFFER_OVERFLOW.value, "buffer_overflow")


class TestHelperFunctions(unittest.TestCase):
    """Helper functions -- analyze_ics_protocols + format_ics_report"""

    def test_analyze_ics_protocols(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as k:
            k.write(b"modbus dnp3")
            temp_path = k.name
        try:
            result = analyze_ics_protocols(temp_path)
            self.assertIsInstance(result, ICSAnalysisResult)
        finally:
            os.unlink(temp_path)

    def test_format_ics_report(self):
        result = ICSAnalysisResult(
            binary_path="/test/binary",
            detected_protocols=[ICSProtocol.MODBUS_TCP],
            identified_functions=[],
            detected_vulnerabilities=[],
            generated_packets=[],
            summary="Test summary",
            analysis_time=1.5,
        )
        report = format_ics_report(result)
        self.assertIn("ICSprotocolanalysis report", report)


if __name__ == "__main__":
    unittest.main()
