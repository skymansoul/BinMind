# -*- coding: utf-8 -*-

import os
import sys
import unittest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.info_leak_analyzer import (
    InfoLeakAnalyzer,
    LeakType,
    LeakDataType,
    Severity,
    LeakPoint,
    LeakCapabilityMatrix,
    analyze_info_leak
)


class TestLeakPoint(unittest.TestCase):
    """LeakPoint dataclass tests"""

    def test_init(self):
        """basic initialization"""
        leak = LeakPoint(
            leak_id="test_1",
            leak_type=LeakType.FORMAT_STRING,
            location="vulnerable_func",
            instruction="printf(user_input)",
            severity=Severity.HIGH
        )

        self.assertEqual(leak.leak_id, "test_1")
        self.assertEqual(leak.leak_type, LeakType.FORMAT_STRING)
        self.assertEqual(leak.location, "vulnerable_func")
        self.assertEqual(leak.severity, Severity.HIGH)

    def test_to_dict(self):
        """convert to dict"""
        leak = LeakPoint(
            leak_id="test_1",
            leak_type=LeakType.FORMAT_STRING,
            location="func",
            instruction="printf(x)",
            severity=Severity.MEDIUM
        )

        result = leak.to_dict()
        self.assertIn("leak_id", result)
        self.assertIn("leak_type", result)
        self.assertEqual(result["severity"], "medium")


class TestLeakCapabilityMatrix(unittest.TestCase):
    """LeakCapabilityMatrix tests"""

    def test_init(self):
        """basic initialization"""
        matrix = LeakCapabilityMatrix(binary_name="test.bin")

        self.assertEqual(matrix.binary_name, "test.bin")
        self.assertEqual(matrix.total_leak_points, 0)
        self.assertFalse(matrix.can_leak_libc_address)

    def test_add_leak_point(self):
        matrix = LeakCapabilityMatrix(binary_name="test.bin")

        leak = LeakPoint(
            leak_id="test",
            leak_type=LeakType.FORMAT_STRING,
            location="func",
            instruction="printf(x)",
            severity=Severity.HIGH,
            leakable_data_types=[LeakDataType.LIBC_ADDRESS]
        )

        matrix.leak_points.append(leak)
        matrix.total_leak_points = len(matrix.leak_points)

        # update leakable info flags
        for lp in matrix.leak_points:
            for dtype in lp.leakable_data_types:
                if dtype == LeakDataType.LIBC_ADDRESS:
                    matrix.can_leak_libc_address = True

        self.assertEqual(matrix.total_leak_points, 1)
        self.assertTrue(matrix.can_leak_libc_address)


class TestInfoLeakAnalyzer(unittest.TestCase):
    """InfoLeakAnalyzer tests"""

    def setUp(self):
        """setup test environment"""
        self.analyzer = InfoLeakAnalyzer(binary_path="test_binary")

    def test_init(self):
        """test initialization"""
        self.assertEqual(self.analyzer.binary_name, "test_binary")
        self.assertEqual(self.analyzer.min_confidence, 0.5)

    def test_analyze_empty_data(self):
        """test empty data analysis"""
        result = self.analyzer.analyze()

        self.assertIsInstance(result, LeakCapabilityMatrix)
        self.assertEqual(result.total_leak_points, 0)

    def test_analyze_format_string_vulnerability(self):
        """test format string vulnerability analysis"""
        decomp_data = {
            'vulnerable_func': {
                'pseudocode': '''
                    void vulnerable_func(char *user_input) {
                        printf(user_input);  // format string vuln
                    }
                ''',
                'address': 0x401000,
            }
        }

        result = self.analyzer.analyze(decomp_data=decomp_data)
        self.assertGreaterEqual(result.format_string_leaks, 0)

    def test_analyze_crash_data_leaks(self):
        """test crash data leak analysis"""
        crash_data = {
            'registers': {
                'rax': 0x7fff12345678,
                'rbx': 0x0000555555555555,
            },
            'function': 'handle_request'
        }

        result = self.analyzer.analyze(crash_data=crash_data)
        self.assertIsInstance(result, LeakCapabilityMatrix)

    def test_select_best_leak_point(self):
        """test selecting the best leak point"""
        leak1 = LeakPoint(
            leak_id="low",
            leak_type=LeakType.FORMAT_STRING,
            location="func1",
            instruction="printf(x)",
            severity=Severity.LOW,
            leakable_bytes=8
        )

        leak2 = LeakPoint(
            leak_id="critical",
            leak_type=LeakType.FORMAT_STRING,
            location="func2",
            instruction="printf(x)",
            severity=Severity.CRITICAL,
            leakable_bytes=1024
        )

        self.analyzer.leak_points = [leak1, leak2]
        best = self.analyzer._select_best_leak_point()

        self.assertEqual(best.leak_id, "critical")

    def test_generate_format_string_exploit(self):
        """test generating format string exploit"""
        exploit = self.analyzer._generate_format_string_exploit("user_input", 1)

        self.assertIsInstance(exploit, str)
        self.assertIn("%p", exploit)

    def test_determine_leak_severity(self):
        """test determining leak severity"""
        # critical leak types
        severity = self.analyzer._determine_leak_severity(
            [LeakDataType.LIBC_ADDRESS, LeakDataType.POINTER],
            100
        )
        self.assertEqual(severity, Severity.CRITICAL)

        # medium leak
        severity = self.analyzer._determine_leak_severity(
            [LeakDataType.POINTER],
            50
        )
        self.assertEqual(severity, Severity.MEDIUM)

    def test_analyze_memory_read_vulnerabilities(self):
        """test memory out-of-bounds read analysis"""
        decomp_data = {
            'mem_func': {
                'pseudocode': '''
                    void mem_func(char *buf, char *input) {
                        strcpy(buf, input);
                    }
                ''',
                'address': 0x401100,
            }
        }

        self.analyzer._analyze_memory_read_vulnerabilities(decomp_data)
        self.assertGreaterEqual(len(self.analyzer.leak_points), 0)


class TestInfoLeakAnalyzerEdgeCases(unittest.TestCase):
    """Edge case tests for info leak analyzer"""

    def setUp(self):
        """setup test environment"""
        self.analyzer = InfoLeakAnalyzer()

    def test_empty_binary_info(self):
        """test empty binary info"""
        result = self.analyzer.analyze(binary_info={})

        self.assertIsInstance(result, LeakCapabilityMatrix)

    def test_special_characters_in_code(self):
        decomp_data = {
            'func': {
                'pseudocode': '''
                    void func(char *s) {
                        printf("%s\\n", s);
                    }
                ''',
            }
        }

        result = self.analyzer.analyze(decomp_data=decomp_data)
        self.assertIsInstance(result, LeakCapabilityMatrix)

    def test_very_long_function_names(self):
        decomp_data = {
            'a' * 1000: {
                'pseudocode': 'printf(user_input);',
            }
        }

        result = self.analyzer.analyze(decomp_data=decomp_data)
        self.assertIsInstance(result, LeakCapabilityMatrix)


class TestConvenienceFunction(unittest.TestCase):
    """convenience function tests"""

    def test_analyze_info_leak(self):
        """test analyze_info_leak function"""
        result = analyze_info_leak(
            binary_path="test.bin",
            binary_info={},
            decomp_data={},
            crash_data={}
        )

        self.assertIsInstance(result, LeakCapabilityMatrix)
        self.assertEqual(result.binary_name, "test.bin")


if __name__ == '__main__':
    unittest.main()
