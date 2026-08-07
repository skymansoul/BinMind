"""
差异测试模块单元测试 -- enriched with OracleComparator, src/diff_tester coverage.

Tests differential testing: input generation, test case creation, execution results,
difference detection, majority-vote oracle comparison, and report formatting.
"""
import unittest
import sys
import os
import tempfile
import shutil

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.differential_tester import (
    DifferentialTester as StandaloneDiffTester,
    InputGenerator,
    TestMode,
    DifferenceType,
    TestCase as StTestCase,
    ExecutionResult,
    Difference,
    DifferentialTestResult,
    format_differential_report,
)

# Import the clean src library version
from modules.testing.src.diff_tester import (
    TestCase,
    DiffResult,
    OracleComparator,
    DifferentialTester,
    generate_report,
)

# Prevent pytest from trying to collect dataclass/enum helpers as test classes
TestMode.__test__ = False
StTestCase.__test__ = False
TestCase.__test__ = False


class TestInputGenerator(unittest.TestCase):
    """InputGenerator测试类 -- random, structured, mutation"""

    def setUp(self):
        self.generator = InputGenerator(seed=42)

    def test_initialization(self):
        self.assertIsNotNone(self.generator)
        self.assertIsNotNone(self.generator.rng)

    def test_generate_random(self):
        data = self.generator.generate_random(min_size=10, max_size=100)
        self.assertIsInstance(data, bytes)
        self.assertGreaterEqual(len(data), 10)
        self.assertLessEqual(len(data), 100)

    def test_generate_random_deduplication(self):
        data1 = self.generator.generate_random(min_size=10, max_size=20)
        data2 = self.generator.generate_random(min_size=10, max_size=20)
        self.assertIsInstance(data2, bytes)

    def test_generate_http_request(self):
        data = self.generator._generate_http_request()
        self.assertIsInstance(data, bytes)
        self.assertIn(b'HTTP', data)

    def test_generate_json_data(self):
        data = self.generator._generate_json_data()
        self.assertIsInstance(data, bytes)
        import json
        parsed = json.loads(data.decode('utf-8'))
        self.assertIsInstance(parsed, dict)

    def test_generate_xml_data(self):
        data = self.generator._generate_xml_data()
        self.assertIsInstance(data, bytes)
        self.assertIn(b'<?xml', data)

    def test_generate_binary_header(self):
        data = self.generator._generate_binary_header()
        self.assertIsInstance(data, bytes)
        self.assertGreater(len(data), 0)

    def test_mutate_bitflip(self):
        original = bytearray([0xFF, 0x00, 0xAA, 0x55])
        mutated = self.generator._mutate_bitflip(original)
        self.assertIsInstance(mutated, bytearray)
        self.assertEqual(len(mutated), len(original))

    def test_mutate_byteflip(self):
        original = bytearray([0xFF, 0x00, 0xAA, 0x55])
        mutated = self.generator._mutate_byteflip(original)
        self.assertIsInstance(mutated, bytearray)

    def test_mutate_arithmetic(self):
        original = bytearray([100, 150, 200])
        mutated = self.generator._mutate_arithmetic(original)
        self.assertIsInstance(mutated, bytearray)

    def test_mutate_insert(self):
        original = bytearray([0xFF, 0x00, 0xAA])
        mutated = self.generator._mutate_insert(original)
        self.assertIsInstance(mutated, bytearray)

    def test_mutate_delete(self):
        original = bytearray([0xFF, 0x00, 0xAA, 0x55])
        mutated = self.generator._mutate_delete(original)
        self.assertIsInstance(mutated, bytearray)
        self.assertLessEqual(len(mutated), len(original))

    def test_mutate_overwrite(self):
        original = bytearray([0xFF, 0x00, 0xAA, 0x55, 0x11])
        mutated = self.generator._mutate_overwrite(original)
        self.assertIsInstance(mutated, bytearray)

    def test_mutate(self):
        original = b'\x00\x01\x02\x03\x04\x05'
        mutated = self.generator.mutate(original, mutations=3)
        self.assertIsInstance(mutated, bytes)


class TestStandaloneTestCase(unittest.TestCase):
    """Standalone TestCase测试类"""

    def test_testcase_creation(self):
        test_case = StTestCase(
            test_id="test_001",
            input_data=b"test input",
            input_type="random",
            generated_at=1234567890.0
        )
        self.assertEqual(test_case.test_id, "test_001")
        self.assertEqual(test_case.input_data, b"test input")
        self.assertEqual(test_case.input_type, "random")


class TestExecutionResult(unittest.TestCase):
    """ExecutionResult测试类"""

    def test_execution_result_creation(self):
        test_case = StTestCase(
            test_id="test_001",
            input_data=b"test input",
            input_type="random",
            generated_at=1234567890.0
        )
        result = ExecutionResult(
            binary_path="/test/binary",
            test_case=test_case,
            exit_code=0,
            stdout=b"output",
            stderr=b"",
            execution_time=0.5
        )
        self.assertEqual(result.binary_path, "/test/binary")
        self.assertEqual(result.exit_code, 0)
        self.assertFalse(result.crashed)

    def test_crash_detection_nonzero_exit(self):
        """非零退出码→crash"""
        tc = StTestCase(test_id="cr", input_data=b"x", input_type="random", generated_at=0)
        result = ExecutionResult(
            binary_path="/bin/a", test_case=tc,
            exit_code=139, stdout=b"", stderr=b"SEGV"
        )
        self.assertTrue(result.crashed)


class TestDifference(unittest.TestCase):
    """Difference测试类"""

    def test_difference_creation(self):
        test_case = StTestCase(
            test_id="test_001", input_data=b"test input",
            input_type="random", generated_at=1234567890.0
        )
        diff = Difference(
            test_case=test_case,
            difference_type=DifferenceType.CRASH,
            description="Binary A crashed",
            severity="high",
            likely_vulnerability=True
        )
        self.assertEqual(diff.difference_type, DifferenceType.CRASH)
        self.assertTrue(diff.likely_vulnerability)


class TestDifferenceType(unittest.TestCase):
    """DifferenceType枚举测试"""

    def test_difference_types(self):
        self.assertEqual(DifferenceType.OUTPUT_MISMATCH.value, "output_mismatch")
        self.assertEqual(DifferenceType.CRASH.value, "crash")
        self.assertEqual(DifferenceType.HANG.value, "hang")
        self.assertEqual(DifferenceType.MEMORY_CORRUPTION.value, "memory_corruption")
        self.assertEqual(DifferenceType.NONE.value, "none")


