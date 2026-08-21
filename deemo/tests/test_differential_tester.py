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
        first = self.generator.generate_random(min_size=10, max_size=20)
        second = self.generator.generate_random(min_size=10, max_size=20)
        self.assertIsInstance(first, bytes)
        self.assertIsInstance(second, bytes)
        # 去重语义: 碰撞时递归重生成, 两次结果必然不同且哈希集合记 2 条
        self.assertNotEqual(first, second)
        self.assertEqual(len(self.generator.generated_hashes), 2)

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


class TestStandaloneDiffTester(unittest.TestCase):
    """Standalone DifferentialTester测试类"""

    def setUp(self):
        self.m_tmp = tempfile.mkdtemp()
        self.test_binary_a = os.path.join(self.m_tmp, "binary_a")
        self.test_binary_b = os.path.join(self.m_tmp, "binary_b")
        with open(self.test_binary_a, 'wb') as f:
            f.write(b'\x7fELF\x02\x01\x01\x00' + b'\x00' * 100)
        os.chmod(self.test_binary_a, 0o755)
        with open(self.test_binary_b, 'wb') as f:
            f.write(b'\x7fELF\x02\x01\x01\x00' + b'\x00' * 100)
        os.chmod(self.test_binary_b, 0o755)

    def tearDown(self):
        shutil.rmtree(self.m_tmp, ignore_errors=True)

    def test_initialization_cross_version(self):
        tester = StandaloneDiffTester(self.test_binary_a, self.test_binary_b)
        self.assertEqual(tester.test_mode, TestMode.CROSS_VERSION)
        self.assertIsNotNone(tester.binary_a)
        self.assertIsNotNone(tester.binary_b)

    def test_initialization_cross_implementation(self):
        tester = StandaloneDiffTester(self.test_binary_a)
        self.assertEqual(tester.test_mode, TestMode.CROSS_IMPLEMENTATION)
        self.assertIsNotNone(tester.binary_a)
        self.assertIsNone(tester.binary_b)

    def test_validate_binary_invalid_path(self):
        tester = StandaloneDiffTester(self.test_binary_a)
        with self.assertRaises(ValueError):
            tester._validate_binary("/nonexistent/binary")

    def test_generate_test_cases_random(self):
        tester = StandaloneDiffTester(self.test_binary_a)
        test_cases = tester.generate_test_cases(count=10, input_type="random")
        self.assertEqual(len(test_cases), 10)
        self.assertTrue(all(isinstance(tc, StTestCase) for tc in test_cases))

    def test_generate_test_cases_structured(self):
        tester = StandaloneDiffTester(self.test_binary_a)
        test_cases = tester.generate_test_cases(
            count=5, input_type="structured", structured_format="json_data"
        )
        self.assertEqual(len(test_cases), 5)

    def test_generate_test_cases_mutated(self):
        tester = StandaloneDiffTester(self.test_binary_a)
        tester.generate_test_cases(count=5)
        mutated = tester.generate_test_cases(count=3, input_type="mutated")
        self.assertEqual(len(mutated), 3)

    def test_compare_results_no_difference(self):
        tester = StandaloneDiffTester(self.test_binary_a)
        test_case = StTestCase(
            test_id="test_001", input_data=b"test",
            input_type="random", generated_at=1234567890.0
        )
        result_a = ExecutionResult(
            binary_path=self.test_binary_a, test_case=test_case,
            exit_code=0, stdout=b"output", stderr=b"", execution_time=0.1
        )
        difference = tester._compare_results(result_a)
        self.assertEqual(difference.difference_type, DifferenceType.NONE)


class TestHelperFunctions(unittest.TestCase):
    """辅助函数测试"""

    def test_format_differential_report(self):
        result = DifferentialTestResult(
            success=True,
            test_mode=TestMode.CROSS_VERSION,
            total_tests=100,
            total_differences=5,
            execution_time=10.5
        )
        report = format_differential_report(result)
        self.assertIn('差异测试结果', report)


# Tests for src/diff_tester (the clean library version)

class TestSrcTestCase(unittest.TestCase):
    """src/diff_tester TestCase dataclass."""

    def test_minimal_creation(self):
        tc = TestCase(id="t1", input_data=b"\x00\x01")
        self.assertEqual(tc.id, "t1")
        self.assertEqual(tc.input_data, b"\x00\x01")
        self.assertIsNone(tc.expected_output)

    def test_with_tags_and_metadata(self):
        tc = TestCase(
            id="t2", input_data=b"data",
            expected_output="result",
            metadata={"src": "fuzz"},
            tags=["p0", "regression"],
        )
        self.assertIn("p0", tc.tags)
        self.assertEqual(tc.metadata["src"], "fuzz")


class TestOracleComparison(unittest.TestCase):
    """Majority-vote OracleComparator."""

    def test_empty_results(self):
        oracle, diverging, _ = OracleComparator.compare({})
        self.assertIsNone(oracle)
        self.assertEqual(len(diverging), 0)

    def test_unanimous_three(self):
        oracle, diverging, _ = OracleComparator.compare(
            {"a": "out", "b": "out", "c": "out"}
        )
        self.assertEqual(oracle, "out")
        self.assertEqual(len(diverging), 0)

    def test_one_divergent(self):
        oracle, diverging, _ = OracleComparator.compare(
            {"a": "good", "b": "good", "c": "bad"}
        )
        self.assertEqual(oracle, "good")
        self.assertIn("c", diverging)

    def test_no_majority_two_engines(self):
        oracle, diverging, _ = OracleComparator.compare(
            {"a": "x", "b": "y"}
        )
        self.assertIsNone(oracle)
        self.assertEqual(len(diverging), 2)

    def test_find_differences_detail(self):
        diffs = OracleComparator.find_differences(
            {"a": "ok", "b": "bad"}, oracle="ok"
        )
        self.assertEqual(len(diffs), 1)
        self.assertEqual(diffs[0]["engine"], "b")
        self.assertIn("actual", diffs[0])


class TestSrcDifferentialTester(unittest.TestCase):
    """Library DifferentialTester: engine registry + multi-engine testing."""

    def setUp(self):
        self.tester = DifferentialTester()

    def test_add_and_list_engines(self):
        self.tester.add_engine("echo", lambda d: d)
        self.assertIn("echo", self.tester.list_engines())

    def test_remove_engine(self):
        self.tester.add_engine("temp", lambda d: d)
        self.tester.remove_engine("temp")
        self.assertNotIn("temp", self.tester.list_engines())

    def test_run_single_engine(self):
        self.tester.add_engine("upper", lambda d: d.upper())
        tc = TestCase(id="t1", input_data=b"hello")
        result = self.tester.run_single(tc)
        self.assertEqual(result.diff_type, "NONE")

    def test_run_engine_crash(self):
        def boom(data):
            raise RuntimeError("kaboom")
        self.tester.add_engine("crashy", boom)
        tc = TestCase(id="crash", input_data=b"x")
        result = self.tester.run_single(tc)
        self.assertEqual(result.diff_type, "CRASH")

    def test_results_summary(self):
        self.tester.add_engine("id", lambda d: d)
        tcs = [TestCase(id=f"t{i}", input_data=b"x") for i in range(3)]
        self.tester.run_tests(tcs)
        summary = self.tester.results_summary()
        self.assertIn("total", summary)
        self.assertEqual(summary["total"], 3)
        self.assertIn("engines", summary)

    def test_by_engine_summary(self):
        self.tester.add_engine("engine_x", lambda d: d)
        self.tester.run_tests([TestCase(id="t1", input_data=b"x")])
        es = self.tester.by_engine_summary()
        self.assertIn("engine_x", es)


class TestGenerateReport(unittest.TestCase):
    """src/diff_tester report generation."""

    def test_report_with_different_types(self):
        results = [
            DiffResult(
                test_case=TestCase(id="t1", input_data=b"x"),
                engine_outputs={}, diff_type="NONE", differences=[],
            ),
            DiffResult(
                test_case=TestCase(id="t2", input_data=b"y"),
                engine_outputs={}, diff_type="ENGINE_MISMATCH", differences=[],
            ),
        ]
        report = generate_report(results)
        self.assertIn("NONE", report)
        self.assertIn("ENGINE_MISMATCH", report)


if __name__ == '__main__':
    unittest.main()
