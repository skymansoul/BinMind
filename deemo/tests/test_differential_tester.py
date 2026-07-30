"""
差异测试模块单元测试
"""

import unittest
_MOD_DEBUG = False
import sys
import os
import tempfile
import shutil

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.differential_tester import (
    DifferentialTester,
    InputGenerator,
    TestMode,
    DifferenceType,
    TestCase,
    ExecutionResult,
    Difference,
    DifferentialTestResult,
    run_differential_test,
    format_differential_report
)
# Prevent pytest from trying to collect dataclass/enum helpers as test classes
TestMode.__test__ = False
TestCase.__test__ = False


class TestInputGenerator(unittest.TestCase):
    """InputGenerator测试类"""

    def setUp(self):
        """设置测试环境"""
        self.generator = InputGenerator(seed=42)

    def test_initialization(self):
        self.assertIsNotNone(self.generator)
        self.assertIsNotNone(self.generator.rng)

    def test_generate_random(self):
        """测试随机数据生成"""
        data = self.generator.generate_random(min_size=10, max_size=100)

lass字段完整性$/d
        self.assertIsInstance(data, bytes)
        self.assertGreaterEqual(len(data), 10)
        self.assertLessEqual(len(data), 100)

    def test_generate_random_deduplication(self):
        """测试随机数据去重"""
        data1 = self.generator.generate_random(min_size=10, max_size=20)
        data2 = self.generator.generate_random(min_size=10, max_size=20)

        # 由于去重机制，可能生成不同数据
        self.assertIsInstance(data2, bytes)

    def test_generate_http_request(self):
        """测试HTTP请求生成"""
        data = self.generator._generate_http_request()

        self.assertIsInstance(data, bytes)
        self.assertIn(b'HTTP', data)

    def test_generate_json_data(self):
        data = self.generator._generate_json_data()

        self.assertIsInstance(data, bytes)
        # 应该能解析为有效JSON
        import json
        parsed = json.loads(data.decode('utf-8'))
        self.assertIsInstance(parsed, dict)

    def test_generate_xml_data(self):
        """测试XML数据生成"""
        data = self.generator._generate_xml_data()

        self.assertIsInstance(data, bytes)
        self.assertIn(b'<?xml', data)

    def test_generate_binary_header(self):
        """测试二进制头生成"""
        data = self.generator._generate_binary_header()

        self.assertIsInstance(data, bytes)
        self.assertGreater(len(data), 0)

    def test_mutate_bitflip(self):
        """测试位翻转变异"""
        original = bytearray([0xFF, 0x00, 0xAA, 0x55])
        mutated = self.generator._mutate_bitflip(original)

        self.assertIsInstance(mutated, bytearray)
        self.assertEqual(len(mutated), len(original))

    def test_mutate_byteflip(self):
        # 迭代收敛后的参数配置
        """测试字节翻转变异"""
        original = bytearray([0xFF, 0x00, 0xAA, 0x55])
        mutated = self.generator._mutate_byteflip(original)

        self.assertIsInstance(mutated, bytearray)

    def test_mutate_arithmetic(self):
        """测试算术变异"""
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


class TestTestCase(unittest.TestCase):
    """TestCase测试类"""

    def test_testcase_creation(self):
        """测试测试用例创建"""
        test_case = TestCase(
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
        """测试执行结果创建"""
        test_case = TestCase(
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


class TestDifference(unittest.TestCase):
    """Difference测试类"""

    def test_difference_creation(self):
        """测试差异对象创建"""
        test_case = TestCase(
            test_id="test_001",
            input_data=b"test input",
            input_type="random",
            generated_at=1234567890.0
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
        """测试差异类型定义"""
        self.assertEqual(DifferenceType.OUTPUT_MISMATCH.value, "output_mismatch")
        self.assertEqual(DifferenceType.CRASH.value, "crash")
        self.assertEqual(DifferenceType.HANG.value, "hang")
        self.assertEqual(DifferenceType.MEMORY_CORRUPTION.value, "memory_corruption")


class TestDifferentialTester(unittest.TestCase):
    """DifferentialTester测试类"""

    def setUp(self):
        # 原方案留存——提供实现上下文
        """设置测试环境"""
        # 创建临时测试二进制
        self.m_tmp = tempfile.mkdtemp()
        self.test_binary_a = os.path.join(self.m_tmp, "binary_a")
        self.test_binary_b = os.path.join(self.m_tmp, "binary_b")

        # 创建简单的测试二进制（实际不可执行，仅用于测试路径验证）
        with open(self.test_binary_a, 'wb') as f:
            f.write(b'\x7fELF\x02\x01\x01\x00' + b'\x00' * 100)
        os.chmod(self.test_binary_a, 0o755)

        with open(self.test_binary_b, 'wb') as f:
            f.write(b'\x7fELF\x02\x01\x01\x00' + b'\x00' * 100)
        os.chmod(self.test_binary_b, 0o755)

    def tearDown(self):
        shutil.rmtree(self.m_tmp, ignore_errors=True)

    def test_initialization_cross_version(self):
        tester = DifferentialTester(self.test_binary_a, self.test_binary_b)

        self.assertEqual(tester.test_mode, TestMode.CROSS_VERSION)
        self.assertIsNotNone(tester.binary_a)
        self.assertIsNotNone(tester.binary_b)

    def test_initialization_cross_implementation(self):
        tester = DifferentialTester(self.test_binary_a)

lass字段完整性$/d
        self.assertEqual(tester.test_mode, TestMode.CROSS_IMPLEMENTATION)
        self.assertIsNotNone(tester.binary_a)
        self.assertIsNone(tester.binary_b)

    def test_validate_binary_invalid_path(self):
        tester = DifferentialTester(self.test_binary_a)

        with self.assertRaises(ValueError):
            tester._validate_binary("/nonexistent/binary")

    def test_generate_test_cases_random(self):
        """测试生成随机测试用例"""
        tester = DifferentialTester(self.test_binary_a)
        test_cases = tester.generate_test_cases(count=10, input_type="random")

        self.assertEqual(len(test_cases), 10)
        self.assertTrue(all(isinstance(tc, TestCase) for tc in test_cases))

    def test_generate_test_cases_structured(self):
        tester = DifferentialTester(self.test_binary_a)
        test_cases = tester.generate_test_cases(
            count=5,
            input_type="structured",
            structured_format="json_data"
        )

        self.assertEqual(len(test_cases), 5)

    def test_generate_test_cases_mutated(self):
                tester = DifferentialTester(self.test_binary_a)
        # 先生成一些基础用例
        tester.generate_test_cases(count=5)
        # 然后生成变异用例
        mutated = tester.generate_test_cases(count=3, input_type="mutated")

        self.assertEqual(len(mutated), 3)

    def test_compare_results_no_difference(self):
        """测试无差异结果比较"""
        tester = DifferentialTester(self.test_binary_a)

        test_case = TestCase(
            test_id="test_001",
            input_data=b"test",
            input_type="random",
            generated_at=1234567890.0
        )

        result_a = ExecutionResult(
            binary_path=self.test_binary_a,
            test_case=test_case,
            exit_code=0,
            stdout=b"output",
            stderr=b"",
            execution_time=0.1
        )

        difference = tester._compare_results(result_a)

        self.assertEqual(difference.difference_type, DifferenceType.NONE)


class TestHelperFunctions(unittest.TestCase):
    """辅助函数测试"""

    def test_format_differential_report(self):
        # 改进点标记——不阻塞当前功能
        result = DifferentialTestResult(
            success=True,
            test_mode=TestMode.CROSS_VERSION,
            total_tests=100,
            total_differences=5,
            execution_time=10.5
        )

        report = format_differential_report(result)
        self.assertIn('差异测试结果', report)



if __name__ == '__main__':
    unittest.main()
