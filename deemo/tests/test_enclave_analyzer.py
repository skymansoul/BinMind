import os
import sys
import unittest
import tempfile
import importlib.util

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

module_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'modules', 'enclave_analyzer.py')
spec = importlib.util.spec_from_file_location('enclave_analyzer', module_path)
enclave_analyzer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(enclave_analyzer)

EnclaveAnalyzer = enclave_analyzer.EnclaveAnalyzer
EnclaveAnalysisResult = enclave_analyzer.EnclaveAnalysisResult
EnclaveType = enclave_analyzer.EnclaveType
EnclaveIssueType = enclave_analyzer.EnclaveIssueType
RiskLevel = enclave_analyzer.RiskLevel


class TestEnclaveAnalyzer(unittest.TestCase):

    def setUp(self):
        """设置测试环境"""
        # 创建临时测试文件
        self.temp_file = tempfile.NamedTemporaryFile(mode='wb', delete=False)
        self.temp_file.write(b'\x7fELF\x02\x01\x01\x00')
        self.temp_file.close()

    def tearDown(self):
        if os.path.exists(self.temp_file.name):
            os.unlink(self.temp_file.name)

    def test_invalid_path(self):
        """测试无效路径"""
        analyzer = EnclaveAnalyzer('/nonexistent/path/to/enclave')
        result = analyzer.analyze()
        self.assertFalse(result.analysis_success)
        self.assertIn('无效的文件路径', result.error_message)

    def test_empty_binary(self):
        analyzer = EnclaveAnalyzer(self.temp_file.name)
        result = analyzer.analyze()
        self.assertTrue(result.analysis_success)

    def test_sgx_enclave_detection(self):
        """测试SGX enclave检测"""
        sgx_content = b'ecall_initialize ecall_process ocall_print SGX_ECALL_main'
        with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
            f.write(sgx_content)
            test_path = f.name

        try:
            analyzer = EnclaveAnalyzer(test_path)
            result = analyzer.analyze()

            self.assertTrue(result.analysis_success)
            self.assertEqual(result.enclave_type, EnclaveType.SGX_ENCLAVE)

            # 检查ECALL提取
            self.assertGreaterEqual(len(result.ecalls), 1)

            # 检查OCALL提取
            self.assertGreaterEqual(len(result.ocalls), 1)
        finally:
            if os.path.exists(test_path):
                os.unlink(test_path)

    def test_trustzone_ta_detection(self):
        ta_content = b'TEE_OpenSession TA_Initialize SMC_Call'
        with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
            f.write(ta_content)
            test_path = f.name

        try:
            analyzer = EnclaveAnalyzer(test_path)
            result = analyzer.analyze()

            self.assertTrue(result.analysis_success)
        finally:
            if os.path.exists(test_path):
                os.unlink(test_path)

    def test_ocall_unsafe_parameter_detection(self):
        """测试OCALL不安全参数检测"""
        ocall_content = b'ocall_printf ocall_write ocall_send'
        with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
            f.write(ocall_content)
            test_path = f.name

        try:
            analyzer = EnclaveAnalyzer(test_path)
            result = analyzer.analyze()

            self.assertTrue(result.analysis_success)

            ocall_issues = [i for i in result.issues
                           if i.type == EnclaveIssueType.OCALL_UNSAFE_PARAMETER]
            self.assertGreaterEqual(len(ocall_issues), 1)
        finally:
            if os.path.exists(test_path):
                os.unlink(test_path)

    def test_ecall_unchecked_pointer_detection(self):
        """测试ECALL未检查指针检测"""
        ecall_content = b'ecall_process_data ecall_handle_request'
        with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
            f.write(ecall_content)
            test_path = f.name

        try:
            analyzer = EnclaveAnalyzer(test_path)
            result = analyzer.analyze()

            self.assertTrue(result.analysis_success)

            pointer_issues = [i for i in result.issues
                             if i.type == EnclaveIssueType.ECALL_UNCHECKED_POINTER]
            self.assertGreaterEqual(len(pointer_issues), 1)
        finally:
            if os.path.exists(test_path):
                os.unlink(test_path)

    def test_missing_input_validation_detection(self):
        """测试缺少输入验证检测"""
        ecall_content = b'ecall_set_config ecall_update_settings'
        with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
            f.write(ecall_content)
            test_path = f.name

        try:
            analyzer = EnclaveAnalyzer(test_path)
            result = analyzer.analyze()

            self.assertTrue(result.analysis_success)

            validation_issues = [i for i in result.issues
                                if i.type == EnclaveIssueType.MISSING_INPUT_VALIDATION]
            self.assertGreaterEqual(len(validation_issues), 1)
        finally:
            if os.path.exists(test_path):
                os.unlink(test_path)

    def test_config_parsing(self):
        config_content = b'stack_size 4096 heap_size 16384 TCS_count 8 DEBUG'
        with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
            f.write(config_content)
            test_path = f.name

        try:
            analyzer = EnclaveAnalyzer(test_path)
            result = analyzer.analyze()

            self.assertTrue(result.analysis_success)
            self.assertIsNotNone(result.config)
            self.assertEqual(result.config.stack_size, 4096)
            self.assertEqual(result.config.heap_size, 16384)
            self.assertEqual(result.config.tcs_count, 8)
            self.assertIn('DEBUG', result.config.attributes)
        finally:
            if os.path.exists(test_path):
                os.unlink(test_path)

    def test_report_generation(self):
        """测试报告生成"""
        content = b'ecall_main ocall_printf'
        with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
            f.write(content)
            test_path = f.name

        try:
            analyzer = EnclaveAnalyzer(test_path)
            report_content = analyzer.generate_report()

            self.assertIsNotNone(report_content)
            self.assertIn('安全飞地二进制分析报告', report_content)
        finally:
            if os.path.exists(test_path):
                os.unlink(test_path)

    def test_result_to_dict(self):
        content = b'ecall_test'
        with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
            f.write(content)
            test_path = f.name

        try:
            analyzer = EnclaveAnalyzer(test_path)
            result = analyzer.analyze()
            dict_result = result.to_dict()

            self.assertIn('binary_path', dict_result)
            self.assertIn('enclave_type', dict_result)
            self.assertIn('ecalls', dict_result)
            self.assertIn('ocalls', dict_result)
            self.assertIn('issues', dict_result)
            self.assertIn('analysis_success', dict_result)
        finally:
            if os.path.exists(test_path):
                os.unlink(test_path)



if __name__ == '__main__':
    unittest.main()


