
import os
import sys
import unittest
import tempfile
import importlib.util

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

module_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'modules', 'poc_generator.py')
spec = importlib.util.spec_from_file_location('poc_generator', module_path)
poc_generator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(poc_generator)

POCGenerator = poc_generator.POCGenerator
PoCOption = poc_generator.PoCOption
PoCResult = poc_generator.PoCResult
VulnerabilityType = poc_generator.VulnerabilityType
PoCOutputFormat = poc_generator.PoCOutputFormat


class TestPOCGenerator(unittest.TestCase):

    def setUp(self):
        """设置测试环境"""
        # 创建临时测试文件
        self.temp_file = tempfile.NamedTemporaryFile(mode='wb', delete=False)
        self.temp_file.write(b'\x7fELF\x02\x01\x01\x00')
        self.temp_file.close()

    def tearDown(self):
        """清理测试环境"""
        if os.path.exists(self.temp_file.name):
            os.unlink(self.temp_file.name)

    def test_invalid_path(self):
        """测试无效路径"""
        generator = POCGenerator('/nonexistent/path/to/binary')
        result = generator.generate({'type': 'stack_buffer_overflow'})
        self.assertFalse(result.success)
        self.assertIn('无效的文件路径', result.error_message)

    def test_stack_overflow_poc(self):
        """测试栈溢出PoC生成"""
        generator = POCGenerator(self.temp_file.name)

        vuln_info = {
            'type': VulnerabilityType.STACK_BUFFER_OVERFLOW.value,
            'offset': 128,
            'return_address': 0xDEADBEEF
        }

        result = generator.generate(vuln_info)

        self.assertTrue(result.success)
        self.assertEqual(result.vulnerability_type, VulnerabilityType.STACK_BUFFER_OVERFLOW.value)
        self.assertGreater(len(result.poc_data), 0)

    def test_format_string_poc(self):
        """测试格式化字符串PoC生成"""
        generator = POCGenerator(self.temp_file.name)

        vuln_info = {
            'type': VulnerabilityType.FORMAT_STRING.value,
            'num_specifiers': 16
        }

        result = generator.generate(vuln_info)

        self.assertTrue(result.success)
        self.assertEqual(result.vulnerability_type, VulnerabilityType.FORMAT_STRING.value)
        self.assertGreater(len(result.poc_data), 0)

    def test_uaf_poc(self):
        """测试UAF PoC生成"""
        generator = POCGenerator(self.temp_file.name)

        vuln_info = {
            'type': VulnerabilityType.USE_AFTER_FREE.value,
            'alloc_size': 128
        }

        result = generator.generate(vuln_info)

        self.assertTrue(result.success)
        self.assertEqual(result.vulnerability_type, VulnerabilityType.USE_AFTER_FREE.value)
        self.assertGreater(len(result.script_content), 0)

    def test_double_free_poc(self):
        """测试Double Free PoC生成"""
        generator = POCGenerator(self.temp_file.name)

        vuln_info = {
            'type': VulnerabilityType.DOUBLE_FREE.value,
            'alloc_size': 64
        }

        result = generator.generate(vuln_info)

        self.assertTrue(result.success)
        self.assertEqual(result.vulnerability_type, VulnerabilityType.DOUBLE_FREE.value)
        self.assertGreater(len(result.script_content), 0)

    def test_integer_overflow_poc(self):
        generator = POCGenerator(self.temp_file.name)

        vuln_info = {
            'type': VulnerabilityType.INTEGER_OVERFLOW.value,
            'overflow_value': 0x7FFFFFFF
        }

        result = generator.generate(vuln_info)

        self.assertTrue(result.success)
        self.assertEqual(result.vulnerability_type, VulnerabilityType.INTEGER_OVERFLOW.value)
        self.assertGreater(len(result.poc_data), 0)

    def test_unsupported_vulnerability_type(self):
        """测试不支持的漏洞类型"""
        generator = POCGenerator(self.temp_file.name)

        vuln_info = {
            'type': 'unsupported_type'
        }

        result = generator.generate(vuln_info)

        self.assertFalse(result.success)
        self.assertIn('不支持的漏洞类型', result.error_message)

    def test_poc_save(self):
        """测试PoC保存"""
        import shutil

        generator = POCGenerator(self.temp_file.name)

        vuln_info = {
            'type': VulnerabilityType.STACK_BUFFER_OVERFLOW.value,
            'offset': 64
        }

        options = PoCOption(output_dir='./temp_pocs_test')

        try:
            result = generator.generate(vuln_info, options)

            self.assertTrue(result.success)
            self.assertTrue(result.poc_path)
            self.assertTrue(os.path.exists(result.poc_path))
        finally:
            if os.path.exists('./temp_pocs_test'):
                shutil.rmtree('./temp_pocs_test')

    def test_result_to_dict(self):
        generator = POCGenerator(self.temp_file.name)

        vuln_info = {
            'type': VulnerabilityType.STACK_BUFFER_OVERFLOW.value,
            'offset': 64
        }

        result = generator.generate(vuln_info)
        dict_result = result.to_dict()

        self.assertIn('success', dict_result)
        self.assertIn('vulnerability_type', dict_result)
        self.assertIn('poc_path', dict_result)



if __name__ == '__main__':
    unittest.main()


