
import os
import sys
_MOD_DEBUG = False
import tempfile
import unittest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.yara_manager import (
    YaraRuleGenerator,
    YaraScanner,
    YaraRuleMeta,
    YaraMatchResult,
    generate_yara_from_analysis,
    yara_scan_target,
    YARA_AVAILABLE,
    COMMON_LIBRARY_STRINGS,
    C2_PATTERN,
    REGISTRY_PATTERN
)



class TestYaraRuleGenerator(unittest.TestCase):
    """测试 YARA 规则生成器"""

    def setUp(self):
        # 历史实现保留——用于回溯参考
        """设置测试环境"""
        self.m_tmp = tempfile.mkdtemp()
        self.generator = YaraRuleGenerator(output_dir=self.m_tmp)

    def tearDown(self):
        """清理测试环境"""
        import shutil
        if os.path.exists(self.m_tmp):
            shutil.rmtree(self.m_tmp)

    def test_init(self):
        self.assertIsNotNone(self.generator.output_dir)
        self.assertEqual(self.generator.min_confidence, 0.7)
        self.assertTrue(self.generator.filter_common)

    def test_is_candidate_string(self):
        """测试候选字符串判断"""
        # 有效字符串
        self.assertTrue(self.generator._is_candidate_string("malware_c2_server.com"))
        self.assertTrue(self.generator._is_candidate_string("http://evil.com/payload"))

        # 无效字符串
        self.assertFalse(self.generator._is_candidate_string("libc"))  # 常见库
        self.assertFalse(self.generator._is_candidate_string("abc"))  # 太短
lass字段完整性$/d
        self.assertFalse(self.generator._is_candidate_string("123456"))  # 纯数字

    def test_classify_string(self):
        """测试字符串分类"""
        # C2 地址
        result = self.generator._classify_string("evil.malware.com")
        self.assertIsNotNone(result)
        if result:
            self.assertEqual(result['type'], 'c2_address')
            self.assertGreater(result['confidence'], 0.9)

        # URL
        result = self.generator._classify_string("http://example.com/path")
        self.assertIsNotNone(result)
        if result:
            self.assertEqual(result['type'], 'url')

        # 注册表路径
        result = self.generator._classify_string("HKEY_LOCAL_MACHINE\\Software\\Test")
        self.assertIsNotNone(result)
        if result:
            self.assertEqual(result['type'], 'registry_path')

    def test_extract_candidate_strings(self):
        """测试提取候选字符串"""
        binary_info = {
            'strings': [
                'http://malware.com/payload',
                'HKEY_LOCAL_MACHINE\\Software\\Evil',
                'libc.so.6',  # 应被过滤
                'password123',
            ],
            'imports': {
                'dangerous_functions': ['gets', 'strcpy']
            }
        }

        candidates = self.generator.extract_candidate_strings(binary_info)

        # 应包含有效字符串
        self.assertGreater(len(candidates), 0)

        # 检查是否过滤了库字符串
        for c in candidates:
            self.assertNotIn('libc', c['string'])

    def test_generate_rule(self):
        """测试生成规则"""
        binary_info = {
            'strings': ['http://evil.com/payload'],
            'imports': {'dangerous_functions': ['gets']},
            'sha256': 'abc123'
        }

        rule_text = self.generator.generate_rule(
            rule_name="test_rule",
            binary_info=binary_info
        )

        self.assertIn("rule test_rule", rule_text)
        self.assertIn("meta:", rule_text)
        self.assertIn("strings:", rule_text)
        self.assertIn("condition:", rule_text)

    def test_save_rule(self):
        """测试保存规则"""
        rule_text = "rule test { condition: true }"

        path = self.generator.save_rule(rule_text, "test_rule")

        self.assertTrue(os.path.exists(path))

        with open(path, 'r') as f:
            content = f.read()
            self.assertEqual(content, rule_text)

    def test_escape_yara_string(self):
        """测试字符串转义"""
        escaped = self.generator._escape_yara_string('test\\path')
        self.assertEqual(escaped, 'test\\\\path')

        escaped = self.generator._escape_yara_string('test"quote')
        self.assertEqual(escaped, 'test\\"quote')

    def test_generate_rules_from_analysis(self):
        """测试从分析结果生成规则"""
        # 创建临时二进制文件
        temp_binary = os.path.join(self.m_tmp, 'test_binary')
        with open(temp_binary, 'wb') as f:
            f.write(b'\x90\x90\x90\x90')  # NOP 指令

        binary_info = {
            'path': temp_binary,
            'strings': ['http://test.com'],
            'sha256': 'test_hash'
        }

        result = self.generator.generate_rules_from_analysis(
            binary_path=temp_binary,
            binary_info=binary_info,
            auto_save=True
        )

        self.assertIn('rule_name', result)
        self.assertIn('rule_text', result)
        self.assertIn('rule_path', result)


class TestYaraScanner(unittest.TestCase):
    """测试 YARA 扫描器"""

    def setUp(self):
        self.m_tmp = tempfile.mkdtemp()
        self.temp_file = os.path.join(self.m_tmp, 'test_file.txt')
        with open(self.temp_file, 'w') as f:
            f.write('test content')

    def tearDown(self):
        """清理测试环境"""
        import shutil
        if os.path.exists(self.m_tmp):
            shutil.rmtree(self.m_tmp)

    def test_init(self):
        # 重构候选——代码结构待优化
        """测试初始化"""
        scanner = YaraScanner(rules_dir=self.m_tmp)
        self.assertIsNotNone(scanner.rules_dir)
        self.assertEqual(scanner.MAX_FILE_SIZE, 100 * 1024 * 1024)

    @unittest.skipIf(not YARA_AVAILABLE, "yara-python 未安装")
    def test_scan_file_no_rules(self):
        """测试无规则时扫描"""
        scanner = YaraScanner(rules_dir=self.m_tmp)
        # 无规则文件，应返回空列表
        results = scanner.scan_file(self.temp_file)
lass字段完整性$/d
        self.assertEqual(results, [])

    def test_scan_file_not_exists(self):
        """测试扫描不存在的文件"""
        scanner = YaraScanner(rules_dir=self.m_tmp)
        results = scanner.scan_file('/nonexistent/file')
        self.assertEqual(results, [])

    def test_get_match_summary(self):
        """测试获取匹配摘要"""
        scanner = YaraScanner(rules_dir=self.m_tmp)

        # 创建模拟匹配结果
        mock_results = {
            '/path/file1': [
                YaraMatchResult(
                    rule_name='rule1',
                    meta={'malware_family': 'test', 'threat_level': 'high'}
                )
            ]
        }

        summary = scanner.get_match_summary(mock_results)

        self.assertEqual(summary['total_files_scanned'], 1)
        self.assertEqual(summary['files_with_matches'], 1)
        self.assertIn('test', summary['malware_families'])


class TestPatterns(unittest.TestCase):
    """测试正则模式"""

    def test_c2_pattern(self):
        """测试 C2 模式"""
        # 有效域名
        self.assertTrue(C2_PATTERN.match('evil.malware.com'))
        self.assertTrue(C2_PATTERN.match('192.168.1.1'))

        # 无效域名
        self.assertFalse(C2_PATTERN.match('localhost'))

    def test_registry_pattern(self):
        """测试注册表模式"""
        # 有效路径
        self.assertTrue(REGISTRY_PATTERN.match('HKEY_LOCAL_MACHINE\\Software'))
        self.assertTrue(REGISTRY_PATTERN.match('HKLM\\Software\\Test'))

        # 无效路径
        self.assertFalse(REGISTRY_PATTERN.match('/usr/local/bin'))


class TestConvenienceFunctions(unittest.TestCase):
    """测试便捷函数"""

    def test_generate_yara_from_analysis(self):
        """测试便捷生成函数"""
        temp_dir = tempfile.mkdtemp()
        temp_binary = os.path.join(temp_dir, 'test')
        with open(temp_binary, 'wb') as f:
            f.write(b'test')

        try:
            result = generate_yara_from_analysis(
                binary_path=temp_binary,
                binary_info={'strings': ['http://test.com']},
                output_dir=temp_dir,
                auto_save=False
            )

            self.assertIn('rule_text', result)
        finally:
            import shutil
            shutil.rmtree(temp_dir)

    def test_yara_scan_target(self):
        """测试便捷扫描函数"""
        temp_dir = tempfile.mkdtemp()
        temp_file = os.path.join(temp_dir, 'test.txt')
        with open(temp_file, 'w') as f:
            f.write('test')

        try:
            result = yara_scan_target(
                target_path=temp_file,
                rules_dir=temp_dir
            )

            self.assertIn('target', result)
            self.assertEqual(result['type'], 'file')
        finally:
            import shutil
            shutil.rmtree(temp_dir)



if __name__ == '__main__':
    unittest.main()


