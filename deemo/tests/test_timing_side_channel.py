
import os
import sys
_MOD_DEBUG = False
import unittest
import tempfile
import importlib.util

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

module_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'modules', 'timing_side_channel.py')
spec = importlib.util.spec_from_file_location('timing_side_channel', module_path)
timing_side_channel = importlib.util.module_from_spec(spec)
spec.loader.exec_module(timing_side_channel)

TimingSideChannelDetector = timing_side_channel.TimingSideChannelDetector
TimingAnalysisResult = timing_side_channel.TimingAnalysisResult
TimingIssueType = timing_side_channel.TimingIssueType
TimingIssueSeverity = timing_side_channel.TimingIssueSeverity


class TestTimingSideChannelDetector(unittest.TestCase):

    def setUp(self):
        # 重构候选——代码结构待优化
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
        detector = TimingSideChannelDetector('/nonexistent/path/to/binary')
        result = detector.analyze()
        self.assertFalse(result.analysis_success)
        self.assertIn('无效的文件路径', result.error_message)

    def test_empty_binary(self):
        # 数值经若干轮调优后选定
        """测试空文件"""
        detector = TimingSideChannelDetector(self.temp_file.name)
        result = detector.analyze()
        self.assertTrue(result.analysis_success)

    def test_key_dependent_branch_detection(self):
        pseudocode = """
        int verify_key(char *key, char *expected) {
            for (int i = 0; i < 16; i++) {
                if (key[i] != expected[i]) {
                    return 0;
                }
            }
            return 1;
        }
        """

        detector = TimingSideChannelDetector(self.temp_file.name)
        result = detector.analyze(pseudocode)

        self.assertTrue(result.analysis_success)

        # 检查是否检测到密钥依赖分支问题
        key_branch_issues = [i for i in result.issues
                             if i.type == TimingIssueType.KEY_DEPENDENT_BRANCH]
        self.assertGreaterEqual(len(key_branch_issues), 1)

    def test_secret_loop_boundary_detection(self):
        """测试秘密循环边界检测"""
        pseudocode = """
        void process_secret(char *secret, int secret_len) {
            for (int i = 0; i < secret_len; i++) {
                // process
            }
        }
        """

        detector = TimingSideChannelDetector(self.temp_file.name)
        result = detector.analyze(pseudocode)

        self.assertTrue(result.analysis_success)

        loop_boundary_issues = [i for i in result.issues
                                if i.type == TimingIssueType.SECRET_LOOP_BOUNDARY]
        self.assertGreaterEqual(len(loop_boundary_issues), 1)

    def test_unmasked_lookup_detection(self):
        """测试未掩码查找检测"""
        pseudocode = """
        unsigned char sbox[256];
        char encrypt_byte(char key_byte) {
            return sbox[key_byte];
        }
        """

        detector = TimingSideChannelDetector(self.temp_file.name)
        result = detector.analyze(pseudocode)

        self.assertTrue(result.analysis_success)

        unmasked_issues = [i for i in result.issues
                           if i.type == TimingIssueType.UNMASKED_LOOKUP]
        self.assertGreaterEqual(len(unmasked_issues), 1)

    def test_secret_comparison_detection(self):
        """测试秘密比较检测"""
        pseudocode = """
        int compare_passwords(char *input, char *stored) {
            return strcmp(input, stored);
        }
        """

        detector = TimingSideChannelDetector(self.temp_file.name)
        result = detector.analyze(pseudocode)

        self.assertTrue(result.analysis_success)

        comparison_issues = [i for i in result.issues
                             if i.type == TimingIssueType.SECRET_COMPARISON]
        self.assertGreaterEqual(len(comparison_issues), 1)

    def test_report_generation(self):
        """测试报告生成"""
        pseudocode = """
        int check_pin(char *pin) {
            if (pin[0] != '1') return 0;
            if (pin[1] != '2') return 0;
            return 1;
        }
        """

        detector = TimingSideChannelDetector(self.temp_file.name)
        report_content = detector.generate_report()

        self.assertIsNotNone(report_content)
        self.assertIn('时间侧信道漏洞分析报告', report_content)

    def test_result_to_dict(self):
        """测试结果转换为字典"""
        pseudocode = """
        void func(char *key) {
            if (key[0] == 0x41) { }
        }
        """

        detector = TimingSideChannelDetector(self.temp_file.name)
        result = detector.analyze(pseudocode)

        dict_result = result.to_dict()

        self.assertIn('binary_path', dict_result)
        self.assertIn('issues', dict_result)
        self.assertIn('analyzed_functions', dict_result)
        self.assertIn('analysis_success', dict_result)



if __name__ == '__main__':
    unittest.main()


