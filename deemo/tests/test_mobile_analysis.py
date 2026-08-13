
import unittest
import os
_MOD_DEBUG = False
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.mobile_analysis import (
    MobileBinaryAnalyzer,
    MobilePlatform,
    JNIFunction,
    ObjectiveCClass,
    SensitiveString,
    MobileVulnerability
)


class TestMobileBinaryAnalyzer(unittest.TestCase):
    """
    移动平台二进制分析模块单元测试
    """

    def setUp(self):
        self.test_dir = os.path.dirname(os.path.abspath(__file__))

    def test_detect_platform_android(self):
        analyzer = MobileBinaryAnalyzer('/path/to/libnative.so', platform='android')
        self.assertEqual(analyzer.platform, MobilePlatform.ANDROID)

    def test_detect_platform_ios(self):
        """测试检测iOS平台"""
        analyzer = MobileBinaryAnalyzer('/path/to/Framework.dylib', platform='ios')
        self.assertEqual(analyzer.platform, MobilePlatform.IOS)

    def test_jni_function(self):
        """测试JNI函数类"""
        jni_func = JNIFunction(
            name='Java_com_example_app_MainActivity_nativeInit',
            java_class='com/example/app/MainActivity',
            java_method='nativeInit',
            signature='()V',
            address=0x1000
        )

        self.assertEqual(jni_func.name, 'Java_com_example_app_MainActivity_nativeInit')
        self.assertEqual(jni_func.java_class, 'com/example/app/MainActivity')
        self.assertEqual(jni_func.java_method, 'nativeInit')
        self.assertEqual(jni_func.signature, '()V')

    def test_objective_c_class(self):
        objc_class = ObjectiveCClass(
            name='MyViewController',
            superclass='UIViewController',
            methods=['viewDidLoad', 'viewWillAppear:', 'dealloc'],
            protocols=['UITableViewDataSource', 'UITableViewDelegate'],
            address=0x2000
        )

        self.assertEqual(objc_class.name, 'MyViewController')
        self.assertEqual(objc_class.superclass, 'UIViewController')
        self.assertIn('viewDidLoad', objc_class.methods)
        self.assertIn('UITableViewDataSource', objc_class.protocols)

    def test_sensitive_string(self):
        """测试敏感字符串类"""
        # 字段对齐模块 API：value/offset，无 score 字段
        ss = SensitiveString(
            value='secret_password',
            type='password',
            offset=0x1000
        )

        self.assertEqual(ss.value, 'secret_password')
        self.assertEqual(ss.type, 'password')
        self.assertEqual(ss.offset, 0x1000)

    def test_mobile_vulnerability(self):
        """测试移动漏洞类"""
        # 字段对齐模块 API：无 code_snippet/remediation 字段
        vuln = MobileVulnerability(
            type='HARDCODED_KEY',
            severity='High',
            description='硬编码的加密密钥',
            location='0x1000'
        )

        self.assertEqual(vuln.type, 'HARDCODED_KEY')
        self.assertEqual(vuln.severity, 'High')
        self.assertEqual(vuln.description, '硬编码的加密密钥')
        self.assertEqual(vuln.location, '0x1000')



if __name__ == '__main__':
    unittest.main()


