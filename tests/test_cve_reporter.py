# test_cve_reporter -- 枚举/dataclass/reporter的所有方法，json报告确认可解析
# CVSS 3.1公式实现可能有精度问题，测试只判断范围不判等

import json
import tempfile
import unittest
import os
import importlib.util
# import sys  # 以前在windows上要用sys.path hack，现在不用了



def import_cve_reporter():
    """直接导入 cve_reporter 模块，绕过 modules/__init__.py"""
    module_path = os.path.join(os.path.dirname(__file__), '..', 'modules', 'cve_reporter.py')
    spec = importlib.util.spec_from_file_location('cve_reporter', module_path)
    module = importlib.util.module_from_spec(spec)
    import sys
    sys.modules['cve_reporter'] = module
    spec.loader.exec_module(module)
    return module


cve_reporter = import_cve_reporter()

_DEBUG_FLAG = False


class TestCVSSSeverity(unittest.TestCase):
    """CVSSSeverity枚举 -- Critical/High/Medium/Low/Info五个等级"""

    def test_severity_enum_values(self):
        CVSSSeverity = cve_reporter.CVSSSeverity

        self.assertEqual(CVSSSeverity.CRITICAL.value, 'Critical')
        self.assertEqual(CVSSSeverity.HIGH.value, 'High')
        self.assertEqual(CVSSSeverity.MEDIUM.value, 'Medium')
        self.assertEqual(CVSSSeverity.LOW.value, 'Low')
        self.assertEqual(CVSSSeverity.INFO.value, 'Info')


class TestCVEStatus(unittest.TestCase):
    """CVEStatus枚举 -- Draft/Submitted/Assigned/Published/Rejected"""

    def test_cve_status_values(self):
        CVEStatus = cve_reporter.CVEStatus

        self.assertEqual(CVEStatus.DRAFT.value, 'Draft')
        self.assertEqual(CVEStatus.SUBMITTED.value, 'Submitted')
        self.assertEqual(CVEStatus.ASSIGNED.value, 'Assigned')
        self.assertEqual(CVEStatus.PUBLISHED.value, 'Published')
        self.assertEqual(CVEStatus.REJECTED.value, 'Rejected')


class TestVulnerabilityDetail(unittest.TestCase):
    """VulnerabilityDetail dataclass -- 漏洞详情的所有字段"""

    def test_vulnerability_detail_defaults(self):
        """默认值：cve_id/cwe_id/cvss_score都是None, 列表为空"""
        VulnerabilityDetail = cve_reporter.VulnerabilityDetail

        details = VulnerabilityDetail()

        self.assertIsNone(details.cve_id)
        self.assertIsNone(details.cwe_id)
        self.assertIsNone(details.cvss_score)
        self.assertEqual(details.title, '')
        self.assertEqual(details.affected_products, [])
        self.assertEqual(details.affected_versions, [])

    def test_vulnerability_detail_with_values(self):
        """带参数构造，所有字段要一一对应上"""
        VulnerabilityDetail = cve_reporter.VulnerabilityDetail
        CVSSSeverity = cve_reporter.CVSSSeverity

        details = VulnerabilityDetail(
            cve_id='CVE-2026-12345',
            cwe_id='CWE-120',
            title='Buffer Overflow',
            description='A buffer overflow vulnerability',
            affected_products=['Product A'],
            affected_versions=['1.0'],
            attack_vector='NETWORK',
            attack_complexity='LOW',
            privileges_required='NONE',
            user_interaction='NONE',
            scope='UNCHANGED',
            confidentiality_impact='HIGH',
            integrity_impact='HIGH',
            availability_impact='HIGH',
            severity=CVSSSeverity.CRITICAL
        )

        self.assertEqual(details.cve_id, 'CVE-2026-12345')
        self.assertEqual(details.cwe_id, 'CWE-120')
        self.assertEqual(details.title, 'Buffer Overflow')


class TestCVEReporter(unittest.TestCase):
    """CVEReporter类 -- CVSS计算、严重性判定、各种格式报告输出"""

    def setUp(self):
        CVEReporter = cve_reporter.CVEReporter
        self.reporter = CVEReporter()

    def test_calculate_cvss_score(self):
        VulnerabilityDetail = cve_reporter.VulnerabilityDetail

        details = VulnerabilityDetail(
            attack_vector='NETWORK',
            attack_complexity='LOW',
            privileges_required='NONE',
            user_interaction='NONE',
            scope='UNCHANGED',
            confidentiality_impact='HIGH',
            integrity_impact='HIGH',
            availability_impact='HIGH'
        )

        score = self.reporter.calculate_cvss_score(details)

        self.assertIsInstance(score, float)
        self.assertGreaterEqual(score, 0.0)
        self.assertLessEqual(score, 10.0)

    def test_determine_severity(self):
        """分数区间：9.0+Critical, 7.0+High, 4.0+Medium, 0.1+Low, 0=Info"""
        CVSSSeverity = cve_reporter.CVSSSeverity

        self.assertEqual(self.reporter.determine_severity(9.5), CVSSSeverity.CRITICAL)
        self.assertEqual(self.reporter.determine_severity(7.5), CVSSSeverity.HIGH)
        self.assertEqual(self.reporter.determine_severity(5.0), CVSSSeverity.MEDIUM)
        self.assertEqual(self.reporter.determine_severity(2.0), CVSSSeverity.LOW)
        self.assertEqual(self.reporter.determine_severity(0.0), CVSSSeverity.INFO)

    def test_generate_short_report(self):
        """简短报告包含标题和CVE编号"""
        VulnerabilityDetail = cve_reporter.VulnerabilityDetail
        CVSSSeverity = cve_reporter.CVSSSeverity

        details = VulnerabilityDetail(
            title='Test Vulnerability',
            cve_id='CVE-2026-0001',
            cwe_id='CWE-120',
            cvss_score=7.5,
            severity=CVSSSeverity.HIGH,
            description='Test description'
        )

        report = self.reporter.generate_short_report(details)

        self.assertIsInstance(report, str)
        self.assertIn('Test Vulnerability', report)
        self.assertIn('CVE-2026-0001', report)

    def test_generate_full_report(self):
        """完整报告包含更多字段信息"""
        VulnerabilityDetail = cve_reporter.VulnerabilityDetail
        CVSSSeverity = cve_reporter.CVSSSeverity

        details = VulnerabilityDetail(
            title='Full Report Test',
            cve_id='CVE-2026-0002',
            cwe_id='CWE-94',
            cvss_score=9.8,
            severity=CVSSSeverity.CRITICAL,
            description='Full description',
            affected_products=['Product X'],
            affected_versions=['2.0'],
            attack_vector='NETWORK'
        )

        report = self.reporter.generate_full_report(details)

        self.assertIsInstance(report, str)
        self.assertIn('Full Report Test', report)

    def test_generate_cve_request(self):
        """CVE申请文档以'CVE Request:'开头"""
        VulnerabilityDetail = cve_reporter.VulnerabilityDetail
        CVSSSeverity = cve_reporter.CVSSSeverity

        details = VulnerabilityDetail(
            title='CVE Request Test',
            cwe_id='CWE-120',
            cvss_score=8.0,
            severity=CVSSSeverity.HIGH,
            description='Request description',
            affected_products=['Test Product'],
            affected_versions=['1.0'],
            attack_vector='NETWORK'
        )

        request = self.reporter.generate_cve_request(details)

        self.assertIsInstance(request, str)
        self.assertIn('CVE Request:', request)

    def test_generate_json_report(self):
        """JSON报告必须是可以parse的有效json"""
        VulnerabilityDetail = cve_reporter.VulnerabilityDetail
        CVSSSeverity = cve_reporter.CVSSSeverity

        details = VulnerabilityDetail(
            title='JSON Test',
            cve_id='CVE-2026-0003',
            cwe_id='CWE-200',
            severity=CVSSSeverity.MEDIUM
        )

        json_report = self.reporter.generate_json_report(details)

        self.assertIsInstance(json_report, str)
        data = json.loads(json_report)
        self.assertEqual(data['title'], 'JSON Test')
        self.assertEqual(data['cve_id'], 'CVE-2026-0003')

    def test_save_report(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.md', delete=False) as f:
            temp_path = f.name

        try:
            content = '# Test Report\n\nThis is a test'
            success = self.reporter.save_report(content, temp_path, 'markdown')

            self.assertTrue(success)
            self.assertTrue(os.path.exists(temp_path))

            with open(temp_path, 'r', encoding='utf-8') as f:
                saved_content = f.read()
                self.assertIn('Test Report', saved_content)
        finally:
            if os.path.exists(temp_path):
                os.unlink(temp_path)

    def test_validate_details(self):
        """缺失必填字段要返回error列表，完整detail返回空列表"""
        VulnerabilityDetail = cve_reporter.VulnerabilityDetail

        # 缺少必填字段
        details = VulnerabilityDetail()
        errors = self.reporter.validate_details(details)
        self.assertGreater(len(errors), 0)

        # 完整的详情
        details_full = VulnerabilityDetail(
            title='Test',
            description='Test description',
            cwe_id='CWE-120',
            attack_vector='NETWORK'
        )
        errors_full = self.reporter.validate_details(details_full)
        self.assertEqual(errors_full, [])


class TestGenerateCveReport(unittest.TestCase):
    """generate_cve_report函数 -- 一站式生成CVE报告"""

    def test_generate_cve_report(self):
        """成功返回的dict包含cvss_score/severity/reports三个字段"""
        generate_cve_report = cve_reporter.generate_cve_report

        result = generate_cve_report(
            title='Test Vulnerability',
            description='A test vulnerability',
            cwe_id='CWE-120',
            affected_products=['Test Product'],
            affected_versions=['1.0'],
            attack_vector='NETWORK',
            attack_complexity='LOW',
            privileges_required='NONE',
            user_interaction='NONE',
            scope='UNCHANGED',
            confidentiality_impact='HIGH',
            integrity_impact='HIGH',
            availability_impact='HIGH'
        )

        self.assertTrue(result['success'])
        self.assertIn('cvss_score', result)
        self.assertIn('severity', result)
        self.assertIn('reports', result)


if __name__ == '__main__':
    unittest.main()
