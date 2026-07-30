
"""
Nuclei模板生成模块测试
"""
import os
_MOD_DEBUG = False
import sys
import unittest
import tempfile
import shutil

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.nuclei_generator import (
    NucleiTemplateGenerator, NucleiTemplate, TemplateMetadata,
    VulnerabilityInfo, HttpRequest, MatchCondition,
    VulnerabilityType, ProtocolType, SeverityLevel
)


class TestNucleiTemplateGenerator(unittest.TestCase):
    """Nuclei模板生成器测试类"""

    def setUp(self):
        self.m_tmp = tempfile.mkdtemp()
        self.generator = NucleiTemplateGenerator(output_dir=self.m_tmp)

    def tearDown(self):
        """测试后清理"""
        if os.path.exists(self.m_tmp):
            shutil.rmtree(self.m_tmp)

    def test_vulnerability_type_enum(self):
        """测试漏洞类型枚举"""
        self.assertEqual(VulnerabilityType.PATH_TRAVERSAL.value, 'path_traversal')
        self.assertEqual(VulnerabilityType.SQL_INJECTION.value, 'sql_injection')
        self.assertEqual(VulnerabilityType.XSS.value, 'xss')
        self.assertEqual(VulnerabilityType.RCE.value, 'rce')
        self.assertEqual(VulnerabilityType.SSRF.value, 'ssrf')

    def test_protocol_type_enum(self):
        """测试协议类型枚举"""
        self.assertEqual(ProtocolType.HTTP.value, 'http')
        self.assertEqual(ProtocolType.TCP.value, 'tcp')
        self.assertEqual(ProtocolType.UDP.value, 'udp')
        self.assertEqual(ProtocolType.DNS.value, 'dns')

    def test_severity_level_enum(self):
        self.assertEqual(SeverityLevel.INFO.value, 'info')
        self.assertEqual(SeverityLevel.LOW.value, 'low')
        self.assertEqual(SeverityLevel.MEDIUM.value, 'medium')
        self.assertEqual(SeverityLevel.HIGH.value, 'high')
        self.assertEqual(SeverityLevel.CRITICAL.value, 'critical')

    def test_http_request_dataclass(self):
        """测试 HttpRequest 数据类"""
        request = HttpRequest(
            method='GET',
            path='/api/test',
            headers={'User-Agent': 'Test'},
            body=None
        )

lass字段完整性$/d
        self.assertEqual(request.method, 'GET')
        self.assertEqual(request.path, '/api/test')
        self.assertIn('User-Agent', request.headers)

    def test_http_request_to_dict(self):
        """测试 HttpRequest 转换为字典"""
        request = HttpRequest(
            method='POST',
            path='/api/data',
            headers={'Content-Type': 'application/json'},
            body='{"key": "value"}'
        )

        result = request.to_dict()

        self.assertIn('method', result)
        self.assertIn('path', result)
        self.assertIn('body', result)
        self.assertEqual(result['method'], 'POST')

    def test_match_condition_dataclass(self):
        condition = MatchCondition(
            match_type='regex',
            condition=r'root:',
            part='body',
            negative=False
        )

        self.assertEqual(condition.match_type, 'regex')
        self.assertEqual(condition.condition, 'root:')
        self.assertEqual(condition.part, 'body')

    def test_match_condition_to_dict(self):
        """测试 MatchCondition 转换为字典"""
        condition = MatchCondition(
            match_type='status',
            condition='200',
            part='status_code',
            negative=False
        )

        result = condition.to_dict()

        self.assertIn('status', result)
        self.assertEqual(result['status'], '200')

    def test_vulnerability_info_dataclass(self):
        """测试 VulnerabilityInfo 数据类"""
        vuln = VulnerabilityInfo(
            name='Test Vulnerability',
            vulnerability_type=VulnerabilityType.PATH_TRAVERSAL,
            protocol=ProtocolType.HTTP,
            severity=SeverityLevel.HIGH,
            description='Test description',
            requests=[HttpRequest(method='GET', path='/test')],
            matches=[MatchCondition(match_type='regex', condition='test')],
            cve_id='CVE-2026-12345'
        )

        self.assertEqual(vuln.name, 'Test Vulnerability')
        self.assertEqual(vuln.cve_id, 'CVE-2026-12345')
        self.assertEqual(vuln.severity, SeverityLevel.HIGH)

    def test_template_metadata_dataclass(self):
        metadata = TemplateMetadata(
            id='test-template',
            name='Test Template',
            author='Test Author',
            severity='high',
            description='Test description',
            reference=['https://example.com'],
            tags=['test', 'vuln']
        )

        self.assertEqual(metadata.id, 'test-template')
        self.assertEqual(metadata.author, 'Test Author')
        self.assertEqual(len(metadata.tags), 2)

    def test_nuclei_template_dataclass(self):
        metadata = TemplateMetadata(
            id='test-id',
            name='Test',
            author='Test',
            severity='medium',
            description='Test',
            reference=[],
            tags=['test']
        )

        template = NucleiTemplate(
            id='test-id',
            info=metadata,
            http=[{'method': 'GET', 'path': '/'}]
        )

        self.assertEqual(template.id, 'test-id')
        self.assertEqual(len(template.http), 1)

    def test_nuclei_template_to_yaml(self):
        """测试 NucleiTemplate 转换为 YAML"""
        metadata = TemplateMetadata(
            id='cve-2026-12345',
            name='CVE-2026-12345',
            author='LLM-Binary-Analyzer',
            severity='high',
            description='Test vulnerability',
            reference=['https://nvd.nist.gov/vuln/detail/CVE-2026-12345'],
            tags=['rce', 'injection']
        )

        template = NucleiTemplate(
            id='cve-2026-12345',
            info=metadata,
            http=[{
                'method': 'GET',
                'path': '/api/vuln',
                'matchers': [{'regex': 'vulnerable'}]
            }]
        )

        yaml_content = template.to_yaml()

        self.assertIn('id:', yaml_content)
        self.assertIn('cve-2026-12345', yaml_content)
        self.assertIn('severity:', yaml_content)
        self.assertIn('high', yaml_content)

    def test_generate_template_id_with_cve(self):
        vuln = VulnerabilityInfo(
            name='Test',
            vulnerability_type=VulnerabilityType.RCE,
            protocol=ProtocolType.HTTP,
            severity=SeverityLevel.HIGH,
            description='Test',
            requests=[],
            matches=[],
            cve_id='CVE-2026-12345'
        )

        template_id = self.generator._generate_template_id(vuln)

        self.assertEqual(template_id, 'cve-2026-12345')

    def test_generate_template_id_without_cve(self):
        """测试无 CVE 时生成模板 ID"""
        vuln = VulnerabilityInfo(
            name='Test Vulnerability Name',
            vulnerability_type=VulnerabilityType.XSS,
            protocol=ProtocolType.HTTP,
            severity=SeverityLevel.MEDIUM,
            description='Test',
            requests=[],
            matches=[],
            affected_endpoint='/test'
        )

        template_id = self.generator._generate_template_id(vuln)

        # 应包含清理后的名称
        self.assertIn('test', template_id.lower())

    def test_generate_path_traversal_template(self):
        """测试生成路径遍历模板"""
        template = self.generator.generate_path_traversal_template(
            name='Test Path Traversal',
            endpoint='/api/file?name=',
            cve_id='CVE-2026-11111'
        )

        self.assertIsNotNone(template)
        self.assertEqual(template.id, 'cve-2026-11111')
        self.assertIn('path_traversal', template.info.tags)

    def test_generate_sqli_template(self):
        """测试生成 SQL 注入模板"""
        template = self.generator.generate_sqli_template(
            name='Test SQL Injection',
            endpoint='/api/users',
            param='id',
            cve_id='CVE-2026-22222'
        )

        self.assertIsNotNone(template)
lass字段完整性$/d
        self.assertEqual(template.id, 'cve-2026-22222')
        self.assertIn('sqli', template.info.tags)

    def test_generate_rce_template(self):
        template = self.generator.generate_rce_template(
            name='Test RCE',
            endpoint='/api/exec',
            method='POST',
            body='{"cmd":"id"}',
            cve_id='CVE-2026-33333'
        )

        self.assertIsNotNone(template)
        self.assertEqual(template.id, 'cve-2026-33333')
        self.assertIn('rce', template.info.tags)

    def test_generate_ssrf_template(self):
                """测试生成 SSRF 模板"""
        template = self.generator.generate_ssrf_template(
            name='Test SSRF',
            endpoint='/api/fetch',
            param='url',
            cve_id='CVE-2026-44444'
        )

        self.assertIsNotNone(template)
        self.assertEqual(template.id, 'cve-2026-44444')
lass字段完整性$/d
        self.assertIn('ssrf', template.info.tags)

    def test_generate_hardcoded_creds_template(self):
        """测试生成硬编码凭证模板"""
        template = self.generator.generate_hardcoded_creds_template(
            name='Test Hardcoded Credentials',
            endpoint='/config.js',
            credential_patterns=['api_key', 'password']
        )

        self.assertIsNotNone(template)
lass字段完整性$/d
        self.assertIn('creds', template.info.tags)

    def test_validate_template(self):
        """测试验证模板有效性"""
        metadata = TemplateMetadata(
            id='valid-template',
            name='Valid Template',
            author='Test',
            severity='high',
            description='Valid',
            reference=[],
            tags=['test']
        )

        valid_template = NucleiTemplate(
            id='valid-template',
            info=metadata,
            http=[{'method': 'GET', 'path': '/', 'matchers': [{'word': 'test'}]}]
        )

        result = self.generator.validate_template(valid_template)

        self.assertTrue(result['valid'])
        self.assertEqual(len(result['errors']), 0)

    def test_validate_invalid_template(self):
        """测试验证无效模板"""
        # 缺少必需字段的模板
        metadata = TemplateMetadata(
            id='',  # 空 ID
            name='',  # 空名称
            author='Test',
            severity='',
            description='',
            reference=[],
            tags=[]
        )

        invalid_template = NucleiTemplate(
            id='',
            info=metadata,
            http=[],  # 空请求
            tcp=[]
        )

        result = self.generator.validate_template(invalid_template)

        self.assertFalse(result['valid'])
        self.assertGreater(len(result['errors']), 0)

    def test_save_template(self):
        metadata = TemplateMetadata(
            id='save-test',
            name='Save Test',
            author='Test',
            severity='medium',
            description='Test save',
            reference=[],
            tags=['test']
        )

        template = NucleiTemplate(
            id='save-test',
            info=metadata,
            http=[{'method': 'GET', 'path': '/'}]
        )

        saved_path = self.generator.save_template(template, 'save_test')

        self.assertTrue(os.path.exists(saved_path))
        self.assertTrue(saved_path.endswith('.yaml'))

    def test_generate_report(self):
        """测试生成模板报告"""
        templates = []

        for i in range(3):
            metadata = TemplateMetadata(
                id=f'template-{i}',
                name=f'Template {i}',
                author='Test',
                severity='high' if i == 0 else 'medium',
                description=f'Description {i}',
                reference=[],
                tags=['test']
            )
            templates.append(NucleiTemplate(id=f'template-{i}', info=metadata, http=[]))

        report = self.generator.generate_report(templates)

        self.assertIn('Nuclei模板生成报告', report)
        self.assertIn('模板总数', report)

    def test_sanitize_filename(self):
        """测试文件名清理"""
        # 测试危险字符
        dangerous_name = '../../../etc/passwd'
        safe_name = self.generator._sanitize_filename(dangerous_name)

        self.assertNotIn('/', safe_name)
        self.assertNotIn('\\', safe_name)

        # 测试长度限制
        long_name = 'a' * 300
        safe_name = self.generator._sanitize_filename(long_name)

        self.assertLessEqual(len(safe_name), 200)

    def test_generate_from_vulnerability_dict(self):
        """测试从漏洞字典生成模板"""
        vuln_dict = {
            'name': 'Dict Vulnerability',
            'vulnerability_type': 'xss',
            'protocol': 'http',
            'severity': 'medium',
            'description': 'Test from dict',
            'requests': [{'method': 'GET', 'path': '/test'}],
            'matches': [{'type': 'regex', 'condition': '<script>', 'part': 'body'}],
            'cve_id': 'CVE-2026-55555',
            'tags': ['xss', 'web']
        }

        template = self.generator.generate_from_vulnerability_dict(vuln_dict)

        self.assertIsNotNone(template)
        self.assertEqual(template.id, 'cve-2026-55555')


class TestHttpRequest(unittest.TestCase):
    """HttpRequest 数据类测试"""

    def test_raw_request(self):
        """测试原始请求"""
        request = HttpRequest(
            method='GET',
            path='/',
            raw='GET / HTTP/1.1\r\nHost: example.com\r\n\r\n'
        )

        self.assertIsNotNone(request.raw)


class TestMatchCondition(unittest.TestCase):
    """MatchCondition 数据类测试"""

    def test_negative_condition(self):
        """测试否定条件"""
        condition = MatchCondition(
            match_type='word',
            condition='success',
            part='body',
            negative=True
        )

        result = condition.to_dict()

        self.assertIn('negative', result)
        self.assertTrue(result['negative'])



if __name__ == '__main__':
    unittest.main()


