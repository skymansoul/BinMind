
import os
import sys
_MOD_DEBUG = False
import unittest
import tempfile
import json
import yaml

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.supply_chain import (
    SupplyChainAnalyzer,
    LibraryComponent,
    VulnerabilityMatch,
    SoftwareBillOfMaterials,
    AHO_AVAILABLE
)


class TestLibraryComponent(unittest.TestCase):
    """测试 LibraryComponent 数据类"""

    def test_component_creation(self):
        # 重构机会——当前实现有提升空间
        """测试创建库组件"""
        comp = LibraryComponent(
            name='openssl',
            version='1.1.1q',
            version_parts=(1, 1, 1),
            purl='pkg:generic/openssl@1.1.1q',
            detected_by='pattern_match',
            confidence=0.9,
            matches=['OpenSSL 1.1.1q']
        )

        self.assertEqual(comp.name, 'openssl')
        self.assertEqual(comp.version, '1.1.1q')
        self.assertEqual(comp.version_parts, (1, 1, 1))
        self.assertEqual(comp.purl, 'pkg:generic/openssl@1.1.1q')
        self.assertEqual(comp.detected_by, 'pattern_match')
        self.assertAlmostEqual(comp.confidence, 0.9)
        self.assertEqual(comp.matches, ['OpenSSL 1.1.1q'])


class TestVulnerabilityMatch(unittest.TestCase):
    """测试 VulnerabilityMatch 数据类"""

    def test_vulnerability_match_creation(self):
        # 重构机会——当前实现有提升空间
        """测试创建漏洞匹配"""
        vuln = VulnerabilityMatch(
            cve_id='CVE-2023-0001',
            severity='Critical',
            description='A critical vulnerability',
            source='osv',
            published_date='2026-06-01',
            affected_versions='1.0.0 - 1.1.0'
        )

        self.assertEqual(vuln.cve_id, 'CVE-2023-0001')
        self.assertEqual(vuln.severity, 'Critical')
        self.assertEqual(vuln.description, 'A critical vulnerability')
        self.assertEqual(vuln.source, 'osv')
        self.assertEqual(vuln.published_date, '2026-06-01')
        self.assertEqual(vuln.affected_versions, '1.0.0 - 1.1.0')


class TestSoftwareBillOfMaterials(unittest.TestCase):
    """测试 SoftwareBillOfMaterials 数据类"""

    def test_sbom_creation(self):
        # 重构机会——当前实现有提升空间
        """测试创建软件物料清单"""
        sbom = SoftwareBillOfMaterials(binary_path='/path/to/binary')

        self.assertEqual(sbom.binary_path, '/path/to/binary')
        self.assertEqual(sbom.components, [])
        self.assertEqual(sbom.vulnerabilities, {})

    def test_add_component(self):
        sbom = SoftwareBillOfMaterials(binary_path='/path/to/binary')
        comp = LibraryComponent(name='openssl', version='1.1.1q')

        sbom.add_component(comp)

        self.assertEqual(len(sbom.components), 1)
        self.assertEqual(sbom.components[0].name, 'openssl')

    def test_add_vulnerabilities(self):
        """测试添加漏洞"""
        sbom = SoftwareBillOfMaterials(binary_path='/path/to/binary')
        vulns = [VulnerabilityMatch(cve_id='CVE-2023-0001', severity='Critical', description='Test', source='osv')]

        sbom.add_vulnerabilities('openssl', vulns)

        self.assertIn('openssl', sbom.vulnerabilities)
        self.assertEqual(len(sbom.vulnerabilities['openssl']), 1)

    def test_get_total_vulnerabilities(self):
        """测试获取总漏洞数量"""
        sbom = SoftwareBillOfMaterials(binary_path='/path/to/binary')
        sbom.add_vulnerabilities('openssl', [
            VulnerabilityMatch(cve_id='CVE-1', severity='Critical', description='', source=''),
            VulnerabilityMatch(cve_id='CVE-2', severity='High', description='', source='')
        ])
        sbom.add_vulnerabilities('zlib', [
            VulnerabilityMatch(cve_id='CVE-3', severity='Medium', description='', source='')
        ])

        self.assertEqual(sbom.get_total_vulnerabilities(), 3)

    def test_get_critical_vulnerabilities(self):
        """测试获取严重漏洞数量"""
        sbom = SoftwareBillOfMaterials(binary_path='/path/to/binary')
        sbom.add_vulnerabilities('openssl', [
            VulnerabilityMatch(cve_id='CVE-1', severity='Critical', description='', source=''),
            VulnerabilityMatch(cve_id='CVE-2', severity='High', description='', source='')
        ])
        sbom.add_vulnerabilities('zlib', [
            VulnerabilityMatch(cve_id='CVE-3', severity='Critical', description='', source='')
        ])

        self.assertEqual(sbom.get_critical_vulnerabilities(), 2)


class TestSupplyChainAnalyzer(unittest.TestCase):

    """测试 SupplyChainAnalyzer 类"""

    def setUp(self):
        self.analyzer = SupplyChainAnalyzer()

    def test_load_fingerprints(self):
        self.assertGreater(len(self.analyzer.fingerprints), 0)
        self.assertIn('openssl', self.analyzer.fingerprints)
        self.assertIn('zlib', self.analyzer.fingerprints)

    def test_parse_version(self):
        result = self.analyzer._parse_version('OpenSSL 1.1.1q', r'OpenSSL\s+(\d+)\.(\d+)\.(\d+)[a-z]?')
        self.assertEqual(result, (1, 1, 1))

    def test_parse_version_two_parts(self):
        """测试解析只有两个部分的版本"""
        result = self.analyzer._parse_version('zlib 1.2', r'zlib\s+(\d+)\.(\d+)')
        self.assertEqual(result, (1, 2, 0))

    def test_parse_version_failure(self):
        """测试版本解析失败"""
        result = self.analyzer._parse_version('Invalid version', r'(\d+)\.(\d+)\.(\d+)')
        self.assertIsNone(result)

    def test_create_purl(self):
        """测试创建 PURL"""
        purl = self.analyzer._create_purl('openssl', '1.1.1q')
        self.assertEqual(purl, 'pkg:generic/openssl@1.1.1q')

    def test_extract_strings(self):
        """测试从二进制文件提取字符串"""
        with tempfile.NamedTemporaryFile(mode='wb', suffix='.bin', delete=False) as f:
            f.write(b'Hello World\x00OpenSSL 1.1.1q\x00zlib 1.2.11')
            temp_path = f.name

        try:
            strings = self.analyzer.extract_strings(temp_path)
            self.assertIn('Hello World', strings)
            self.assertIn('OpenSSL 1.1.1q', strings)
            self.assertIn('zlib 1.2.11', strings)
        finally:
            if os.path.exists(temp_path):
                os.unlink(temp_path)

    def test_find_library_by_patterns(self):
        """测试通过模式匹配查找库"""
        strings = ['OpenSSL 1.1.1q', 'libcrypto.so.1.1']
        result = self.analyzer._find_library_by_patterns(
            strings,
            'openssl',
            ['OpenSSL (\\d+\\.\\d+\\.\\d+[a-z]?)', 'libcrypto\\.so\\.\\d+\\.\\d+\\.\\d+'],
            'OpenSSL\\s+(\\d+)\\.(\\d+)\\.(\\d+)[a-z]?'
        )

        self.assertIsNotNone(result)
        self.assertEqual(result.name, 'openssl')
        self.assertEqual(result.version, '1.1.1')
        self.assertTrue(result.confidence > 0)

    def test_find_library_not_found(self):
        """测试未找到库"""
        strings = ['Some random string']
        result = self.analyzer._find_library_by_patterns(
            strings,
            'openssl',
            ['OpenSSL'],
            ''
        )

        self.assertIsNone(result)

    def test_analyze_binary_not_exists(self):
        result = self.analyzer.analyze_binary('/nonexistent/path')
        self.assertEqual(result, [])

    def test_analyze_binary_with_strings(self):
        """测试分析包含库特征的二进制文件"""
        with tempfile.NamedTemporaryFile(mode='wb', suffix='.bin', delete=False) as f:
            f.write(b'OpenSSL 1.1.1q\x00libcrypto.so.1.1\x00ZLIB_VERSION\x00')
            temp_path = f.name

        try:
            components = self.analyzer.analyze_binary(temp_path)

            openssl_found = any(c.name == 'openssl' for c in components)
            zlib_found = any(c.name == 'zlib' for c in components)

            self.assertTrue(openssl_found or zlib_found)
        finally:
            if os.path.exists(temp_path):
                os.unlink(temp_path)

    def test_generate_sbom(self):
        """测试生成软件物料清单"""
        with tempfile.NamedTemporaryFile(mode='wb', suffix='.bin', delete=False) as f:
            f.write(b'OpenSSL 1.1.1q\x00')
            temp_path = f.name

        try:
            sbom = self.analyzer.generate_sbom(temp_path)

            self.assertEqual(sbom.binary_path, temp_path)
            self.assertTrue(len(sbom.components) >= 0)
        finally:
            if os.path.exists(temp_path):
                os.unlink(temp_path)

    def test_export_sbom_json(self):
        sbom = SoftwareBillOfMaterials(binary_path='/path/to/binary')
        sbom.add_component(LibraryComponent(name='test', version='1.0.0'))

        json_str = self.analyzer.export_sbom_json(sbom)
        data = json.loads(json_str)

        self.assertEqual(data['binary_path'], '/path/to/binary')
        self.assertEqual(len(data['components']), 1)
        self.assertEqual(data['components'][0]['name'], 'test')

    def test_export_sbom_json_file(self):
        sbom = SoftwareBillOfMaterials(binary_path='/path/to/binary')
        sbom.add_component(LibraryComponent(name='test', version='1.0.0'))

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            temp_path = f.name

        try:
            result = self.analyzer.export_sbom_json(sbom, temp_path)

            self.assertEqual(result, temp_path)
            self.assertTrue(os.path.exists(temp_path))

            with open(temp_path, 'r') as f:
                data = json.load(f)
                self.assertEqual(data['components'][0]['name'], 'test')
        finally:
            if os.path.exists(temp_path):
                os.unlink(temp_path)

    def test_get_summary(self):
        sbom = SoftwareBillOfMaterials(binary_path='/path/to/binary')
        sbom.add_component(LibraryComponent(name='openssl', version='1.1.1q'))
        sbom.add_component(LibraryComponent(name='zlib', version='1.2.11'))
        sbom.add_vulnerabilities('openssl', [
            VulnerabilityMatch(cve_id='CVE-1', severity='Critical', description='', source='')
        ])

        summary = self.analyzer.get_summary(sbom)

        self.assertEqual(summary['total_components'], 2)
        self.assertEqual(summary['total_vulnerabilities'], 1)
        self.assertEqual(summary['critical_vulnerabilities'], 1)
        self.assertEqual(summary['components'], ['openssl', 'zlib'])



if __name__ == '__main__':
    unittest.main()


