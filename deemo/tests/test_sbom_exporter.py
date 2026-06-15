"""
SBOM 标准化导出模块单元测试
"""

import os
import sys
import tempfile
import unittest
import json
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.sbom_exporter import (
    SBOMExporter,
    SBOMDocument,
    SBOMComponent,
    export_sbom_from_analysis
)


class TestSBOMComponent(unittest.TestCase):
    """测试 SBOM 组件"""
    
    def test_init(self):
        """测试初始化"""
        comp = SBOMComponent(name="test-lib", version="1.0.0")
        self.assertEqual(comp.name, "test-lib")
        self.assertEqual(comp.version, "1.0.0")
        self.assertEqual(comp.license, "NOASSERTION")
    
    def test_with_data(self):
        """测试带数据初始化"""
        comp = SBOMComponent(
            name="openssl",
            version="1.1.1",
            purl="pkg:generic/openssl@1.1.1",
            license="Apache-2.0",
            sha256="abc123",
            vulnerabilities=[{'cve_id': 'CVE-2021-1234'}]
        )
        self.assertEqual(comp.purl, "pkg:generic/openssl@1.1.1")
        self.assertEqual(comp.license, "Apache-2.0")
        self.assertEqual(len(comp.vulnerabilities), 1)


class TestSBOMDocument(unittest.TestCase):
    """测试 SBOM 文档"""
    
    def test_init(self):
        """测试初始化"""
        doc = SBOMDocument(name="test-app")
        self.assertEqual(doc.name, "test-app")
        self.assertEqual(doc.author, "deemo-analyzer")
        self.assertEqual(doc.tool, "LLM-Assisted Binary Vulnerability Analysis Tool")
    
    def test_with_components(self):
        """测试带组件初始化"""
        comp1 = SBOMComponent(name="main", version="1.0")
        comp2 = SBOMComponent(name="lib", version="2.0")
        
        doc = SBOMDocument(
            name="test-app",
            components=[comp1, comp2]
        )
        
        self.assertEqual(len(doc.components), 2)


class TestSBOMExporter(unittest.TestCase):
    """测试 SBOM 导出器"""
    
    def setUp(self):
        """设置测试环境"""
        self.temp_dir = tempfile.mkdtemp()
        self.exporter = SBOMExporter(output_dir=self.temp_dir)
        
        # 创建临时二进制文件
        self.temp_binary = os.path.join(self.temp_dir, 'test_binary')
        with open(self.temp_binary, 'wb') as f:
            f.write(b'\x00' * 100)
    
    def tearDown(self):
        """清理测试环境"""
        import shutil
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)
    
    def test_init(self):
        """测试初始化"""
        self.assertIsNotNone(self.exporter.output_dir)
        self.assertTrue(os.path.exists(self.output_dir))
    
    def test_normalize_license(self):
        """测试许可证标准化"""
        self.assertEqual(self.exporter._normalize_license('apache'), 'Apache-2.0')
        self.assertEqual(self.exporter._normalize_license('MIT'), 'MIT')
        self.assertEqual(self.exporter._normalize_license('GPL-3.0'), 'GPL-3.0')
        self.assertEqual(self.exporter._normalize_license(''), 'NOASSERTION')
        self.assertEqual(self.exporter._normalize_license('unknown'), 'NOASSERTION')
    
    def test_normalize_severity(self):
        """测试严重程度标准化"""
        self.assertEqual(self.exporter._normalize_severity('Critical'), 'critical')
        self.assertEqual(self.exporter._normalize_severity('High'), 'high')
        self.assertEqual(self.exporter._normalize_severity('Medium'), 'medium')
        self.assertEqual(self.exporter._normalize_severity('Low'), 'low')
        self.assertEqual(self.exporter._normalize_severity('Unknown'), 'unknown')
    
    def test_generate_spdx_id(self):
        """测试 SPDX ID 生成"""
        spdx_id = self.exporter._generate_spdx_id('test-lib')
        self.assertTrue(spdx_id.startswith('SPDXRef-'))
        self.assertIn('test', spdx_id.lower())
    
    def test_generate_cyclonedx_bom_ref(self):
        """测试 CycloneDX bom-ref 生成"""
        bom_ref = self.exporter._generate_cyclonedx_bom_ref('test-lib', '1.0')
        # 应为 UUID 格式
        self.assertEqual(len(bom_ref), 36)  # UUID 格式长度
        self.assertIn('-', bom_ref)
    
    def test_calculate_file_hashes(self):
        """测试文件哈希计算"""
        hashes = self.exporter._calculate_file_hashes(self.temp_binary)
        
        self.assertIn('sha256', hashes)
        self.assertIn('sha1', hashes)
        self.assertIn('md5', hashes)
        
        self.assertEqual(len(hashes['sha256']), 64)
        self.assertEqual(len(hashes['sha1']), 40)
        self.assertEqual(len(hashes['md5']), 32)
    
    def test_calculate_file_hashes_not_exists(self):
        """测试不存在文件的哈希计算"""
        hashes = self.exporter._calculate_file_hashes('/nonexistent/file')
        self.assertEqual(hashes['sha256'], '')
        self.assertEqual(hashes['sha1'], '')
        self.assertEqual(hashes['md5'], '')
    
    def test_build_sbom_document(self):
        """测试构建 SBOM 文档"""
        binary_info = {
            'arch': 'x86_64',
            'bits': 64,
            'format': 'ELF',
            'version': '1.0'
        }
        
        supply_chain_result = {
            'components': [
                {'name': 'openssl', 'version': '1.1.1', 'purl': 'pkg:generic/openssl@1.1.1'}
            ],
            'vulnerabilities': {
                'openssl': [
                    {'cve_id': 'CVE-2021-1234', 'severity': 'High'}
                ]
            }
        }
        
        document = self.exporter.build_sbom_document(
            binary_path=self.temp_binary,
            binary_info=binary_info,
            supply_chain_result=supply_chain_result
        )
        
        self.assertEqual(document.name, 'test_binary')
        self.assertGreater(len(document.components), 0)
    
    def test_export_spdx_json(self):
        """测试导出 SPDX JSON"""
        document = SBOMDocument(
            name="test-app",
            components=[
                SBOMComponent(name="main", version="1.0", sha256="abc123"),
                SBOMComponent(name="lib", version="2.0", license="MIT")
            ]
        )
        
        spdx_path = os.path.join(self.temp_dir, 'test_spdx.json')
        result = self.exporter.export_spdx_json(document, spdx_path)
        
        self.assertTrue(os.path.exists(spdx_path))
        
        # 验证 JSON 结构
        with open(spdx_path, 'r') as f:
            data = json.load(f)
        
        self.assertEqual(data['spdxVersion'], 'SPDX-2.3')
        self.assertEqual(data['bomFormat'], None)  # SPDX 没有 bomFormat
        self.assertIn('packages', data)
        self.assertEqual(len(data['packages']), 2)
    
    def test_export_cyclonedx_json(self):
        """测试导出 CycloneDX JSON"""
        document = SBOMDocument(
            name="test-app",
            components=[
                SBOMComponent(name="main", version="1.0", sha256="abc123"),
                SBOMComponent(name="lib", version="2.0", license="MIT")
            ]
        )
        
        cyclonedx_path = os.path.join(self.temp_dir, 'test_cyclonedx.json')
        result = self.exporter.export_cyclonedx_json(document, cyclonedx_path)
        
        self.assertTrue(os.path.exists(cyclonedx_path))
        
        # 验证 JSON 结构
        with open(cyclonedx_path, 'r') as f:
            data = json.load(f)
        
        self.assertEqual(data['bomFormat'], 'CycloneDX')
        self.assertEqual(data['specVersion'], '1.4')
        self.assertIn('components', data)
        self.assertEqual(len(data['components']), 2)
    
    def test_export_sbom_both(self):
        """测试同时导出两种格式"""
        binary_info = {'arch': 'x86_64', 'bits': 64}
        
        results = self.exporter.export_sbom(
            binary_path=self.temp_binary,
            binary_info=binary_info,
            format='both',
            output_dir=self.temp_dir
        )
        
        self.assertIn('spdx', results)
        self.assertIn('cyclonedx', results)
    
    def test_export_sbom_spdx_only(self):
        """测试仅导出 SPDX"""
        binary_info = {'arch': 'x86_64'}
        
        results = self.exporter.export_sbom(
            binary_path=self.temp_binary,
            binary_info=binary_info,
            format='spdx',
            output_dir=self.temp_dir
        )
        
        self.assertIn('spdx', results)
        self.assertNotIn('cyclonedx', results)
    
    def test_validate_spdx_json(self):
        """测试验证 SPDX JSON"""
        # 有效的 SPDX
        valid_spdx = json.dumps({
            'spdxVersion': 'SPDX-2.3',
            'dataLicense': 'CC0-1.0',
            'SPDXID': 'SPDXRef-DOCUMENT',
            'name': 'test',
            'documentNamespace': 'https://test.org',
            'creationInfo': {'created': '2024-01-01'},
            'packages': [{'SPDXID': 'SPDXRef-1', 'name': 'test', 'downloadLocation': 'NONE', 'licenseConcluded': 'MIT'}]
        })
        
        result = self.exporter.validate_spdx_json(valid_spdx)
        self.assertTrue(result['valid'])
    
    def test_validate_spdx_json_invalid(self):
        """测试验证无效 SPDX JSON"""
        invalid_spdx = json.dumps({'spdxVersion': 'SPDX-2.3'})  # 缺少必需字段
        
        result = self.exporter.validate_spdx_json(invalid_spdx)
        self.assertFalse(result['valid'])
        self.assertGreater(len(result['errors']), 0)
    
    def test_validate_cyclonedx_json(self):
        """测试验证 CycloneDX JSON"""
        valid_cyclonedx = json.dumps({
            'bomFormat': 'CycloneDX',
            'specVersion': '1.4',
            'serialNumber': 'urn:uuid:test',
            'version': 1,
            'metadata': {},
            'components': [{'type': 'library', 'name': 'test', 'bom-ref': 'test-1'}]
        })
        
        result = self.exporter.validate_cyclonedx_json(valid_cyclonedx)
        self.assertTrue(result['valid'])
    
    def test_validate_cyclonedx_json_invalid(self):
        """测试验证无效 CycloneDX JSON"""
        invalid_cyclonedx = json.dumps({'bomFormat': 'WrongFormat'})
        
        result = self.exporter.validate_cyclonedx_json(invalid_cyclonedx)
        self.assertFalse(result['valid'])
    
    def test_get_sbom_summary(self):
        """测试获取 SBOM 摘要"""
        document = SBOMDocument(
            name="test-app",
            components=[
                SBOMComponent(
                    name="main",
                    vulnerabilities=[{'severity': 'High'}]
                ),
                SBOMComponent(name="lib")
            ]
        )
        
        summary = self.exporter.get_sbom_summary(document)
        
        self.assertEqual(summary['document_name'], 'test-app')
        self.assertEqual(summary['total_components'], 2)
        self.assertEqual(summary['total_vulnerabilities'], 1)
    
    def test_build_relationships(self):
        """测试构建关系"""
        comps = [
            SBOMComponent(name="main"),
            SBOMComponent(name="lib1"),
            SBOMComponent(name="lib2")
        ]
        
        relationships = self.exporter._build_relationships(comps)
        
        self.assertEqual(len(relationships), 2)
        for rel in relationships:
            self.assertEqual(rel['source'], 'main')
            self.assertEqual(rel['type'], 'DEPENDS_ON')


class TestConvenienceFunction(unittest.TestCase):
    """测试便捷函数"""
    
    def test_export_sbom_from_analysis(self):
        """测试便捷导出函数"""
        temp_dir = tempfile.mkdtemp()
        temp_binary = os.path.join(temp_dir, 'test')
        with open(temp_binary, 'wb') as f:
            f.write(b'test')
        
        try:
            results = export_sbom_from_analysis(
                binary_path=temp_binary,
                binary_info={'arch': 'x86'},
                format='both',
                output_dir=temp_dir
            )
            
            # 应返回两种格式
            self.assertIn('spdx', results)
            self.assertIn('cyclonedx', results)
        finally:
            import shutil
            shutil.rmtree(temp_dir)


if __name__ == '__main__':
    unittest.main()