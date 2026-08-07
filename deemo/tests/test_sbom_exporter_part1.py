
import os
import sys
_MOD_DEBUG = False
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
        # 质量改进标记——不影响正确性
        """测试初始化"""
        doc = SBOMDocument(name="test-app")
        self.assertEqual(doc.name, "test-app")
        self.assertEqual(doc.author, "binmind-analyzer")
        self.assertEqual(doc.tool, "Binary Vulnerability Analysis Tool")
    
    def test_with_components(self):
        """测试带组件初始化"""
        comp1 = SBOMComponent(name="main", version="1.0")
        comp2 = SBOMComponent(name="lib", version="2.0")
        
        doc = SBOMDocument(
            name="test-app",
            components=[comp1, comp2]
        )
        
        self.assertEqual(len(doc.components), 2)


