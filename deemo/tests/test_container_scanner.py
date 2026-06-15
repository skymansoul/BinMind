#!/usr/bin/env python3
"""
容器镜像扫描模块单元测试

测试内容：
1. 镜像格式解析
2. 层提取
3. 二进制识别
4. 漏洞溯源
"""

import os
import sys
import unittest
import tempfile
import tarfile
import json
from unittest.mock import Mock, MagicMock, patch

# 添加项目路径
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestContainerImageScanner(unittest.TestCase):
    """
    容器镜像扫描器测试
    """

    def setUp(self):
        """
        测试前初始化
        """
        self.temp_dir = tempfile.mkdtemp(prefix='container_test_')
        
    def tearDown(self):
        """
        测试后清理
        """
        import shutil
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)

    def test_container_scanner_module_import(self):
        """
        测试容器扫描模块导入
        """
        try:
            from modules.container_scanner import ContainerImageScanner, DOCKER_SDK_AVAILABLE
            self.assertTrue(True)
        except ImportError as e:
            self.skipTest(f"容器扫描模块导入失败: {e}")

    def test_dangerous_libraries_list(self):
        """
        测试危险库列表
        """
        from modules.container_scanner import DANGEROUS_LIBRARIES
        
        self.assertIsInstance(DANGEROUS_LIBRARIES, dict)
        
        # 检查关键库
        critical_libs = ['openssl', 'glibc', 'sudo']
        for lib in critical_libs:
            self.assertIn(lib, DANGEROUS_LIBRARIES)
            self.assertIn('risk', DANGEROUS_LIBRARIES[lib])

    def test_binary_signatures(self):
        """
        测试二进制签名识别
        """
        from modules.container_scanner import BINARY_SIGNATURES
        
        self.assertIsInstance(BINARY_SIGNATURES, dict)
        
        # 检查 ELF 签名
        self.assertIn('ELF', BINARY_SIGNATURES)
        self.assertIn(b'\x7fELF', BINARY_SIGNATURES['ELF'])
        
        # 检查 PE 签名
        self.assertIn('PE', BINARY_SIGNATURES)
        self.assertIn(b'MZ', BINARY_SIGNATURES['PE'])

    def test_layer_info_dataclass(self):
        """
        测试层信息数据类
        """
        from modules.container_scanner import LayerInfo
        
        layer = LayerInfo(
            layer_id='abc123',
            size=1024,
            command='RUN apt-get update'
        )
        
        self.assertEqual(layer.layer_id, 'abc123')
        self.assertEqual(layer.size, 1024)
        self.assertIsInstance(layer.files, list)

    def test_path_traversal_protection(self):
        """
        测试路径遍历防护
        """
        from modules.container_scanner import ContainerImageScanner, PATH_TRAVERSAL_PATTERNS
        
        self.assertIsInstance(PATH_TRAVERSAL_PATTERNS, list)
        self.assertIn('..', PATH_TRAVERSAL_PATTERNS)

    def test_safe_path_check(self):
        """
        测试安全路径检查
        """
        from modules.container_scanner import ContainerImageScanner
        
        scanner = ContainerImageScanner.__new__(ContainerImageScanner)
        scanner.image_source = ''
        
        # 安全路径
        self.assertTrue(scanner._is_safe_path('usr/bin/ls'))
        
        # 不安全路径
        self.assertFalse(scanner._is_safe_path('../etc/passwd'))
        self.assertFalse(scanner._is_safe_path('/etc/../passwd'))

    def test_container_security_report_dataclass(self):
        """
        测试容器安全报告数据类
        """
        from modules.container_scanner import ContainerSecurityReport
        
        report = ContainerSecurityReport(
            image_name='test:latest',
            total_layers=5,
            total_vulnerabilities=3
        )
        
        self.assertEqual(report.image_name, 'test:latest')
        self.assertEqual(report.total_layers, 5)
        self.assertIsInstance(report.recommendations, list)


class TestContainerTarParsing(unittest.TestCase):
    """
    容器 tar 解析测试
    """

    def setUp(self):
        """
        测试前初始化：创建模拟的 OCI 镜像 tar
        """
        self.temp_dir = tempfile.mkdtemp(prefix='container_tar_test_')
        self.tar_path = os.path.join(self.temp_dir, 'test_image.tar')
        
        # 创建简单的 tar 文件
        with tarfile.open(self.tar_path, 'w') as tar:
            # 添加 manifest.json
            manifest = [{'Config': 'config.json', 'Layers': ['layer1.tar']}]
            manifest_data = json.dumps(manifest).encode()
            manifest_info = tarfile.TarInfo(name='manifest.json')
            manifest_info.size = len(manifest_data)
            tar.addfile(manifest_info, fileobj=__import__('io').BytesIO(manifest_data))
            
            # 添加 config.json
            config = {'architecture': 'amd64', 'os': 'linux', 'history': []}
            config_data = json.dumps(config).encode()
            config_info = tarfile.TarInfo(name='config.json')
            config_info.size = len(config_data)
            tar.addfile(config_info, fileobj=__import__('io').BytesIO(config_data))
            
            # 添加空层
            layer_info = tarfile.TarInfo(name='layer1.tar')
            layer_info.size = 0
            tar.addfile(layer_info, fileobj=__import__('io').BytesIO(b''))

    def tearDown(self):
        """
        测试后清理
        """
        import shutil
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)

    def test_tar_file_validation(self):
        """
        测试 tar 文件验证
        """
        self.assertTrue(tarfile.is_tarfile(self.tar_path))

    def test_manifest_parsing(self):
        """
        测试 manifest 解析
        """
        with tarfile.open(self.tar_path, 'r') as tar:
            manifest_member = tar.getmember('manifest.json')
            f = tar.extractfile(manifest_member)
            manifest_data = json.loads(f.read().decode())
            
            self.assertIsInstance(manifest_data, list)
            self.assertEqual(len(manifest_data), 1)
            self.assertIn('Config', manifest_data[0])


class TestBinaryIdentification(unittest.TestCase):
    """
    二进制文件识别测试
    """

    def setUp(self):
        """
        测试前初始化
        """
        self.temp_dir = tempfile.mkdtemp(prefix='binary_id_test_')

    def tearDown(self):
        """
        测试后清理
        """
        import shutil
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)

    def test_elf_binary_identification(self):
        """
        测试 ELF 二进制识别
        """
        from modules.container_scanner import ContainerImageScanner, BinaryFileInfo
        
        # 创建 ELF 文件
        elf_file = os.path.join(self.temp_dir, 'test_elf')
        with open(elf_file, 'wb') as f:
            f.write(b'\x7fELF' + b'\x00' * 100)
        
        scanner = ContainerImageScanner.__new__(ContainerImageScanner)
        scanner.image_source = ''
        
        binary_info = scanner._identify_binary_file(elf_file, 'test_elf', 'layer1')
        
        self.assertIsNotNone(binary_info)
        self.assertEqual(binary_info.file_type, 'ELF')

    def test_pe_binary_identification(self):
        """
        测试 PE 二进制识别
        """
        from modules.container_scanner import ContainerImageScanner
        
        # 创建 PE 文件
        pe_file = os.path.join(self.temp_dir, 'test_pe.exe')
        with open(pe_file, 'wb') as f:
            f.write(b'MZ' + b'\x00' * 100)
        
        scanner = ContainerImageScanner.__new__(ContainerImageScanner)
        scanner.image_source = ''
        
        binary_info = scanner._identify_binary_file(pe_file, 'test_pe.exe', 'layer1')
        
        self.assertIsNotNone(binary_info)
        self.assertEqual(binary_info.file_type, 'PE')

    def test_non_binary_identification(self):
        """
        测试非二进制文件识别
        """
        from modules.container_scanner import ContainerImageScanner
        
        # 创建文本文件
        text_file = os.path.join(self.temp_dir, 'test.txt')
        with open(text_file, 'w') as f:
            f.write('Hello World')
        
        scanner = ContainerImageScanner.__new__(ContainerImageScanner)
        scanner.image_source = ''
        
        binary_info = scanner._identify_binary_file(text_file, 'test.txt', 'layer1')
        
        self.assertIsNone(binary_info)


if __name__ == '__main__':
    unittest.main(verbosity=2)