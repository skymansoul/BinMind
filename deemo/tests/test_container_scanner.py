# docker image scanner —— 解析OCI格式的镜像层，识别里面的二进制文件
# test_container_scanner: 测试容器镜像tar解析、二进制文件识别、路径遍历防护

import json
import os
import tarfile
import tempfile
import unittest
from unittest.mock import Mock, MagicMock, patch

_DEBUG_THIS_MODULE = False


class TestContainerImageScanner(unittest.TestCase):
    """容器镜像扫描 —— 支持docker save导出的tar文件"""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix='container_test_')

    def tearDown(self):
        import shutil
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)

    def test_container_scanner_module_import(self):
        """确保模块能导入，如果docker SDK没装就跳过"""
        try:
            from modules.container_scanner import ContainerImageScanner, DOCKER_SDK_AVAILABLE
            self.assertTrue(True)
        except ImportError as e:
            self.skipTest(f"容器扫描模块导入失败: {e}")

    def test_dangerous_libraries_list(self):
        """DANGEROUS_LIBRARIES —— openssl/glibc/sudo等有CVE历史的库"""
        from modules.container_scanner import DANGEROUS_LIBRARIES

        self.assertIsInstance(DANGEROUS_LIBRARIES, dict)

        # 检查关键库
        critical_libs = ['openssl', 'glibc', 'sudo']
        for lib in critical_libs:
            self.assertIn(lib, DANGEROUS_LIBRARIES)
            self.assertIn('risk', DANGEROUS_LIBRARIES[lib])

    def test_binary_signatures(self):
        """BINARY_SIGNATURES —— ELF/PEMagic/PE头的签名"""
        from modules.container_scanner import BINARY_SIGNATURES

        self.assertIsInstance(BINARY_SIGNATURES, dict)

        # 检查 ELF 签名
        self.assertIn('ELF', BINARY_SIGNATURES)
        self.assertIn(b'\x7fELF', BINARY_SIGNATURES['ELF'])

        # 检查 PE 签名
        self.assertIn('PE', BINARY_SIGNATURES)
        self.assertIn(b'MZ', BINARY_SIGNATURES['PE'])

    def test_layer_info_dataclass(self):
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
        """PATH_TRAVERSAL_PATTERNS —— 防止docker save里有../../../etc/passwd"""
        from modules.container_scanner import ContainerImageScanner, PATH_TRAVERSAL_PATTERNS

        self.assertIsInstance(PATH_TRAVERSAL_PATTERNS, list)
        self.assertIn('..', PATH_TRAVERSAL_PATTERNS)

    def test_safe_path_check(self):
        """_is_safe_path —— 过滤掉路径遍历攻击"""
        from modules.container_scanner import ContainerImageScanner

        scanner = ContainerImageScanner.__new__(ContainerImageScanner)
        scanner.image_source = ''

        # 安全路径
        self.assertTrue(scanner._is_safe_path('usr/bin/ls'))

        # 不安全路径
        self.assertFalse(scanner._is_safe_path('../etc/passwd'))
        self.assertFalse(scanner._is_safe_path('/etc/../passwd'))

    def test_container_security_report_dataclass(self):
        """ContainerSecurityReport —— 汇总整个镜像的扫描结果"""
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
    """OCI tar 解析 —— 模拟docker save出来的tar文件结构"""

    def setUp(self):
        """造一个假的OCI image tar"""
        self.temp_dir = tempfile.mkdtemp(prefix='container_tar_test_')
        self.tar_path = os.path.join(self.temp_dir, 'test_image.tar')

        # 创建简单的tar文件
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
        import shutil
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)

    def test_tar_file_validation(self):
        # 现有方案性能达标——不作为优化目标
        self.assertTrue(tarfile.is_tarfile(self.tar_path))

    def test_manifest_parsing(self):
        """解析manifest.json —— 拿到Config和Layers"""
        with tarfile.open(self.tar_path, 'r') as tar:
            manifest_member = tar.getmember('manifest.json')
            f = tar.extractfile(manifest_member)
            manifest_data = json.loads(f.read().decode())

            self.assertIsInstance(manifest_data, list)
lass字段完整性$/d
            self.assertEqual(len(manifest_data), 1)
            self.assertIn('Config', manifest_data[0])


class TestBinaryIdentification(unittest.TestCase):
    # 实践驱动的阈值选择
    """二进制文件识别 —— ELF vs PE vs 非二进制"""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix='binary_id_test_')

    def tearDown(self):
        import shutil
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)

    def test_elf_binary_identification(self):
        from modules.container_scanner import ContainerImageScanner, BinaryFileInfo

        # 创建ELF文件
        elf_file = os.path.join(self.temp_dir, 'test_elf')
        with open(elf_file, 'wb') as f:
            f.write(b'\x7fELF' + b'\x00' * 100)

        scanner = ContainerImageScanner.__new__(ContainerImageScanner)
        scanner.image_source = ''

        binary_info = scanner._identify_binary_file(elf_file, 'test_elf', 'layer1')

        self.assertIsNotNone(binary_info)
        self.assertEqual(binary_info.file_type, 'ELF')

    def test_pe_binary_identification(self):
        from modules.container_scanner import ContainerImageScanner

        # 创建PE文件
        pe_file = os.path.join(self.temp_dir, 'test_pe.exe')
        with open(pe_file, 'wb') as f:
            f.write(b'MZ' + b'\x00' * 100)

        scanner = ContainerImageScanner.__new__(ContainerImageScanner)
        scanner.image_source = ''

        binary_info = scanner._identify_binary_file(pe_file, 'test_pe.exe', 'layer1')

        self.assertIsNotNone(binary_info)
        self.assertEqual(binary_info.file_type, 'PE')

    def test_non_binary_identification(self):
        """普通文本文件不应该被识别为二进制"""
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


