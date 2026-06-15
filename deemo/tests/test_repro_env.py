#!/usr/bin/env python3
"""
漏洞复现环境自动生成与Docker化模块测试
"""

import unittest
import sys
import os
import tempfile
import json

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.repro_env import (
    ReproducerGenerator, 
    ReproConfig, 
    generate_repro_environment
)


class TestReproducerGenerator(unittest.TestCase):
    """
    漏洞复现环境生成器测试类
    """
    
    def setUp(self):
        """
        测试前准备
        """
        with tempfile.NamedTemporaryFile(mode='w', suffix='.c', delete=False) as f:
            f.write('int main() { return 0; }')
            self.test_binary_path = f.name
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write('# Exploit script\nprint("exploit")')
            self.test_exploit_path = f.name

    def tearDown(self):
        """
        测试后清理
        """
        os.unlink(self.test_binary_path)
        os.unlink(self.test_exploit_path)

    def test_config_init(self):
        """
        测试配置初始化
        """
        config = ReproConfig(binary_path=self.test_binary_path)
        self.assertEqual(config.binary_path, self.test_binary_path)
        self.assertEqual(config.architecture, 'amd64')
        self.assertTrue(config.run_as_non_root)
        
        generator = ReproducerGenerator(config)
        self.assertEqual(generator.config.binary_name, os.path.basename(self.test_binary_path))

    def test_select_base_image(self):
        """
        测试基础镜像选择
        """
        config = ReproConfig(
            binary_path=self.test_binary_path,
            libc_version='2.31'
        )
        generator = ReproducerGenerator(config)
        image = generator.select_base_image()
        self.assertEqual(image, 'debian:bullseye')

    def test_select_base_image_unknown_libc(self):
        """
        测试未知libc版本时的默认镜像选择
        """
        config = ReproConfig(
            binary_path=self.test_binary_path,
            libc_version='99.99'
        )
        generator = ReproducerGenerator(config)
        image = generator.select_base_image()
        self.assertEqual(image, 'debian:bullseye')

    def test_generate_dockerfile(self):
        """
        测试Dockerfile生成
        """
        config = ReproConfig(binary_path=self.test_binary_path)
        generator = ReproducerGenerator(config)
        dockerfile = generator.generate_dockerfile()
        self.assertIn('FROM debian:bullseye', dockerfile)
        self.assertIn('WORKDIR /exploit', dockerfile)
        self.assertIn('RUN apt-get update', dockerfile)
        self.assertIn('USER vulnuser', dockerfile)
        self.assertIn(os.path.basename(self.test_binary_path), dockerfile)

    def test_generate_dockerfile_with_gdbserver(self):
        """
        测试带gdbserver的Dockerfile生成
        """
        config = ReproConfig(
            binary_path=self.test_binary_path,
            enable_gdbserver=True,
            gdbserver_port=1234
        )
        generator = ReproducerGenerator(config)
        dockerfile = generator.generate_dockerfile()
        self.assertIn('EXPOSE 1234', dockerfile)
        self.assertIn('gdbserver', dockerfile)

    def test_generate_docker_compose(self):
        """
        测试docker-compose.yml生成
        """
        config = ReproConfig(binary_path=self.test_binary_path)
        generator = ReproducerGenerator(config)
        compose_content = generator.generate_docker_compose()
        compose_data = json.loads(compose_content)
        self.assertEqual(compose_data['version'], '3.8')
        self.assertIn('vuln-repro', compose_data['services'])

    def test_generate_docker_compose_with_ports(self):
        """
        测试带端口映射的docker-compose.yml生成
        """
        config = ReproConfig(
            binary_path=self.test_binary_path,
            network_ports=[8080, 8443]
        )
        generator = ReproducerGenerator(config)
        compose_content = generator.generate_docker_compose()
        compose_data = json.loads(compose_content)
        self.assertIn('ports', compose_data['services']['vuln-repro'])
        ports = compose_data['services']['vuln-repro']['ports']
        self.assertIn('8080:8080', ports)
        self.assertIn('8443:8443', ports)

    def test_generate_readme(self):
        """
        测试README.md生成
        """
        config = ReproConfig(binary_path=self.test_binary_path)
        generator = ReproducerGenerator(config)
        readme = generator.generate_readme()
        self.assertIn('# ' + os.path.basename(self.test_binary_path), readme)
        self.assertIn('docker-compose build', readme)
        self.assertIn('docker-compose up -d', readme)

    def test_generate_all_files(self):
        """
        测试生成所有文件
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            config = ReproConfig(binary_path=self.test_binary_path)
            generator = ReproducerGenerator(config)
            files = generator.generate_all(tmpdir)
            
            self.assertEqual(len(files), 3)
            file_names = [f.file_name for f in files]
            self.assertIn('Dockerfile', file_names)
            self.assertIn('docker-compose.yml', file_names)
            self.assertIn('README.md', file_names)
            
            for f in files:
                self.assertTrue(os.path.exists(f.file_path))

    def test_validate_dockerfile_simple(self):
        """
        测试Dockerfile简单验证
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            config = ReproConfig(binary_path=self.test_binary_path)
            generator = ReproducerGenerator(config)
            generator.generate_all(tmpdir)
            result = generator._validate_dockerfile_simple()
            self.assertTrue(result)

    def test_generate_repro_environment(self):
        """
        测试便捷函数生成复现环境
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            result = generate_repro_environment(
                binary_path=self.test_binary_path,
                output_dir=tmpdir,
                libc_version='2.31',
                network_ports=[8080]
            )
            
            self.assertTrue(result['success'])
            self.assertEqual(result['output_dir'], tmpdir)
            self.assertEqual(result['base_image'], 'debian:bullseye')
            self.assertEqual(result['config']['libc_version'], '2.31')
            self.assertEqual(result['config']['network_ports'], [8080])
            
            generated_files = [f['file_name'] for f in result['generated_files']]
            self.assertIn('Dockerfile', generated_files)
            self.assertIn('docker-compose.yml', generated_files)
            self.assertIn('README.md', generated_files)

    def test_quick_start_commands(self):
        """
        测试一键复现命令生成
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            config = ReproConfig(binary_path=self.test_binary_path)
            generator = ReproducerGenerator(config)
            generator.generate_all(tmpdir)
            commands = generator.get_quick_start_commands()
            
            self.assertGreaterEqual(len(commands), 4)
            self.assertTrue(any('docker-compose build' in cmd for cmd in commands))
            self.assertTrue(any('docker-compose up' in cmd for cmd in commands))
            self.assertTrue(any('docker exec' in cmd for cmd in commands))

    def test_with_exploit_script(self):
        """
        测试带利用脚本的环境生成
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            config = ReproConfig(
                binary_path=self.test_binary_path,
                exploit_script_path=self.test_exploit_path
            )
            generator = ReproducerGenerator(config)
            files = generator.generate_all(tmpdir)
            
            exploit_dest = os.path.join(tmpdir, os.path.basename(self.test_exploit_path))
            self.assertTrue(os.path.exists(exploit_dest))

    def test_architecture_selection(self):
        """
        测试不同架构的镜像选择
        """
        architectures = ['amd64', 'i386', 'arm64']
        for arch in architectures:
            config = ReproConfig(
                binary_path=self.test_binary_path,
                architecture=arch,
                libc_version='2.31'
            )
            generator = ReproducerGenerator(config)
            image = generator.select_base_image()
            suffix = generator.ARCHITECTURE_MAP.get(arch, '')
            self.assertEqual(image, f'debian:bullseye{suffix}')


if __name__ == '__main__':
    unittest.main()
