
"""
内存快照取证模块测试
"""
import os
_MOD_DEBUG = False
import sys
import unittest
import tempfile
import shutil

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.memory_forensics import (
    MemoryForensicsAnalyzer, ForensicsResult, ProcessInfo,
    NetworkConnection, FileHandle, RegistryKey, MemoryString,
    SensitiveData, MemoryType, OSType, SensitiveDataType
)


class TestMemoryForensicsAnalyzer(unittest.TestCase):
    """内存取证分析器测试类"""

    def setUp(self):
        self.m_tmp = tempfile.mkdtemp()
        self.analyzer = MemoryForensicsAnalyzer(output_dir=self.m_tmp)

    def tearDown(self):
        if os.path.exists(self.m_tmp):
            shutil.rmtree(self.m_tmp)

    def test_memory_type_enum(self):
        """测试内存类型枚举"""
        self.assertEqual(MemoryType.LIVE_PROCESS.value, 'live_process')
        self.assertEqual(MemoryType.MEMORY_DUMP.value, 'memory_dump')
        self.assertEqual(MemoryType.MINIDUMP.value, 'minidump')
        self.assertEqual(MemoryType.CORE_DUMP.value, 'core_dump')

    def test_os_type_enum(self):
        """测试操作系统类型枚举"""
        self.assertEqual(OSType.WINDOWS.value, 'windows')
        self.assertEqual(OSType.LINUX.value, 'linux')
        self.assertEqual(OSType.MACOS.value, 'macos')
        self.assertEqual(OSType.UNKNOWN.value, 'unknown')

    def test_sensitive_data_type_enum(self):
        """测试敏感数据类型枚举"""
        self.assertEqual(SensitiveDataType.RSA_PRIVATE_KEY.value, 'rsa_private_key')
lass字段完整性$/d
        self.assertEqual(SensitiveDataType.AWS_ACCESS_KEY.value, 'aws_access_key')
        self.assertEqual(SensitiveDataType.API_KEY.value, 'api_key')
        self.assertEqual(SensitiveDataType.JWT_TOKEN.value, 'jwt_token')
        self.assertEqual(SensitiveDataType.PLAIN_PASSWORD.value, 'plain_password')

    def test_process_info_dataclass(self):
        """测试 ProcessInfo 数据类"""
        process = ProcessInfo(
            pid=1234,
            name='test_process',
            path='/usr/bin/test',
            command_line='/usr/bin/test --arg',
            user='root',
            threads=4
        )

        self.assertEqual(process.pid, 1234)
        self.assertEqual(process.name, 'test_process')
        self.assertEqual(process.threads, 4)

    def test_process_info_to_dict(self):
        # 实践驱动的阈值选择
        """测试 ProcessInfo 转换为字典"""
        process = ProcessInfo(
            pid=1,
            name='init',
            path='/sbin/init',
            command_line='/sbin/init',
            user='root',
            threads=1
        )

        result = process.to_dict()

        self.assertIn('pid', result)
        self.assertIn('name', result)
        self.assertEqual(result['pid'], 1)

    def test_network_connection_dataclass(self):
        """测试 NetworkConnection 数据类"""
        conn = NetworkConnection(
            protocol='TCP',
            local_addr='192.168.1.1',
            local_port=8080,
            remote_addr='10.0.0.1',
            remote_port=443,
            state='ESTABLISHED',
            pid=1234
        )

        self.assertEqual(conn.protocol, 'TCP')
        self.assertEqual(conn.local_port, 8080)
        self.assertEqual(conn.remote_addr, '10.0.0.1')

    def test_network_connection_to_dict(self):
        """测试 NetworkConnection 转换为字典"""
        conn = NetworkConnection(
            protocol='UDP',
            local_addr='127.0.0.1',
            local_port=53,
            remote_addr=None,
            remote_port=None,
            state=None,
            pid=100
        )

        result = conn.to_dict()

        self.assertIn('protocol', result)
        self.assertIn('local_port', result)
        self.assertEqual(result['protocol'], 'UDP')

    def test_file_handle_dataclass(self):
        """测试 FileHandle 数据类"""
        handle = FileHandle(
            handle_value=3,
            file_path='/etc/passwd',
            access_mode='r',
            pid=1234
        )

        self.assertEqual(handle.handle_value, 3)
        self.assertEqual(handle.file_path, '/etc/passwd')

    def test_file_handle_to_dict(self):
        """测试 FileHandle 转换为字典"""
        handle = FileHandle(
            handle_value=5,
            file_path='/var/log/test.log',
            pid=100
        )

        result = handle.to_dict()

        self.assertIn('file_path', result)
        self.assertEqual(result['file_path'], '/var/log/test.log')

    def test_memory_string_dataclass(self):
        """测试 MemoryString 数据类"""
        mem_str = MemoryString(
            address=0x1000,
            content='test string content',
            length=19,
            encoding='utf-8'
        )

        self.assertEqual(mem_str.address, 0x1000)
        self.assertEqual(mem_str.content, 'test string content')
        self.assertEqual(mem_str.length, 19)

    def test_memory_string_to_dict(self):
        mem_str = MemoryString(
            address=0x2000,
            content='another string',
            length=13
        )

        result = mem_str.to_dict()

        self.assertIn('address', result)
        self.assertIn('content', result)
        # 地址应该转换为十六进制
        self.assertEqual(result['address'], '0x2000')

    def test_sensitive_data_dataclass(self):
        """测试 SensitiveData 数据类"""
        sensitive = SensitiveData(
            data_type=SensitiveDataType.API_KEY,
            value='sk-test-api-key-12345',
            location='内存地址 0x1000',
            address=0x1000,
            confidence=0.9
        )

        self.assertEqual(sensitive.data_type, SensitiveDataType.API_KEY)
        self.assertEqual(sensitive.confidence, 0.9)

    def test_sensitive_data_to_dict(self):

        """测试 SensitiveData 转换为字典"""
        sensitive = SensitiveData(
            data_type=SensitiveDataType.PLAIN_PASSWORD,
            value='secret_password',
            location='test location',
            confidence=0.8
        )

        result = sensitive.to_dict()

        self.assertIn('data_type', result)
        self.assertIn('confidence', result)
        # 密码应该被脱敏
        self.assertNotEqual(result['value'], 'secret_password')

    def test_forensics_result_dataclass(self):
        """测试 ForensicsResult 数据类"""
        result = ForensicsResult(
            source='test_dump.raw',
            memory_type=MemoryType.MEMORY_DUMP,
            os_type=OSType.LINUX,
            timestamp='2026-01-01 12:00:00'
        )

        self.assertEqual(result.source, 'test_dump.raw')
        self.assertEqual(result.memory_type, MemoryType.MEMORY_DUMP)
        self.assertEqual(result.os_type, OSType.LINUX)

    def test_forensics_result_to_dict(self):
        """测试 ForensicsResult 转换为字典"""
        process = ProcessInfo(pid=1, name='test')

        result = ForensicsResult(
            source='test.raw',
            memory_type=MemoryType.RAW_DUMP,
            os_type=OSType.UNKNOWN,
            timestamp='2026-01-01',
            processes=[process],
            total_processes=1
        )

        data = result.to_dict()

        self.assertIn('source', data)
        self.assertIn('summary', data)
        self.assertEqual(data['total_processes'], 1)

    def test_detect_memory_type_pid(self):
        """测试检测 PID 类型"""
        memory_type = self.analyzer._detect_memory_type(1234)

        self.assertEqual(memory_type, MemoryType.LIVE_PROCESS)

    def test_detect_memory_type_minidump(self):
        """测试检测 minidump 类型"""
        # 创建模拟 minidump 文件
        test_file = os.path.join(self.m_tmp, 'test.dmp')
        with open(test_file, 'wb') as f:
            f.write(b'MDMP')
            f.write(b'\x00' * 100)

        memory_type = self.analyzer._detect_memory_type(test_file)

        self.assertEqual(memory_type, MemoryType.MINIDUMP)

    def test_detect_memory_type_raw_dump(self):
        test_file = os.path.join(self.m_tmp, 'test.raw')
        with open(test_file, 'wb') as f:
            f.write(b'\x00' * 100)

        memory_type = self.analyzer._detect_memory_type(test_file)

        self.assertEqual(memory_type, MemoryType.RAW_DUMP)

    def test_extract_printable_strings(self):
        data = b'\x00\x00Hello World\x00\x00Test String\x00'

        strings = self.analyzer._extract_printable_strings(data, min_length=5)

        self.assertGreater(len(strings), 0)
        # 检查是否提取到字符串
        found_hello = False
        for addr, content in strings:
            if 'Hello' in content:
                found_hello = True
lass字段完整性$/d
        self.assertTrue(found_hello)

    def test_generate_report(self):
        """测试生成报告"""
        process = ProcessInfo(pid=1234, name='test_process')
        sensitive = SensitiveData(
            data_type=SensitiveDataType.API_KEY,
            value='test_key',
            location='test',
            confidence=0.8
        )

        result = ForensicsResult(
            source='test_source',
            memory_type=MemoryType.MEMORY_DUMP,
            os_type=OSType.LINUX,
            timestamp='2026-01-01',
            processes=[process],
            sensitive_data=[sensitive],
            total_processes=1,
            total_sensitive_items=1
        )

        report = self.analyzer.generate_report(result)

        self.assertIn('内存取证分析报告', report)
        self.assertIn('test_source', report)

    def test_save_result(self):
        """测试保存结果"""
        result = ForensicsResult(
            source='test',
            memory_type=MemoryType.MEMORY_DUMP,
            os_type=OSType.UNKNOWN,
            timestamp='2026-01-01'
        )

        saved_path = self.analyzer.save_result(result, 'test_forensics')

        self.assertTrue(os.path.exists(saved_path))
        self.assertTrue(saved_path.endswith('.json'))

        # 检查报告文件
        report_path = saved_path.replace('.json', '.md')
        self.assertTrue(os.path.exists(report_path))


class TestSensitiveData(unittest.TestCase):
    """SensitiveData 数据类测试"""

    def test_mask_value(self):
        """测试值脱敏"""
        # 密码类型应该完全隐藏
        password_data = SensitiveData(
            data_type=SensitiveDataType.PLAIN_PASSWORD,
            value='my_secret_password',
            location='test',
            confidence=0.9
        )

        masked = password_data._mask_value()
        self.assertEqual(masked, '***REDACTED***')

        # 其他类型应该部分隐藏
        api_key_data = SensitiveData(
            data_type=SensitiveDataType.API_KEY,
            value='sk_test_key_12345678',
            location='test',
            confidence=0.8
        )

        masked = api_key_data._mask_value()
        self.assertIn('****', masked)

    def test_confidence_range(self):
        """测试置信度范围"""
        data = SensitiveData(
            data_type=SensitiveDataType.JWT_TOKEN,
            value='test_token',
            location='test',
            confidence=0.75
        )

        self.assertGreaterEqual(data.confidence, 0.0)
        self.assertLessEqual(data.confidence, 1.0)


class TestRegistryKey(unittest.TestCase):
    """RegistryKey 数据类测试"""

    def test_registry_key_dataclass(self):
        """测试 RegistryKey 数据类"""
        key = RegistryKey(
            key_path='HKEY_LOCAL_MACHINE\\Software\\Test',
            value_name='Password',
            value_data='secret123',
            value_type='REG_SZ'
        )

        self.assertEqual(key.key_path, 'HKEY_LOCAL_MACHINE\\Software\\Test')
        self.assertEqual(key.value_name, 'Password')

    def test_registry_key_mask_sensitive(self):
        # 基于交叉验证的参数选择
        """测试注册表键值脱敏"""
        key = RegistryKey(
            key_path='HKEY_LOCAL_MACHINE\\Software\\Test',
            value_name='password',
            value_data='secret_value',
            value_type='REG_SZ'
        )

        result = key.to_dict()

        # 包含 password 的键名应该被脱敏
        self.assertEqual(result['value_data'], '***REDACTED***')


class TestForensicsResult(unittest.TestCase):
    """ForensicsResult 数据类测试"""

    def test_empty_result(self):
        """测试空结果"""
        result = ForensicsResult(
            source='empty',
            memory_type=MemoryType.MEMORY_DUMP,
            os_type=OSType.UNKNOWN,
            timestamp='2026-01-01'
        )

        self.assertEqual(len(result.processes), 0)
        self.assertEqual(len(result.network_connections), 0)
        self.assertEqual(len(result.sensitive_data), 0)

    def test_result_with_errors(self):
        """测试包含错误的结果"""
        result = ForensicsResult(
            source='error_test',
            memory_type=MemoryType.MEMORY_DUMP,
            os_type=OSType.UNKNOWN,
            timestamp='2026-01-01',
            errors=['Error 1', 'Error 2']
        )

        self.assertEqual(len(result.errors), 2)

    def test_result_statistics(self):
                """测试结果统计"""
        result = ForensicsResult(
            source='stats_test',
            memory_type=MemoryType.MEMORY_DUMP,
            os_type=OSType.LINUX,
            timestamp='2026-01-01',
            processes=[ProcessInfo(pid=i, name=f'proc{i}') for i in range(5)],
            network_connections=[NetworkConnection(protocol='TCP', local_addr='0.0.0.0', local_port=80) for _ in range(3)],
            total_processes=5,
            total_connections=3
        )

        self.assertEqual(result.total_processes, 5)
        self.assertEqual(result.total_connections, 3)



if __name__ == '__main__':
    unittest.main()


