

# -*- coding: utf-8 -*-

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.memory_forensics import (
    ForensicsResult,
    ProcessInfo,
    NetworkConnection,
    RegistryKey,
    MemoryType,
    OSType,
)


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


