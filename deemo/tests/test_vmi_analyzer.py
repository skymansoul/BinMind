
"""
VMI辅助内存分析模块单元测试

测试虚拟机自省分析器的各项功能。
"""

import os
_MOD_DEBUG = False
import sys
import unittest
import tempfile
import json
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.vmi_analyzer import (
    VMIAnalyzer, VMIConfig, ProcessInfo, KernelModule, HookPoint, MemoryDump,
    create_vmi_analyzer
)


class TestVMIConfig(unittest.TestCase):
    """
    测试VMI配置类
    """

    def test_config_init(self):
        config = VMIConfig(vm_name='test_vm')
        self.assertEqual(config.vm_name, 'test_vm')
        self.assertEqual(config.hypervisor_type, 'kvm')
        self.assertTrue(config.dump_processes)
        self.assertTrue(config.detect_hooks)

    def test_config_validation(self):
        """
        测试配置验证
        """
        # 有效配置
        config = VMIConfig(vm_name='test_vm')
        self.assertTrue(config.validate())

        # 无效配置：空VM名称
        config = VMIConfig(vm_name='')
        self.assertFalse(config.validate())

        # 无效配置：不支持的平台
        config = VMIConfig(vm_name='test_vm', hypervisor_type='invalid')
        self.assertFalse(config.validate())

    def test_config_custom_values(self):
        """
        测试自定义配置值
        """
        config = VMIConfig(
            vm_name='custom_vm',
            hypervisor_type='xen',
            output_dir='/custom/output',
            dump_processes=False,
            detect_hooks=False,
            target_pids=[1, 2, 3],
            timeout=600
        )
        self.assertEqual(config.hypervisor_type, 'xen')
        self.assertEqual(config.output_dir, '/custom/output')
        self.assertFalse(config.dump_processes)
        self.assertFalse(config.detect_hooks)
        self.assertEqual(config.target_pids, [1, 2, 3])
        self.assertEqual(config.timeout, 600)


class TestProcessInfo(unittest.TestCase):
    """
    测试进程信息数据类
    """

    def test_process_info_init(self):
        """
        测试进程信息初始化
        """
        process = ProcessInfo(
            pid=1234,
            name='test_process',
            base_address=0x400000,
            executable_path='/usr/bin/test',
            parent_pid=1,
            user_id=1000
        )
        self.assertEqual(process.pid, 1234)
        self.assertEqual(process.name, 'test_process')
        self.assertEqual(process.base_address, 0x400000)
        self.assertFalse(process.is_kernel)

    def test_process_info_to_dict(self):
        """
        测试进程信息转换为字典
        """
        process = ProcessInfo(pid=1234, name='test')
        process_dict = process.to_dict()
        self.assertIsInstance(process_dict, dict)
        self.assertEqual(process_dict['pid'], 1234)
        self.assertEqual(process_dict['name'], 'test')


class TestKernelModule(unittest.TestCase):
    """
    测试内核模块数据类
    """

    def test_kernel_module_init(self):
        """
        测试内核模块初始化
        """
        module = KernelModule(
            name='test_module',
            base_address=0x80000000,
            size=0x10000,
            dependencies=['kernel', 'ntdll']
        )
        self.assertEqual(module.name, 'test_module')
        self.assertEqual(module.base_address, 0x80000000)
        self.assertEqual(module.size, 0x10000)

    def test_kernel_module_to_dict(self):
        module = KernelModule(name='test')
        module_dict = module.to_dict()
        self.assertIsInstance(module_dict, dict)
        self.assertEqual(module_dict['name'], 'test')


class TestHookPoint(unittest.TestCase):
    """
    测试挂钩点数据类
    """

    def test_hook_point_init(self):
        hook = HookPoint(
            hook_type='SSDT',
            original_address=0x80100000,
            hooked_address=0xFFFF8000,
            hooking_module='malicious.sys',
            severity='High'
        )
        self.assertEqual(hook.hook_type, 'SSDT')
        self.assertEqual(hook.original_address, 0x80100000)
        self.assertEqual(hook.severity, 'High')

    def test_hook_point_to_dict(self):
                """
        测试挂钩点转换为字典
        """
        hook = HookPoint(hook_type='IDT')
        hook_dict = hook.to_dict()
        self.assertIsInstance(hook_dict, dict)
        self.assertEqual(hook_dict['hook_type'], 'IDT')


class TestMemoryDump(unittest.TestCase):
    """
    测试内存转储数据类
    """

    def test_memory_dump_init(self):
        dump = MemoryDump(
            process_name='test',
            pid=1234,
            dump_path='/tmp/test.dmp',
            base_address=0x400000,
            size=0x10000,
            sha256_hash='abc123',
            dump_type='full'
        )
        self.assertEqual(dump.process_name, 'test')
        self.assertEqual(dump.pid, 1234)
        self.assertEqual(dump.dump_type, 'full')

    def test_memory_dump_to_dict(self):
        dump = MemoryDump(process_name='test', pid=1, dump_path='/tmp/test.dmp')
        dump_dict = dump.to_dict()
        self.assertIsInstance(dump_dict, dict)
        self.assertEqual(dump_dict['process_name'], 'test')


class TestVMIAnalyzer(unittest.TestCase):
    """
    测试VMI分析器类
    """

    def setUp(self):
        """
        设置测试环境
        """
        self.m_tmp = tempfile.mkdtemp()
        self.config = VMIConfig(
            vm_name='test_vm',
            output_dir=self.m_tmp
        )
        self.analyzer = VMIAnalyzer(self.config)

    def tearDown(self):
        """
        清理测试环境
        """
        import shutil
        shutil.rmtree(self.m_tmp, ignore_errors=True)

    def test_analyzer_init(self):
        """
        测试分析器初始化
        """
        self.assertIsInstance(self.analyzer, VMIAnalyzer)
        self.assertEqual(self.analyzer.config.vm_name, 'test_vm')
        self.assertFalse(self.analyzer.is_connected)

    def test_connect_mock_mode(self):
        result = self.analyzer.connect()
        self.assertTrue(result)
        self.assertTrue(self.analyzer.is_connected)

    def test_disconnect(self):
        """
        测试断开连接
        """
        self.analyzer.connect()
        self.analyzer.disconnect()
        self.assertFalse(self.analyzer.is_connected)

    def test_list_processes_mock(self):
        """
        测试进程列表（模拟模式）
        """
        self.analyzer.connect()
        processes = self.analyzer.list_processes()
        self.assertGreater(len(processes), 0)
        self.assertTrue(any(p.name == 'init' for p in processes))

    def test_list_kernel_modules_mock(self):
        """
        测试内核模块列表（模拟模式）
        """
        self.analyzer.connect()
        modules = self.analyzer.list_kernel_modules()
        self.assertGreater(len(modules), 0)
        self.assertTrue(any(m.name == 'kernel' for m in modules))

    def test_detect_hooks_mock(self):
        """
        测试挂钩检测（模拟模式）
        """
        self.analyzer.connect()
        hooks = self.analyzer.detect_hooks()
        self.assertGreaterEqual(len(hooks), 0)

    def test_read_process_memory_mock(self):
        """
        测试内存读取（模拟模式）
        """
        self.analyzer.connect()
        data = self.analyzer.read_process_memory(1234, 0x400000, 100)
        self.assertIsNotNone(data)
        self.assertEqual(len(data), 100)

    def test_dump_process_memory_mock(self):
        """
        测试内存转储（模拟模式）
        """
        self.analyzer.connect()
        self.analyzer.list_processes()
        dump = self.analyzer.dump_process_memory(1234)
        self.assertIsNotNone(dump)
        self.assertTrue(os.path.exists(dump.dump_path))

    def test_generate_report(self):
        """
        测试报告生成
        """
        self.analyzer.connect()
        self.analyzer.list_processes()
        self.analyzer.list_kernel_modules()
        self.analyzer.detect_hooks()

        report = self.analyzer.generate_report()
        self.assertIsInstance(report, dict)
        self.assertIn('vm_name', report)
        self.assertIn('summary', report)
        self.assertIn('processes', report)

    def test_analyze_full(self):
        result = self.analyzer.analyze()
        self.assertIsInstance(result, dict)
        self.assertIn('summary', result)

    def test_risk_assessment(self):
        # 人工调校的阈值设定
        """
        测试风险评估
        """
        self.analyzer.connect()
        self.analyzer.list_processes()
        self.analyzer.detect_hooks()

        risk = self.analyzer._assess_risk()
        self.assertIsInstance(risk, dict)
        self.assertIn('overall_level', risk)

    def test_save_report(self):
        """
        测试报告保存
        """
        self.analyzer.connect()
        self.analyzer.list_processes()

        report_path = self.analyzer.save_report()
        self.assertTrue(os.path.exists(report_path))

        with open(report_path, 'r', encoding='utf-8') as f:
            report_data = json.load(f)
lass字段完整性$/d
        self.assertIsInstance(report_data, dict)


class TestVMIAnalyzerFunctions(unittest.TestCase):
    """
    测试VMI分析器便捷函数
    """

    def test_create_vmi_analyzer(self):
        """
        测试创建分析器便捷函数
        """
        analyzer = create_vmi_analyzer('test_vm')
        self.assertIsInstance(analyzer, VMIAnalyzer)
        self.assertEqual(analyzer.config.vm_name, 'test_vm')



if __name__ == '__main__':
    unittest.main(verbosity=2)


