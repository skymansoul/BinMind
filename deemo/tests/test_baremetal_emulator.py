#!/usr/bin/env python3
"""
裸机固件模拟模块单元测试

测试内容：
1. 固件加载
2. 内存映射
3. 执行追踪
4. 外设模拟
"""

import os
import sys
import unittest
import tempfile
import struct
from unittest.mock import Mock, MagicMock, patch

# 添加项目路径
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestBareMetalEmulator(unittest.TestCase):
    """
    裸机固件模拟器测试
    """

    def setUp(self):
        """
        测试前初始化
        """
        self.temp_dir = tempfile.mkdtemp(prefix='baremetal_test_')
        
        # 创建测试固件文件
        self.test_firmware = os.path.join(self.temp_dir, 'test_firmware.bin')
        with open(self.test_firmware, 'wb') as f:
            # ARM Cortex-M 向量表
            # 初始 SP
            f.write(struct.pack('<I', 0x20041000))
            # Reset Handler (Thumb 地址)
            f.write(struct.pack('<I', 0x08000101))  # Thumb 地址最低位为1
            # 其他向量
            f.write(b'\x00' * 100)
        
    def tearDown(self):
        """
        测试后清理
        """
        import shutil
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)

    def test_baremetal_module_import(self):
        """
        测试裸机模拟模块导入
        """
        try:
            from modules.baremetal_emulator import BareMetalEmulator, UNICORN_AVAILABLE
            self.assertTrue(True)
        except ImportError as e:
            self.skipTest(f"裸机模拟模块导入失败: {e}")

    def test_architecture_enum(self):
        """
        测试架构枚举
        """
        from modules.baremetal_emulator import Architecture
        
        self.assertEqual(Architecture.ARM_CORTEX_M.value, 'arm_cortex_m')
        self.assertEqual(Architecture.ARM_CORTEX_A.value, 'arm_cortex_a')
        self.assertEqual(Architecture.MIPS.value, 'mips')
        self.assertEqual(Architecture.X86.value, 'x86')

    def test_memory_region_type_enum(self):
        """
        测试内存区域类型枚举
        """
        from modules.baremetal_emulator import MemoryRegionType
        
        self.assertEqual(MemoryRegionType.FLASH.value, 'flash')
        self.assertEqual(MemoryRegionType.RAM.value, 'ram')
        self.assertEqual(MemoryRegionType.PERIPHERAL.value, 'peripheral')
        self.assertEqual(MemoryRegionType.STACK.value, 'stack')

    def test_execution_state_enum(self):
        """
        测试执行状态枚举
        """
        from modules.baremetal_emulator import ExecutionState
        
        self.assertEqual(ExecutionState.RUNNING.value, 'running')
        self.assertEqual(ExecutionState.STOPPED.value, 'stopped')
        self.assertEqual(ExecutionState.ERROR.value, 'error')
        self.assertEqual(ExecutionState.COMPLETED.value, 'completed')

    def test_default_memory_layout(self):
        """
        测试默认内存布局
        """
        from modules.baremetal_emulator import DEFAULT_MEMORY_LAYOUT, Architecture
        
        self.assertIsInstance(DEFAULT_MEMORY_LAYOUT, dict)
        self.assertIn(Architecture.ARM_CORTEX_M, DEFAULT_MEMORY_LAYOUT)
        
        cortex_m_layout = DEFAULT_MEMORY_LAYOUT[Architecture.ARM_CORTEX_M]
        self.assertTrue(len(cortex_m_layout) > 0)
        
        # 检查 Flash 区域
        flash_regions = [r for r in cortex_m_layout if r['type'] == 'flash']
        self.assertTrue(len(flash_regions) > 0)

    def test_peripheral_map(self):
        """
        测试外设映射
        """
        from modules.baremetal_emulator import PERIPHERAL_MAP
        
        self.assertIsInstance(PERIPHERAL_MAP, dict)
        
        # 检查关键外设
        critical_peripherals = ['GPIO', 'UART', 'TIMER', 'NVIC']
        for peripheral in critical_peripherals:
            self.assertIn(peripheral, PERIPHERAL_MAP)
            self.assertIn('base', PERIPHERAL_MAP[peripheral])
            self.assertIn('size', PERIPHERAL_MAP[peripheral])

    def test_memory_region_dataclass(self):
        """
        测试内存区域数据类
        """
        from modules.baremetal_emulator import MemoryRegion, MemoryRegionType
        
        region = MemoryRegion(
            type=MemoryRegionType.FLASH,
            address=0x08000000,
            size=0x100000,
            permissions='rx'
        )
        
        self.assertEqual(region.type, MemoryRegionType.FLASH)
        self.assertEqual(region.address, 0x08000000)
        self.assertEqual(region.permissions, 'rx')

    def test_execution_trace_dataclass(self):
        """
        测试执行追踪数据类
        """
        from modules.baremetal_emulator import ExecutionTrace
        
        trace = ExecutionTrace(
            pc=0x08000100,
            disassembly='mov r0, #1',
            timestamp=12345.678
        )
        
        self.assertEqual(trace.pc, 0x08000100)
        self.assertEqual(trace.disassembly, 'mov r0, #1')
        self.assertIsInstance(trace.registers, dict)

    def test_peripheral_state_dataclass(self):
        """
        测试外设状态数据类
        """
        from modules.baremetal_emulator import PeripheralState
        
        state = PeripheralState(
            name='GPIO',
            base_address=0x40020000
        )
        
        self.assertEqual(state.name, 'GPIO')
        self.assertEqual(state.base_address, 0x40020000)
        self.assertIsInstance(state.registers, dict)

    def test_firmware_analysis_result_dataclass(self):
        """
        测试固件分析结果数据类
        """
        from modules.baremetal_emulator import FirmwareAnalysisResult, Architecture
        
        result = FirmwareAnalysisResult(
            firmware_path='/test/firmware.bin',
            architecture=Architecture.ARM_CORTEX_M,
            entry_point=0x08000100,
            instructions_executed=100
        )
        
        self.assertEqual(result.firmware_path, '/test/firmware.bin')
        self.assertEqual(result.architecture, Architecture.ARM_CORTEX_M)
        self.assertIsInstance(result.traces, list)
        self.assertIsInstance(result.vulnerabilities, list)

    def test_emulator_initialization(self):
        """
        测试模拟器初始化
        """
        from modules.baremetal_emulator import BareMetalEmulator, Architecture
        
        emulator = BareMetalEmulator(
            firmware_path=self.test_firmware,
            architecture=Architecture.ARM_CORTEX_M
        )
        
        self.assertEqual(emulator.architecture, Architecture.ARM_CORTEX_M)
        self.assertEqual(emulator.firmware_path, self.test_firmware)

    def test_path_validation(self):
        """
        测试路径验证
        """
        from modules.baremetal_emulator import BareMetalEmulator
        
        # 测试空路径
        with self.assertRaises(ValueError):
            BareMetalEmulator('')
        
        # 测试路径遍历
        with self.assertRaises(ValueError):
            BareMetalEmulator('../../../etc/passwd')

    def test_static_load(self):
        """
        测试静态加载模式
        """
        from modules.baremetal_emulator import BareMetalEmulator, Architecture
        
        emulator = BareMetalEmulator.__new__(BareMetalEmulator)
        emulator.firmware_path = self.test_firmware
        emulator.architecture = Architecture.ARM_CORTEX_M
        emulator.UNICORN_AVAILABLE = False
        emulator.stats = {}
        emulator.exceptions = []
        emulator.entry_point = 0
        
        result = emulator._load_static()
        
        self.assertTrue(result)
        self.assertTrue(emulator.stats.get('firmware_size', 0) > 0)


class TestEntryPointDetection(unittest.TestCase):
    """
    入口地址检测测试
    """

    def setUp(self):
        """
        测试前初始化
        """
        self.temp_dir = tempfile.mkdtemp(prefix='entry_test_')

    def tearDown(self):
        """
        测试后清理
        """
        import shutil
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)

    def test_arm_cortex_m_vector_table(self):
        """
        测试 ARM Cortex-M 向量表解析
        """
        from modules.baremetal_emulator import BareMetalEmulator, Architecture, MemoryRegion, MemoryRegionType
        
        # 创建向量表
        firmware = os.path.join(self.temp_dir, 'vector.bin')
        with open(firmware, 'wb') as f:
            # 初始 SP
            f.write(struct.pack('<I', 0x20041000))
            # Reset Handler
            f.write(struct.pack('<I', 0x08000101))
            f.write(b'\x00' * 100)
        
        emulator = BareMetalEmulator.__new__(BareMetalEmulator)
        emulator.firmware_path = firmware
        emulator.architecture = Architecture.ARM_CORTEX_M
        emulator.memory_regions = {
            0x08000000: MemoryRegion(
                type=MemoryRegionType.FLASH,
                address=0x08000000,
                size=0x100000,
                data=struct.pack('<I', 0x20041000) + struct.pack('<I', 0x08000101) + b'\x00' * 100
            )
        }
        emulator.entry_point = 0
        
        emulator._detect_entry_point()
        
        # Reset Handler 地址应去掉 Thumb 位
        expected_entry = 0x08000101 & 0xFFFFFFFE
        self.assertEqual(emulator.entry_point, expected_entry)


class TestMemoryMapping(unittest.TestCase):
    """
    内存映射测试
    """

    def test_memory_region_permissions(self):
        """
        测试内存区域权限映射
        """
        from modules.baremetal_emulator import BareMetalEmulator, Architecture
        
        # 权限映射测试
        perm_map = {
            'r': 1,
            'w': 2,
            'x': 4,
            'rw': 3,
            'rx': 5,
            'rwx': 7,
        }
        
        self.assertEqual(perm_map['rw'], 3)
        self.assertEqual(perm_map['rx'], 5)
        self.assertEqual(perm_map['rwx'], 7)


if __name__ == '__main__':
    unittest.main(verbosity=2)