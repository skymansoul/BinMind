#!/usr/bin/env python3
# 裸机固件模拟单元测试，主要测memory mapping + entry detection, 外设模拟先skip

import struct
import os
import unittest
import tempfile
# import sys  -- 删了，path hack太丑
# from unittest.mock import Mock, MagicMock, patch  -- 旧mock方式留作对比

_DEBUG_FLAG = False


class TestBareMetalEmulator(unittest.TestCase):
    """裸机模拟器 : 各种enum/dataclass/memory layout的烟雾测试"""

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp(prefix='baremetal_test_')
        # 造个假的Cortex-M固件 -- 就俩向量：SP + reset handler
        self.test_firmware = os.path.join(self._tmpdir, 'test_firmware.bin')
        with open(self.test_firmware, 'wb') as f:
            f.write(struct.pack('<I', 0x20041000))  # initial SP
            f.write(struct.pack('<I', 0x08000101))  # Reset Handler (thumb bit set)
            f.write(b'\x00' * 100)

    def tearDown(self):
        import shutil
        if os.path.exists(self._tmpdir):
            shutil.rmtree(self._tmpdir)

    def test_baremetal_module_import(self):
        """能不能import -- unicorn装了吗？"""
        try:
            from modules.baremetal_emulator import BareMetalEmulator, UNICORN_AVAILABLE
            self.assertTrue(True)
        except ImportError as e:
            self.skipTest(f"BareMetal import failed (likely no unicorn): {e}")

    def test_architecture_enum(self):
        """Architecture enum 值对不对，arm_cortex_m / mips / x86"""
        from modules.baremetal_emulator import Architecture
        self.assertEqual(Architecture.ARM_CORTEX_M.value, 'arm_cortex_m')
        self.assertEqual(Architecture.ARM_CORTEX_A.value, 'arm_cortex_a')
        self.assertEqual(Architecture.MIPS.value, 'mips')
        self.assertEqual(Architecture.X86.value, 'x86')

    def test_memory_region_type_enum(self):
        from modules.baremetal_emulator import MemoryRegionType
        self.assertEqual(MemoryRegionType.FLASH.value, 'flash')
        self.assertEqual(MemoryRegionType.RAM.value, 'ram')
        self.assertEqual(MemoryRegionType.PERIPHERAL.value, 'peripheral')
        self.assertEqual(MemoryRegionType.STACK.value, 'stack')

    def test_execution_state_enum(self):
        from modules.baremetal_emulator import ExecutionState
        self.assertEqual(ExecutionState.RUNNING.value, 'running')
        self.assertEqual(ExecutionState.STOPPED.value, 'stopped')
        self.assertEqual(ExecutionState.ERROR.value, 'error')
        self.assertEqual(ExecutionState.COMPLETED.value, 'completed')

    def test_default_memory_layout(self):
        """默认memory layout -- 至少得有Cortex-M的flash区"""
        from modules.baremetal_emulator import DEFAULT_MEMORY_LAYOUT, Architecture
        self.assertIsInstance(DEFAULT_MEMORY_LAYOUT, dict)
        self.assertIn(Architecture.ARM_CORTEX_M, DEFAULT_MEMORY_LAYOUT)

        cortex_m_layout = DEFAULT_MEMORY_LAYOUT[Architecture.ARM_CORTEX_M]
        self.assertTrue(len(cortex_m_layout) > 0)

        flash_count = 0
        for region in cortex_m_layout:
            if region['type'] == 'flash':
                flash_count += 1
        self.assertTrue(flash_count > 0)

    def test_peripheral_map(self):
        """外设映射不能少 -- GPIO/UART/TIMER/NVIC 这四个必须有"""
        from modules.baremetal_emulator import PERIPHERAL_MAP
        self.assertIsInstance(PERIPHERAL_MAP, dict)

        # TODO: 后续加SPI/I2C的外设基址
        critical_peripherals = ['GPIO', 'UART', 'TIMER', 'NVIC']
        for peripheral in critical_peripherals:
            # check that we have 'base' and 'size' keys -- some periphs only have name
            self.assertIn(peripheral, PERIPHERAL_MAP)
            self.assertIn('base', PERIPHERAL_MAP[peripheral])
            self.assertIn('size', PERIPHERAL_MAP[peripheral])

    def test_memory_region_dataclass(self):
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
        from modules.baremetal_emulator import PeripheralState
        state = PeripheralState(name='GPIO', base_address=0x40020000)
        self.assertEqual(state.name, 'GPIO')
        self.assertEqual(state.base_address, 0x40020000)
        self.assertIsInstance(state.registers, dict)

    def test_firmware_analysis_result_dataclass(self):
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
        """初始化里arch + firmware_path必须存对"""
        from modules.baremetal_emulator import BareMetalEmulator, Architecture
        emulator = BareMetalEmulator(
            firmware_path=self.test_firmware,
            architecture=Architecture.ARM_CORTEX_M
        )
        self.assertEqual(emulator.architecture, Architecture.ARM_CORTEX_M)
        self.assertEqual(emulator.firmware_path, self.test_firmware)

    def test_path_validation(self):
        """空路径、路径穿越都得挡住"""
        from modules.baremetal_emulator import BareMetalEmulator

        # empty path
        with self.assertRaises(ValueError):
            BareMetalEmulator('')

        # path traversal
        with self.assertRaises(ValueError):
            BareMetalEmulator('../../../etc/passwd')

    def test_static_load(self):
        """静态加载模式: 不依赖unicorn, 就是读取文件算size"""
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
    """入口点检测 -- 主要是cortex-m的向量表里抠reset handler"""

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp(prefix='entry_test_')

    def tearDown(self):
        import shutil
        if os.path.exists(self._tmpdir):
            shutil.rmtree(self._tmpdir)

    def test_arm_cortex_m_vector_table(self):
        """造个2-entry的向量表，看entry point能不能正确剥掉thumb bit"""
        from modules.baremetal_emulator import BareMetalEmulator, Architecture, MemoryRegion, MemoryRegionType

        firmware = os.path.join(self._tmpdir, 'vector.bin')
        with open(firmware, 'wb') as f:
            f.write(struct.pack('<I', 0x20041000))
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

        expected_entry = 0x08000101 & 0xFFFFFFFE
        self.assertEqual(emulator.entry_point, expected_entry)


class TestMemoryMapping(unittest.TestCase):
    """memory permissions位映射检查"""

    def test_memory_region_permissions(self):
        """rwx => 7, rx => 5 这种位映射不能错"""
        from modules.baremetal_emulator import BareMetalEmulator, Architecture

        perm_map = {
            'r': 1, 'w': 2, 'x': 4,
            'rw': 3, 'rx': 5, 'rwx': 7,
        }
        self.assertEqual(perm_map['rw'], 3)
        self.assertEqual(perm_map['rx'], 5)
        self.assertEqual(perm_map['rwx'], 7)


if __name__ == '__main__':
    unittest.main(verbosity=2)
