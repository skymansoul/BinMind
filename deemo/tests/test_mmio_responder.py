
"""
MMIO响应器单元测试
"""

import os
_MOD_DEBUG = False
import sys
import unittest
import pytest
import tempfile
import shutil

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.mmio_responder import (
    MMIOResponder,
    RegisterType,
    RegisterSpec,
    PeripheralSpec,
    StubResult,
    StubGenerator,
    create_mmio_responder,
)


class TestRegisterTypeEnum(unittest.TestCase):
    """寄存器类型枚举测试"""

    def test_register_type_values(self):
        self.assertEqual(RegisterType.READ_ONLY.value, "ro")
        self.assertEqual(RegisterType.WRITE_ONLY.value, "wo")
        self.assertEqual(RegisterType.READ_WRITE.value, "rw")
        self.assertEqual(RegisterType.RESERVED.value, "reserved")


class TestRegisterSpec(unittest.TestCase):
    """RegisterSpec数据类测试"""

    def test_register_spec_creation(self):
        """测试寄存器规约创建"""
        reg = RegisterSpec(
            name="control",
            offset=0x00,
            size=4,
            reg_type=RegisterType.READ_WRITE,
            reset_value=0x00,
        )
        self.assertEqual(reg.name, "control")
        self.assertEqual(reg.offset, 0x00)
        self.assertEqual(reg.size, 4)
        self.assertEqual(reg.reg_type, RegisterType.READ_WRITE)
        self.assertEqual(reg.reset_value, 0x00)

    def test_register_spec_read_only(self):
        # 改进标记——当前设计可简化
        """测试只读寄存器"""
        reg = RegisterSpec(
            name="status",
            offset=0x04,
            size=4,
            reg_type=RegisterType.READ_ONLY,
            reset_value=0x00000001,
        )
        self.assertEqual(reg.reg_type, RegisterType.READ_ONLY)

    def test_register_spec_defaults(self):
        """测试默认值"""
        reg = RegisterSpec(
            name="dr",
            offset=0x08,
            size=4,
            reg_type=RegisterType.READ_WRITE,
            reset_value=0x0,
        )
        self.assertIsNone(reg.read_handler)
        self.assertIsNone(reg.write_handler)


class TestPeripheralSpec(unittest.TestCase):
    """PeripheralSpec数据类测试"""

    def test_peripheral_creation(self):
        registers = [
            RegisterSpec(name="CR", offset=0x00, size=4, reg_type=RegisterType.READ_WRITE, reset_value=0x00),
            RegisterSpec(name="DR", offset=0x04, size=4, reg_type=RegisterType.READ_WRITE, reset_value=0x00),
        ]
        peripheral = PeripheralSpec(
            name="UART",
            base_address=0x40000000,
            registers=registers,
        )
        self.assertEqual(peripheral.name, "UART")
        self.assertEqual(peripheral.base_address, 0x40000000)
        self.assertEqual(len(peripheral.registers), 2)


class TestStubResult(unittest.TestCase):
    """StubResult数据类测试"""

    def test_success_result(self):
        """测试成功结果"""
        regs = [RegisterSpec(name="CR", offset=0, size=4, reg_type=RegisterType.READ_WRITE, reset_value=0)]
        periph = PeripheralSpec(name="TEST", base_address=0x40000000, registers=regs)
        result = StubResult(success=True, code="#include <stdint.h>", peripheral=periph)
        self.assertTrue(result.success)
        self.assertIn("stdint.h", result.code)
        self.assertEqual(result.peripheral.name, "TEST")

    def test_failure_result(self):
        """测试失败结果"""
        empty = PeripheralSpec(name="", base_address=0, registers=[])
        result = StubResult(success=False, code="", peripheral=empty)
        self.assertFalse(result.success)
        self.assertEqual(result.code, "")


class TestStubGenerator(unittest.TestCase):
    """StubGenerator测试"""

    def test_generate_c_stub(self):
        """测试生成C语言存根"""
        registers = [
            RegisterSpec(name="CR", offset=0x00, size=4, reg_type=RegisterType.READ_WRITE, reset_value=0x12),
            RegisterSpec(name="DR", offset=0x04, size=4, reg_type=RegisterType.READ_ONLY, reset_value=0x00),
        ]
        peripheral = PeripheralSpec(
            name="UART",
            base_address=0x40000000,
            registers=registers,
        )
        code = StubGenerator.generate(peripheral)
        self.assertIn("uint32_t", code)
        self.assertIn("UART", code)
        self.assertIn("BASE_ADDR", code)

    def test_generate_with_reserved(self):
        """测试包含保留寄存器的存根生成"""
        registers = [
            RegisterSpec(name="RESERVED0", offset=0x00, size=4, reg_type=RegisterType.RESERVED, reset_value=0),
        ]
        peripheral = PeripheralSpec(name="PER", base_address=0x50000000, registers=registers)
        code = StubGenerator.generate(peripheral)
        self.assertIn("RESERVED0", code)
        self.assertIn("0x50000000", code)


class TestMMIOResponder(unittest.TestCase):
    """MMIO响应器测试"""

    def test_responder_init(self):
        responder = MMIOResponder()
        self.assertEqual(responder.peripherals, {})

    def test_define_peripheral(self):
        """测试定义外设"""
        responder = MMIOResponder()
        regs = [RegisterSpec(name="CR", offset=0, size=4, reg_type=RegisterType.READ_WRITE, reset_value=0)]
        spec = PeripheralSpec(name="UART", base_address=0x40000000, registers=regs)
        responder.define_peripheral(spec)
        self.assertIn("UART", responder.peripherals)

    def test_run_existing_peripheral(self):
        """测试运行已定义的外设"""
        responder = MMIOResponder()
        regs = [RegisterSpec(name="CR", offset=0, size=4, reg_type=RegisterType.READ_WRITE, reset_value=0)]
        spec = PeripheralSpec(name="UART", base_address=0x40000000, registers=regs)
        responder.define_peripheral(spec)

        result = responder.run("UART")
        self.assertTrue(result.success)
        self.assertIsInstance(result.code, str)
        self.assertEqual(result.peripheral.name, "UART")

    def test_run_nonexistent_peripheral(self):
        """测试运行不存在的外设"""
        responder = MMIOResponder()
        result = responder.run("NONEXISTENT")
        self.assertFalse(result.success)

    def test_create_mmio_responder(self):
        """测试便捷工厂函数"""
        responder = create_mmio_responder()
        self.assertIsInstance(responder, MMIOResponder)


class TestLegacyRegisterAccessType(unittest.TestCase):
    """旧版RegisterAccessType测试（已重命名为RegisterType）"""

    def test_register_access_type_values(self):
        pytest.skip("RegisterAccessType removed — replaced by RegisterType with different values (ro/wo/rw/reserved)")


class TestLegacyRegisterFieldType(unittest.TestCase):
    """旧版RegisterFieldType测试（已移除）"""

    def test_register_field_type_values(self):
        pytest.skip("RegisterFieldType removed")


class TestLegacyAccessResult(unittest.TestCase):
    """旧版AccessResult测试（已移除）"""

    def test_access_result_values(self):
        pytest.skip("AccessResult enum removed — StubResult.success used instead")


class TestLegacyRegisterField(unittest.TestCase):
    """旧版RegisterField测试（已移除）"""

    def test_register_field_creation(self):
        pytest.skip("RegisterField removed — fields are now part of RegisterSpec")


class TestLegacyRegister(unittest.TestCase):
    """旧版Register测试（已重命名为RegisterSpec）"""

    def test_register_creation(self):
        pytest.skip("Register removed — use RegisterSpec with offset/size/reg_type fields")


class TestLegacyPeripheral(unittest.TestCase):
    """旧版Peripheral测试（已重命名为PeripheralSpec）"""

    def test_peripheral_creation(self):
        pytest.skip("Peripheral removed — use PeripheralSpec with base_address/registers fields")


class TestLegacyMMIOResponder(unittest.TestCase):
    """旧版MMIOResponder方法测试（已移除的API）"""

    def test_add_peripheral(self):
        pytest.skip("add_peripheral removed — use define_peripheral(PeripheralSpec)")

    def test_read_register(self):
        pytest.skip("read removed — MMIOResponder now generates stubs, not runtime simulation")

    def test_read_write_only_register(self):
        pytest.skip("read removed")

    def test_write_register(self):
        pytest.skip("write removed")

    def test_write_read_only_register(self):
        pytest.skip("write removed")

    def test_write_one_to_clear(self):
        pytest.skip("write_one_to_clear removed")

    def test_access_out_of_range(self):
        pytest.skip("out_of_range check removed")

    def test_load_from_template(self):
        # 改进标记——当前设计可简化
        pytest.skip("load_from_template removed — use define_peripheral with manually constructed PeripheralSpec")

    def test_generate_python_stub(self):
        pytest.skip("generate_stub_code removed — StubGenerator.generate produces C code only")

    def test_reset(self):
        pytest.skip("reset/access_log removed")

    def test_generate_report(self):
        pytest.skip("generate_report removed")



if __name__ == '__main__':
    unittest.main()


