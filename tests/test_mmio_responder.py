
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
    """旧版RegisterAccessType测试（重写为RegisterType枚举断言）"""

    def test_register_access_type_values(self):
        # RegisterAccessType 更名 RegisterType：成员固定四个，取值 ro/wo/rw/reserved
        self.assertEqual(
            [m.name for m in RegisterType],
            ["READ_ONLY", "WRITE_ONLY", "READ_WRITE", "RESERVED"],
        )
        self.assertIs(RegisterType("rw"), RegisterType.READ_WRITE)


class TestLegacyRegisterFieldType(unittest.TestCase):
    """旧版RegisterFieldType测试（功能并入RegisterSpec类型字段）"""

    def test_register_field_type_values(self):
        # RegisterFieldType 无对应新枚举：字段类型由 RegisterSpec.reg_type 表达
        reg = RegisterSpec(
            name="field", offset=0, size=4,
            reg_type=RegisterType.READ_ONLY, reset_value=0,
        )
        self.assertIs(reg.reg_type, RegisterType.READ_ONLY)


class TestLegacyAccessResult(unittest.TestCase):
    """旧版AccessResult测试（重写为StubResult成败语义断言）"""

    def test_access_result_values(self):
        # AccessResult 由 StubResult.success 表达：失败时 code 为空、无外设
        result = StubResult(success=False, code="", peripheral=None)
        self.assertFalse(result.success)
        self.assertEqual(result.code, "")
        self.assertIsNone(result.peripheral)


class TestLegacyRegisterField(unittest.TestCase):
    """旧版RegisterField测试（重写为RegisterSpec字段断言）"""

    def test_register_field_creation(self):
        # RegisterField 并入 RegisterSpec：offset/size/reg_type 承载字段语义
        reg = RegisterSpec(
            name="field0", offset=0x10, size=4,
            reg_type=RegisterType.WRITE_ONLY, reset_value=0,
        )
        self.assertEqual(reg.name, "field0")
        self.assertEqual(reg.offset, 0x10)
        self.assertIs(reg.reg_type, RegisterType.WRITE_ONLY)


class TestLegacyRegister(unittest.TestCase):
    """旧版Register测试（重写为RegisterSpec完整构造断言）"""

    def test_register_creation(self):
        # Register 更名 RegisterSpec：offset/size/reg_type/reset_value 全字段
        reg = RegisterSpec(
            name="DR", offset=0x04, size=4,
            reg_type=RegisterType.READ_WRITE, reset_value=0xFF,
        )
        self.assertEqual(reg.offset, 0x04)
        self.assertEqual(reg.size, 4)
        self.assertEqual(reg.reset_value, 0xFF)
        self.assertIs(reg.reg_type, RegisterType.READ_WRITE)


class TestLegacyPeripheral(unittest.TestCase):
    """旧版Peripheral测试（重写为PeripheralSpec派生属性断言）"""

    def test_peripheral_creation(self):
        # Peripheral 更名 PeripheralSpec：base_addr 属性与按名查寄存器
        regs = [
            RegisterSpec(name="CR", offset=0x00, size=4, reg_type=RegisterType.READ_WRITE, reset_value=0),
            RegisterSpec(name="SR", offset=0x04, size=4, reg_type=RegisterType.READ_ONLY, reset_value=0),
        ]
        peripheral = PeripheralSpec(name="SPI", base_address=0x40001000, registers=regs)
        self.assertEqual(peripheral.base_addr, 0x40001000)
        self.assertIs(peripheral.register_by_name("SR"), regs[1])
        self.assertIsNone(peripheral.register_by_name("NOPE"))


class TestLegacyMMIOResponder(unittest.TestCase):
    """旧版MMIOResponder方法测试（重写为真实新API断言）"""

    def test_add_peripheral(self):
        # add_peripheral 更名 define_peripheral：按名注册 PeripheralSpec
        responder = MMIOResponder()
        regs = [RegisterSpec(name="CR", offset=0, size=4, reg_type=RegisterType.READ_WRITE, reset_value=0)]
        spec = PeripheralSpec(name="TIM", base_address=0x40002000, registers=regs)
        responder.define_peripheral(spec)
        self.assertIn("TIM", responder.peripherals)
        self.assertIs(responder.peripherals["TIM"], spec)

    def test_read_register(self):
        # read 移除——由生成存根中的 _read 函数承载读语义
        regs = [
            RegisterSpec(name="R0", offset=0x00, size=4, reg_type=RegisterType.READ_ONLY, reset_value=0),
            RegisterSpec(name="R1", offset=0x04, size=4, reg_type=RegisterType.READ_WRITE, reset_value=0),
        ]
        periph = PeripheralSpec(name="READDEV", base_address=0x60000000, registers=regs)
        code = StubGenerator.generate(periph)
        self.assertIn("READDEV_read(", code)
        self.assertIn("READDEV_BASE_ADDR + offset", code)
        self.assertIn("uint32_t", code)

    def test_read_write_only_register(self):
        # 读语义落在存根 _read 上；WRITE_ONLY 寄存器仍生成 OFFSET 宏
        regs = [RegisterSpec(name="WO", offset=0x08, size=4, reg_type=RegisterType.WRITE_ONLY, reset_value=0)]
        periph = PeripheralSpec(name="WODEV", base_address=0x60000000, registers=regs)
        code = StubGenerator.generate(periph)
        self.assertIn("WODEV_WO_OFFSET", code)
        self.assertIn("WODEV_read(", code)

    def test_write_register(self):
        # write 移除——存根中的 _write 函数承载写语义，写入基址加偏移
        regs = [RegisterSpec(name="CR", offset=0x00, size=4, reg_type=RegisterType.READ_WRITE, reset_value=0)]
        periph = PeripheralSpec(name="WRDEV", base_address=0x60000000, registers=regs)
        code = StubGenerator.generate(periph)
        self.assertIn("WRDEV_write(", code)
        self.assertIn("WRDEV_BASE_ADDR + offset", code)
        self.assertIn("= value", code)

    def test_write_read_only_register(self):
        # 旧 write 语义由存根承载；READ_ONLY 寄存器照常进入 reset 写入段
        regs = [RegisterSpec(name="SR", offset=0x04, size=4, reg_type=RegisterType.READ_ONLY, reset_value=0x01)]
        periph = PeripheralSpec(name="RODEV", base_address=0x60000000, registers=regs)
        code = StubGenerator.generate(periph)
        self.assertIn("RODEV_SR_OFFSET", code)
        self.assertIn("RODEV_SR_OFFSET) = 0x1;", code)

    def test_access_out_of_range(self):
        # 越界语义等价于运行未注册外设：run 返回 success=False
        responder = MMIOResponder()
        result = responder.run("OUT_OF_RANGE_DEV")
        self.assertFalse(result.success)
        self.assertEqual(result.code, "")
        self.assertIsNone(result.peripheral)

    def test_load_from_template(self):
        # 改进标记——当前设计可简化
        # load_from_template 移除——工厂函数 create_mmio_responder 承担模板化构造
        regs = [
            {"name": "CR", "offset": 0x00, "size": 4, "type": RegisterType.READ_WRITE, "reset": 0x00},
            {"name": "SR", "offset": 0x04, "size": 4, "type": RegisterType.READ_ONLY, "reset": 0x01},
        ]
        responder = create_mmio_responder(registers=regs, base=0x40000000)
        self.assertIn("custom", responder.peripherals)
        code = responder.run("custom").code
        self.assertIn("custom_CR_OFFSET", code)
        self.assertIn("custom_SR_OFFSET", code)

    def test_generate_python_stub(self):
        # 存根仅生成 C 代码——断言 C 头包含与函数定义，无 Python 分支
        regs = [RegisterSpec(name="CR", offset=0x00, size=4, reg_type=RegisterType.READ_WRITE, reset_value=0)]
        periph = PeripheralSpec(name="CDEV", base_address=0x40000000, registers=regs)
        code = StubGenerator.generate(periph)
        self.assertIn("#include <stdint.h>", code)
        self.assertIn("CDEV_reset(void)", code)
        self.assertNotIn("def ", code)

    def test_reset(self):
        # reset/access_log 移除——复位语义由存根 reset() 函数承载
        regs = [
            RegisterSpec(name="CR", offset=0x00, size=4, reg_type=RegisterType.READ_WRITE, reset_value=0x12),
            RegisterSpec(name="RSVD", offset=0x08, size=4, reg_type=RegisterType.RESERVED, reset_value=0xAA),
        ]
        periph = PeripheralSpec(name="RSTDEV", base_address=0x40000000, registers=regs)
        code = StubGenerator.generate(periph)
        self.assertIn("RSTDEV_reset(void)", code)
        # RESERVED 寄存器不出现在复位写入段
        self.assertNotIn("RSTDEV_RSVD_OFFSET) = 0xaa;", code)
        self.assertIn("RSTDEV_CR_OFFSET) = 0x12;", code)


if __name__ == '__main__':
    unittest.main()


