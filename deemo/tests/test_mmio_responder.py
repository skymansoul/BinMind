#!/usr/bin/env python3
"""
MMIO响应器单元测试
"""

import os
import sys
import unittest
import tempfile
import shutil

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.mmio_responder import (
    MMIOResponder, Peripheral, Register, RegisterField, RegisterAccessType,
    RegisterFieldType, AccessResult, MMIOAccess
)


class TestRegisterAccessTypeEnum(unittest.TestCase):
    """寄存器访问类型枚举测试"""
    
    def test_register_access_type_values(self):
        """测试寄存器访问类型枚举值"""
        self.assertEqual(RegisterAccessType.READ_ONLY.value, "read_only")
        self.assertEqual(RegisterAccessType.WRITE_ONLY.value, "write_only")
        self.assertEqual(RegisterAccessType.READ_WRITE.value, "read_write")
        self.assertEqual(RegisterAccessType.WRITE_ONE_TO_CLEAR.value, "write_one_to_clear")


class TestRegisterFieldTypeEnum(unittest.TestCase):
    """寄存器字段类型枚举测试"""
    
    def test_register_field_type_values(self):
        """测试寄存器字段类型枚举值"""
        self.assertEqual(RegisterFieldType.RESERVED.value, "reserved")
        self.assertEqual(RegisterFieldType.GENERAL.value, "general")
        self.assertEqual(RegisterFieldType.FLAG.value, "flag")
        self.assertEqual(RegisterFieldType.COUNTER.value, "counter")


class TestAccessResultEnum(unittest.TestCase):
    """访问结果枚举测试"""
    
    def test_access_result_values(self):
        """测试访问结果枚举值"""
        self.assertEqual(AccessResult.SUCCESS.value, "success")
        self.assertEqual(AccessResult.DENIED.value, "denied")
        self.assertEqual(AccessResult.OUT_OF_RANGE.value, "out_of_range")


class TestRegisterFieldDataclass(unittest.TestCase):
    """RegisterField数据类测试"""
    
    def test_register_field_creation(self):
        """测试寄存器字段创建"""
        field = RegisterField(
            name="status",
            bit_start=0,
            bit_end=3,
            field_type=RegisterFieldType.FLAG,
            description="状态标志",
            default_value=0
        )
        
        self.assertEqual(field.name, "status")
        self.assertEqual(field.bit_start, 0)
        self.assertEqual(field.bit_end, 3)


class TestRegisterDataclass(unittest.TestCase):
    """Register数据类测试"""
    
    def test_register_creation(self):
        """测试寄存器创建"""
        fields = [
            RegisterField(name="bit0", bit_start=0, bit_end=0),
            RegisterField(name="bit1", bit_start=1, bit_end=1)
        ]
        
        reg = Register(
            name="control",
            address=0x40000000,
            size=4,
            access_type=RegisterAccessType.READ_WRITE,
            reset_value=0x00,
            fields=fields
        )
        
        self.assertEqual(reg.name, "control")
        self.assertEqual(reg.address, 0x40000000)
        self.assertEqual(len(reg.fields), 2)


class TestPeripheralDataclass(unittest.TestCase):
    """Peripheral数据类测试"""
    
    def test_peripheral_creation(self):
        """测试外设创建"""
        registers = [
            Register(name="CR", address=0x40000000),
            Register(name="DR", address=0x40000004)
        ]
        
        peripheral = Peripheral(
            name="UART",
            base_address=0x40000000,
            size=0x100,
            registers=registers,
            description="UART外设"
        )
        
        self.assertEqual(peripheral.name, "UART")
        self.assertEqual(peripheral.base_address, 0x40000000)
        self.assertEqual(len(peripheral.registers), 2)


class TestMMIOResponder(unittest.TestCase):
    """MMIO响应器测试"""
    
    def setUp(self):
        """测试前准备"""
        self.temp_dir = tempfile.mkdtemp()
        self.responder = MMIOResponder()
    
    def tearDown(self):
        """测试后清理"""
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)
    
    def test_add_peripheral(self):
        """测试添加外设"""
        registers = [
            Register(name="CR", address=0x40000000, access_type=RegisterAccessType.READ_WRITE),
            Register(name="DR", address=0x40000004, access_type=RegisterAccessType.READ_WRITE)
        ]
        
        peripheral = Peripheral(
            name="UART",
            base_address=0x40000000,
            size=0x100,
            registers=registers
        )
        
        self.responder.add_peripheral(peripheral)
        
        self.assertIn("UART", self.responder.peripherals)
    
    def test_read_register(self):
        """测试读取寄存器"""
        registers = [
            Register(name="CR", address=0x40000000, reset_value=0x12345678),
            Register(name="DR", address=0x40000004, reset_value=0x00)
        ]
        
        peripheral = Peripheral(
            name="UART",
            base_address=0x40000000,
            size=0x100,
            registers=registers
        )
        
        self.responder.add_peripheral(peripheral)
        
        value, result = self.responder.read(0x40000000)
        
        self.assertEqual(result, AccessResult.SUCCESS)
        self.assertEqual(value, 0x12345678)
    
    def test_read_write_only_register(self):
        """测试读取写保护寄存器"""
        registers = [
            Register(name="DR", address=0x40000000, access_type=RegisterAccessType.WRITE_ONLY)
        ]
        
        peripheral = Peripheral(
            name="UART",
            base_address=0x40000000,
            size=0x100,
            registers=registers
        )
        
        self.responder.add_peripheral(peripheral)
        
        value, result = self.responder.read(0x40000000)
        
        self.assertEqual(result, AccessResult.DENIED)
    
    def test_write_register(self):
        """测试写入寄存器"""
        registers = [
            Register(name="CR", address=0x40000000, access_type=RegisterAccessType.READ_WRITE)
        ]
        
        peripheral = Peripheral(
            name="UART",
            base_address=0x40000000,
            size=0x100,
            registers=registers
        )
        
        self.responder.add_peripheral(peripheral)
        
        result = self.responder.write(0x40000000, 4, 0xABCDEF01)
        
        self.assertEqual(result, AccessResult.SUCCESS)
        
        # 验证写入成功
        value, _ = self.responder.read(0x40000000)
        self.assertEqual(value, 0xABCDEF01)
    
    def test_write_read_only_register(self):
        """测试写入只读寄存器"""
        registers = [
            Register(name="SR", address=0x40000000, access_type=RegisterAccessType.READ_ONLY)
        ]
        
        peripheral = Peripheral(
            name="UART",
            base_address=0x40000000,
            size=0x100,
            registers=registers
        )
        
        self.responder.add_peripheral(peripheral)
        
        result = self.responder.write(0x40000000, 4, 0x1234)
        
        self.assertEqual(result, AccessResult.DENIED)
    
    def test_write_one_to_clear(self):
        """测试写1清零"""
        registers = [
            Register(name="ISR", address=0x40000000, access_type=RegisterAccessType.WRITE_ONE_TO_CLEAR, reset_value=0xFFFF)
        ]
        
        peripheral = Peripheral(
            name="UART",
            base_address=0x40000000,
            size=0x100,
            registers=registers
        )
        
        self.responder.add_peripheral(peripheral)
        
        # 写入0x000F应该清除低4位
        self.responder.write(0x40000000, 4, 0x000F)
        
        value, _ = self.responder.read(0x40000000)
        self.assertEqual(value, 0xFFF0)  # 低4位被清除
    
    def test_access_out_of_range(self):
        """测试访问范围外地址"""
        registers = [
            Register(name="CR", address=0x40000000)
        ]
        
        peripheral = Peripheral(
            name="UART",
            base_address=0x40000000,
            size=0x100,
            registers=registers
        )
        
        self.responder.add_peripheral(peripheral)
        
        # 访问外设范围外的地址
        value, result = self.responder.read(0x50000000)
        
        self.assertEqual(result, AccessResult.OUT_OF_RANGE)
    
    def test_load_from_template(self):
        """测试从模板加载"""
        template_content = """
peripherals:
  - name: UART
    base_address: 0x40000000
    size: 256
    description: UART Controller
    registers:
      - name: CR
        address: 0x40000000
        size: 4
        access: read_write
        reset: 0x00
      - name: DR
        address: 0x40000004
        size: 4
        access: read_write
        reset: 0x00
"""
        
        template_path = os.path.join(self.temp_dir, "peripheral.yaml")
        with open(template_path, 'w') as f:
            f.write(template_content)
        
        self.responder.load_from_template(template_path)
        
        self.assertIn("UART", self.responder.peripherals)
    
    def test_generate_c_stub(self):
        """测试生成C语言存根"""
        registers = [
            Register(name="CR", address=0x40000000, reset_value=0x12),
            Register(name="DR", address=0x40000004, reset_value=0x00)
        ]
        
        peripheral = Peripheral(
            name="UART",
            base_address=0x40000000,
            size=0x100,
            registers=registers
        )
        
        self.responder.add_peripheral(peripheral)
        
        stub = self.responder.generate_stub_code('c')
        
        self.assertIn("uint32_t", stub)
        self.assertIn("mmio_read", stub)
        self.assertIn("mmio_write", stub)
    
    def test_generate_python_stub(self):
        """测试生成Python存根"""
        registers = [
            Register(name="CR", address=0x40000000),
            Register(name="DR", address=0x40000004)
        ]
        
        peripheral = Peripheral(
            name="UART",
            base_address=0x40000000,
            size=0x100,
            registers=registers
        )
        
        self.responder.add_peripheral(peripheral)
        
        stub = self.responder.generate_stub_code('python')
        
        self.assertIn("class MMIOPeripheral", stub)
        self.assertIn("def read", stub)
        self.assertIn("def write", stub)
    
    def test_reset(self):
        """测试重置"""
        registers = [
            Register(name="CR", address=0x40000000, reset_value=0x00)
        ]
        
        peripheral = Peripheral(
            name="UART",
            base_address=0x40000000,
            size=0x100,
            registers=registers
        )
        
        self.responder.add_peripheral(peripheral)
        
        # 修改寄存器值
        self.responder.write(0x40000000, 4, 0x12345678)
        
        # 记录一次访问
        self.responder.read(0x40000000)
        
        # 重置
        self.responder.reset()
        
        # 验证访问日志被清除
        self.assertEqual(len(self.responder.access_log), 0)
        
        # 验证寄存器恢复到复位值
        value, _ = self.responder.read(0x40000000)
        self.assertEqual(value, 0x00)
    
    def test_generate_report(self):
        """测试生成报告"""
        registers = [
            Register(name="CR", address=0x40000000)
        ]
        
        peripheral = Peripheral(
            name="UART",
            base_address=0x40000000,
            size=0x100,
            registers=registers
        )
        
        self.responder.add_peripheral(peripheral)
        
        report = self.responder.generate_report()
        
        self.assertIn("MMIO响应器分析报告", report)
        self.assertIn("UART", report)


if __name__ == '__main__':
    unittest.main()