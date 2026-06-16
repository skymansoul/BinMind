"""
测试Gadget组合器模块
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from modules.gadget_composer import (
    GadgetScanner,
    GadgetComposer,
    Gadget,
    GadgetType,
    Architecture,
    GadgetChain,
    scan_gadgets,
    create_gadget_chain
)


class TestGadgetScanner(unittest.TestCase):
    """测试Gadget扫描器"""
    
    def test_scanner_init(self):
        """测试扫描器初始化"""
        scanner = GadgetScanner(Architecture.X86_64)
        self.assertEqual(scanner.architecture, Architecture.X86_64)
    
    def test_scan_memory_empty(self):
        """测试扫描空内存"""
        scanner = GadgetScanner(Architecture.X86_64)
        gadgets = scanner.scan_memory(b'')
        self.assertEqual(len(gadgets), 0)
    
    def test_scan_memory_with_ret(self):
        """测试扫描包含ret指令的内存"""
        scanner = GadgetScanner(Architecture.X86_64)
        # x86_64 ret指令是0xc3
        memory = b'\xc3'
        gadgets = scanner.scan_memory(memory, 0x1000)
        self.assertEqual(len(gadgets), 1)
        self.assertEqual(gadgets[0].address, 0x1000)
        self.assertEqual(gadgets[0].type, GadgetType.ROP)
    
    def test_scan_memory_pop_rdi_ret(self):
        """测试扫描pop rdi; ret序列"""
        scanner = GadgetScanner(Architecture.X86_64)
        # pop rdi = 0x5f, ret = 0xc3
        memory = b'\x5f\xc3'
        gadgets = scanner.scan_memory(memory, 0x2000)
        self.assertGreaterEqual(len(gadgets), 1)


class TestGadgetComposer(unittest.TestCase):
    """测试Gadget组合器"""
    
    def setUp(self):
        """设置测试数据"""
        self.test_gadgets = [
            Gadget(
                address=0x1000,
                type=GadgetType.ROP,
                instructions=['pop rdi', 'ret'],
                bytes=b'\x5f\xc3',
                registers_read=set(),
                registers_written={'rdi'},
                stack_effect=8,
                description='pop rdi; ret'
            ),
            Gadget(
                address=0x1002,
                type=GadgetType.ROP,
                instructions=['pop rsi', 'ret'],
                bytes=b'\x5e\xc3',
                registers_read=set(),
                registers_written={'rsi'},
                stack_effect=8,
                description='pop rsi; ret'
            ),
            Gadget(
                address=0x1004,
                type=GadgetType.SYSCALL,
                instructions=['syscall'],
                bytes=b'\x0f\x05',
                registers_read=set(),
                registers_written=set(),
                stack_effect=0,
                description='syscall'
            ),
            Gadget(
                address=0x1006,
                type=GadgetType.XCHG,
                instructions=['xchg rax, rsp', 'ret'],
                bytes=b'\x48\x91\xc3',
                registers_read={'rax', 'rsp'},
                registers_written={'rax', 'rsp'},
                stack_effect=0,
                description='xchg rax, rsp; ret'
            )
        ]
        self.composer = GadgetComposer(self.test_gadgets)
    
    def test_composer_init(self):
        """测试组合器初始化"""
        self.assertEqual(len(self.composer.gadgets), 4)
    
    def test_find_gadget_by_type(self):
        """测试按类型查找Gadget"""
        rop_gadgets = self.composer.find_gadget(type=GadgetType.ROP)
        self.assertIsNotNone(rop_gadgets)
    
    def test_find_gadget_by_description(self):
        """测试按描述查找Gadget"""
        pop_rdi = self.composer.find_gadget(description_contains='pop rdi')
        self.assertIsNotNone(pop_rdi)
        self.assertEqual(pop_rdi.address, 0x1000)
    
    def test_compose_chain_simple(self):
        """测试简单链组合"""
        chain = self.composer.compose_chain("把 X 赋值给 RDI")
        self.assertIsNotNone(chain)
        self.assertEqual(len(chain.gadgets), 1)
    
    def test_compose_chain_complex(self):
        """测试复杂链组合"""
        chain = self.composer.compose_chain("把 X 赋值给 RDI，把 Y 赋值给 RSI")
        self.assertIsNotNone(chain)
        self.assertEqual(len(chain.gadgets), 2)
    
    def test_find_srop_chain(self):
        """测试查找SROP链"""
        chain = self.composer.find_srop_chain(0xf)  # sigreturn syscall number
        self.assertIsNotNone(chain)
        self.assertEqual(len(chain.gadgets), 2)
    
    def test_generate_shellcode_chain(self):
        """测试生成shellcode链"""
        # 添加jmp rax gadget用于测试
        jmp_rax_gadget = Gadget(
            address=0x1008,
            type=GadgetType.ROP,
            instructions=['jmp rax'],
            bytes=b'\xff\xe0',
            registers_read={'rax'},
            registers_written=set(),
            stack_effect=0,
            description='jmp rax'
        )
        composer = GadgetComposer(self.test_gadgets + [jmp_rax_gadget])
        
        chain = composer.generate_shellcode_chain(0xdeadbeef)
        self.assertIsNotNone(chain)
        self.assertEqual(len(chain.gadgets), 1)
    
    def test_calculate_probability(self):
        """测试概率计算"""
        chain = self.composer.compose_chain("把 X 赋值给 RDI")
        if chain:
            self.assertGreater(chain.success_probability, 0.0)
            self.assertLessEqual(chain.success_probability, 1.0)


class TestConvenienceFunctions(unittest.TestCase):
    """测试便捷函数"""
    
    def test_scan_gadgets(self):
        """测试扫描Gadgets函数"""
        memory = b'\x5f\xc3'  # pop rdi; ret
        gadgets = scan_gadgets(memory, 0x1000, 'x86_64')
        self.assertGreaterEqual(len(gadgets), 1)
    
    def test_create_gadget_chain(self):
        """测试创建Gadget链函数"""
        gadgets = [
            Gadget(
                address=0x1000,
                type=GadgetType.ROP,
                instructions=['pop rdi', 'ret'],
                bytes=b'\x5f\xc3',
                registers_read=set(),
                registers_written={'rdi'},
                stack_effect=8,
                description='pop rdi; ret'
            )
        ]
        chain = create_gadget_chain(gadgets, "把 X 赋值给 RDI")
        self.assertIsNotNone(chain)


if __name__ == '__main__':
    unittest.main()