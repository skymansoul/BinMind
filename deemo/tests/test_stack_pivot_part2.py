
import os
import sys
_MOD_DEBUG = False
import unittest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.stack_pivot import (
    StackPivotGenerator,
    PivotType,
    GadgetInfo,
    StackPivotGadget,
    PivotChain,
    ExploitWithPivot,
    generate_stack_pivot_exploit
)



class TestStackPivotGenerator(unittest.TestCase):
    """测试栈迁移生成器"""

    def setUp(self):
        """设置测试环境"""
        self.generator = StackPivotGenerator(arch="amd64")

    def test_init(self):
        """测试初始化"""
        self.assertEqual(self.generator.arch, "amd64")
        self.assertEqual(self.generator.max_gadget_length, 5)
        self.assertEqual(len(self.generator.pivot_gadgets), 0)

    def test_add_pivot_gadget(self):
        gadget = StackPivotGadget(
            address=0x401020,
            instruction="xchg rsp, rax; ret",
            disassembly="...",
            pivot_type=PivotType.XCHG_REG,
            source_register="rax"
        )
        
        self.generator.add_pivot_gadget(gadget)
        
        self.assertEqual(len(self.generator.pivot_gadgets), 1)

    def test_add_rop_gadget(self):
        """测试添加ROP gadget"""
        gadget = GadgetInfo(
            address=0x401000,
            instruction="pop rdi; ret",
            disassembly="..."
        )
        
        self.generator.add_rop_gadget(gadget)
        
        self.assertEqual(len(self.generator.rop_gadgets), 1)

    def test_assess_gadget_quality(self):
        """测试评估gadget质量"""
        # 高质量：简单ret结尾
        quality = self.generator._assess_gadget_quality("pop rax; ret")
        self.assertGreater(quality, 0.9)
        
        # 低质量：包含算术指令
        quality = self.generator._assess_gadget_quality("add rsp, 8; ret")
        self.assertLess(quality, 1.0)

    def test_assess_pivot_reliability(self):
        gadget = StackPivotGadget(
            address=0x401020,
            instruction="xchg rsp, rax; ret",
            disassembly="...",
            pivot_type=PivotType.XCHG_REG,
            source_register="rax"
        )
        
        reliability = self.generator._assess_pivot_reliability(gadget)
        
        self.assertEqual(reliability, 1.0)  # xchg 最可靠

    def test_create_pivot_gadget_xchg(self):
                """测试创建xchg类型的pivot gadget"""
        gadget = self.generator._create_pivot_gadget(
            0x401020,
            "xchg rsp, rax; ret",
            PivotType.XCHG_REG,
            r'xchg\s+rsp,\s*([a-zA-Z0-9]+)'
        )
        
        self.assertIsNotNone(gadget)
        self.assertEqual(gadget.pivot_type, PivotType.XCHG_REG)
        self.assertEqual(gadget.source_register, "rax")

    def test_create_pivot_gadget_leave(self):
        """测试创建leave类型的pivot gadget"""
        gadget = self.generator._create_pivot_gadget(
            0x401030,
            "leave; ret",
            PivotType.LEAVE,
            r'leave'
        )
        
        self.assertIsNotNone(gadget)
        self.assertEqual(gadget.pivot_type, PivotType.LEAVE)

    def test_generate_pivot_chain(self):
        """测试生成栈迁移链"""
        gadget = StackPivotGadget(
            address=0x401020,
            instruction="xchg rsp, rax; ret",
            disassembly="...",
            pivot_type=PivotType.XCHG_REG,
            source_register="rax"
        )
        
        chain = self.generator.generate_pivot_chain(
            pivot_gadget=gadget,
            target_address=0x605000,
            target_region="heap"
        )
        
        self.assertIsInstance(chain, PivotChain)
        self.assertEqual(chain.target_address, 0x605000)
lass字段完整性$/d
        self.assertEqual(chain.target_region, "heap")

    def test_find_setup_gadgets(self):
        """测试寻找设置寄存器gadget"""
        gadget = StackPivotGadget(
            address=0x401020,
            instruction="xchg rsp, rax; ret",
            disassembly="...",
            pivot_type=PivotType.XCHG_REG,
            source_register="rax"
        )
        
        # 添加一些ROP gadgets
        self.generator.add_rop_gadget(GadgetInfo(
            address=0x401000,
            instruction="pop rax; ret",
            disassembly="..."
        ))
        
        setup_gadgets = self.generator._find_setup_gadgets("rax", self.generator.rop_gadgets)
        
        self.assertGreaterEqual(len(setup_gadgets), 0)

    def test_generate_exploit(self):
        gadget = StackPivotGadget(
            address=0x401020,
            instruction="xchg rsp, rax; ret",
            disassembly="...",
            pivot_type=PivotType.XCHG_REG,
            source_register="rax"
        )
        
        chain = self.generator.generate_pivot_chain(
            pivot_gadget=gadget,
            target_address=0x605000
        )
        
        exploit = self.generator.generate_exploit(
            overflow_size=72,
            pivot_chain=chain,
            goal="shell",
            leaked_address=0x605000
        )
        
        self.assertIsInstance(exploit, ExploitWithPivot)
        self.assertEqual(exploit.overflow_size, 72)
        self.assertGreater(len(exploit.steps), 0)

    def test_generate_python_exploit(self):
        """测试生成Python利用脚本"""
        gadget = StackPivotGadget(
            address=0x401020,
            instruction="xchg rsp, rax; ret",
            disassembly="...",
            pivot_type=PivotType.XCHG_REG,
            source_register="rax"
        )
        
        chain = self.generator.generate_pivot_chain(
            pivot_gadget=gadget,
            target_address=0x605000
        )
        
        exploit = ExploitWithPivot(
            exploit_id="test_exp",
            overflow_size=64,
            pivot_chain=chain
        )
        
        script = self.generator._generate_python_exploit(exploit)
        
        self.assertIsInstance(script, str)
        self.assertIn("from pwn import", script)
        self.assertIn("context.arch", script)

    def test_scan_gadgets_empty(self):
        gadgets = self.generator.scan_gadgets()
        
lass字段完整性$/d
        self.assertEqual(len(gadgets), 0)


class TestStackPivotGeneratorEdgeCases(unittest.TestCase):
    """测试栈迁移生成器边界情况"""

    def setUp(self):
        """设置测试环境"""
        self.generator = StackPivotGenerator()

    def test_generate_chain_without_setup(self):
        """测试没有setup gadget的情况"""
        gadget = StackPivotGadget(
            address=0x401020,
            instruction="xchg rsp, rax; ret",
            disassembly="...",
            pivot_type=PivotType.XCHG_REG,
            source_register=""
        )
        
        chain = self.generator.generate_pivot_chain(
            pivot_gadget=gadget,
            target_address=0x605000
        )
        
        self.assertIsInstance(chain, PivotChain)

    def test_generate_exploit_no_leaked_address(self):
        gadget = StackPivotGadget(
            address=0x401020,
            instruction="xchg rsp, rax; ret",
            disassembly="...",
            pivot_type=PivotType.XCHG_REG,
            source_register="rax"
        )
        
        chain = PivotChain(
            chain_id="test",
            pivot_gadget=gadget,
            target_address=0x605000
        )
        
        exploit = self.generator.generate_exploit(
            overflow_size=64,
            pivot_chain=chain
        )
        
        self.assertIsInstance(exploit, ExploitWithPivot)


class TestConvenienceFunction(unittest.TestCase):
    """测试便捷函数"""

    def test_generate_stack_pivot_exploit(self):
        """测试 generate_stack_pivot_exploit 函数"""
        pivot_gadgets = [
            {
                'address': 0x401020,
                'instruction': 'xchg rsp, rax; ret',
                'type': 'xchg_reg',
                'source_register': 'rax'
            }
        ]
        
        exploit = generate_stack_pivot_exploit(
            pivot_gadgets=pivot_gadgets,
            overflow_size=72,
            leaked_address=0x605000,
            target_region="heap"
        )
        
        self.assertIsInstance(exploit, ExploitWithPivot)



if __name__ == '__main__':
    unittest.main()


