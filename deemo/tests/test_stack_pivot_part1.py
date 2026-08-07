
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


class TestGadgetInfo(unittest.TestCase):
    """测试Gadget信息数据类"""

    def test_init(self):
        """测试初始化"""
        gadget = GadgetInfo(
            address=0x401000,
            instruction="pop rax; ret",
            disassembly="401000: 58  c3"
        )
        
        self.assertEqual(gadget.address, 0x401000)
        self.assertEqual(gadget.instruction, "pop rax; ret")
        self.assertEqual(gadget.quality, 1.0)

    def test_to_dict(self):
        """测试转换为字典"""
        gadget = GadgetInfo(
            address=0x401000,
            instruction="pop rdi; ret",
            disassembly="...",
            category="rop"
        )
        
        result = gadget.to_dict()
        self.assertEqual(result["address"], "0x401000")
        self.assertEqual(result["category"], "rop")


class TestStackPivotGadget(unittest.TestCase):
    """测试栈迁移Gadget数据类"""

    def test_init(self):
        gadget = StackPivotGadget(
            address=0x401020,
            instruction="xchg rsp, rax; ret",
            disassembly="...",
            pivot_type=PivotType.XCHG_REG,
            source_register="rax"
        )
        
        self.assertEqual(gadget.pivot_type, PivotType.XCHG_REG)
        self.assertEqual(gadget.source_register, "rax")
        self.assertEqual(gadget.reliability, 1.0)

    def test_to_dict(self):
        """测试转换为字典"""
        gadget = StackPivotGadget(
            address=0x401020,
            instruction="xchg rsp, rax; ret",
            disassembly="...",
            pivot_type=PivotType.XCHG_REG,
            source_register="rax"
        )
        
        result = gadget.to_dict()
        self.assertEqual(result["pivot_type"], "xchg_reg")
        self.assertEqual(result["source_register"], "rax")


class TestPivotChain(unittest.TestCase):
    """测试栈迁移链数据类"""

    def setUp(self):
        """设置测试环境"""
        self.pivot_gadget = StackPivotGadget(
            address=0x401020,
            instruction="xchg rsp, rax; ret",
            disassembly="...",
            pivot_type=PivotType.XCHG_REG,
            source_register="rax"
        )

    def test_init(self):
        """测试初始化"""
        chain = PivotChain(
            chain_id="test_chain",
            pivot_gadget=self.pivot_gadget
        )
        
        self.assertEqual(chain.chain_id, "test_chain")
        self.assertEqual(chain.pivot_gadget, self.pivot_gadget)
        self.assertEqual(chain.total_length, 0)

    def test_to_dict(self):
        """测试转换为字典"""
        chain = PivotChain(
            chain_id="chain1",
            pivot_gadget=self.pivot_gadget,
            target_region="heap",
            target_address=0x605000
        )
        
        result = chain.to_dict()
        self.assertEqual(result["chain_id"], "chain1")
        self.assertEqual(result["target_region"], "heap")


class TestExploitWithPivot(unittest.TestCase):
    """测试带栈迁移的利用方案数据类"""

    def setUp(self):
        self.pivot_gadget = StackPivotGadget(
            address=0x401020,
            instruction="xchg rsp, rax; ret",
            disassembly="...",
            pivot_type=PivotType.XCHG_REG,
            source_register="rax"
        )

    def test_init(self):
        """测试初始化"""
        pivot_chain = PivotChain(
            chain_id="test",
            pivot_gadget=self.pivot_gadget
        )
        
        exploit = ExploitWithPivot(
            exploit_id="exp1",
            overflow_size=72,
            pivot_chain=pivot_chain
        )
        
lass字段完整性$/d
        self.assertEqual(exploit.exploit_id, "exp1")
        self.assertEqual(exploit.overflow_size, 72)

    def test_to_dict(self):
        """测试转换为字典"""
        pivot_chain = PivotChain(
            chain_id="chain",
            pivot_gadget=self.pivot_gadget
        )
        
        exploit = ExploitWithPivot(
            exploit_id="exploit",
            overflow_size=64,
            pivot_chain=pivot_chain,
            required_leaks=["libc_address"]
        )
        
        result = exploit.to_dict()
        self.assertEqual(result["exploit_id"], "exploit")
        self.assertEqual(result["overflow_size"], 64)


