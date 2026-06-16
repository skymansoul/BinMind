#!/usr/bin/env python3
"""
IR提升框架单元测试
"""

import os
import sys
import unittest
import tempfile
import shutil

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.ir_lifter import (
    IRLifter, Architecture, IRType, Instruction, IRInstruction,
    BasicBlock, FunctionIR, LifterResult, CapstoneDisassembler,
    VEXLifter, LLVMIRLifter, ConstantPropagationPass,
    DeadCodeEliminationPass, IRTypeInferencePass
)


class TestArchitectureEnum(unittest.TestCase):
    """架构枚举测试"""
    
    def test_architecture_values(self):
        """测试架构枚举值"""
        self.assertEqual(Architecture.X86.value, "x86")
        self.assertEqual(Architecture.X86_64.value, "x86_64")
        self.assertEqual(Architecture.ARM.value, "arm")
        self.assertEqual(Architecture.ARM64.value, "arm64")
        self.assertEqual(Architecture.MIPS.value, "mips")


class TestIRTypeEnum(unittest.TestCase):
    """IR类型枚举测试"""
    
    def test_ir_type_values(self):
        """测试IR类型枚举值"""
        self.assertEqual(IRType.VEX.value, "vex")
        self.assertEqual(IRType.LLVM_IR.value, "llvm_ir")
        self.assertEqual(IRType.BIR.value, "bir")


class TestInstructionDataclass(unittest.TestCase):
    """Instruction数据类测试"""
    
    def test_instruction_creation(self):
        """测试指令创建"""
        instr = Instruction(
            address=0x401000,
            mnemonic="mov",
            op_str="eax, ebx",
            bytes=b"\x89\xd8",
            size=2
        )
        
        self.assertEqual(instr.address, 0x401000)
        self.assertEqual(instr.mnemonic, "mov")
        self.assertEqual(instr.op_str, "eax, ebx")
        self.assertEqual(instr.bytes, b"\x89\xd8")
        self.assertEqual(instr.size, 2)


class TestIRInstructionDataclass(unittest.TestCase):
    """IRInstruction数据类测试"""
    
    def test_ir_instruction_creation(self):
        """测试IR指令创建"""
        ir_instr = IRInstruction(
            address=0x401000,
            opcode="Iop_Add",
            operands=["rd", "rs1", "rs2"],
            comment="add eax, ebx"
        )
        
        self.assertEqual(ir_instr.address, 0x401000)
        self.assertEqual(ir_instr.opcode, "Iop_Add")
        self.assertEqual(len(ir_instr.operands), 3)
        self.assertEqual(ir_instr.comment, "add eax, ebx")


class TestBasicBlockDataclass(unittest.TestCase):
    """BasicBlock数据类测试"""
    
    def test_basic_block_creation(self):
        """测试基本块创建"""
        block = BasicBlock(
            start_address=0x401000,
            end_address=0x401010,
            instructions=[],
            successors=[0x401010, 0x401020],
            predecessors=[0x400fff]
        )
        
        self.assertEqual(block.start_address, 0x401000)
        self.assertEqual(block.end_address, 0x401010)
        self.assertEqual(len(block.successors), 2)
        self.assertEqual(len(block.predecessors), 1)


class TestFunctionIRDataclass(unittest.TestCase):
    """FunctionIR数据类测试"""
    
    def test_function_ir_creation(self):
        """测试函数IR创建"""
        block = BasicBlock(
            start_address=0x401000,
            end_address=0x401010,
            instructions=[]
        )
        
        func_ir = FunctionIR(
            name="main",
            address=0x401000,
            basic_blocks=[block],
            ir_type=IRType.VEX,
            original_binary=b"\x90\x90"
        )
        
        self.assertEqual(func_ir.name, "main")
        self.assertEqual(func_ir.address, 0x401000)
        self.assertEqual(len(func_ir.basic_blocks), 1)
        self.assertEqual(func_ir.ir_type, IRType.VEX)


class TestLifterResultDataclass(unittest.TestCase):
    """LifterResult数据类测试"""
    
    def test_lifter_result_success(self):
        """测试提升结果成功"""
        result = LifterResult(
            success=True,
            functions=[],
            architecture=Architecture.X86_64,
            ir_type=IRType.VEX
        )
        
        self.assertTrue(result.success)
        self.assertEqual(result.architecture, Architecture.X86_64)
        self.assertEqual(result.ir_type, IRType.VEX)
        self.assertEqual(len(result.errors), 0)
    
    def test_lifter_result_failure(self):
        """测试提升结果失败"""
        result = LifterResult(
            success=False,
            functions=[],
            architecture=Architecture.X86_64,
            ir_type=IRType.VEX,
            errors=["文件不存在"]
        )
        
        self.assertFalse(result.success)
        self.assertEqual(len(result.errors), 1)


class TestCapstoneDisassembler(unittest.TestCase):
    """Capstone反汇编器测试"""
    
    def test_x86_disassembly(self):
        """测试x86反汇编"""
        disassembler = CapstoneDisassembler(Architecture.X86)
        code = b"\x55\x48\x89\xe5\x90\xc3"  # push rbp; mov rbp, rsp; nop; ret
        
        instructions = disassembler.disassemble(code, 0x401000)
        
        self.assertGreater(len(instructions), 0)
        self.assertEqual(instructions[0].mnemonic, "push")
        self.assertEqual(instructions[-1].mnemonic, "ret")
    
    def test_arm_disassembly(self):
        """测试ARM反汇编"""
        disassembler = CapstoneDisassembler(Architecture.ARM)
        code = b"\xe1a00000\x0e12fff1"  # nop; bx lr
        
        instructions = disassembler.disassemble(code, 0x1000)
        
        self.assertGreater(len(instructions), 0)


class TestVEXLifter(unittest.TestCase):
    """VEX提升器测试"""
    
    def test_lift_simple_function(self):
        """测试提升简单函数"""
        lifter = VEXLifter(Architecture.X86)
        code = b"\x55\x48\x89\xe5\xc3"  # push rbp; mov rbp, rsp; ret
        
        func_ir = lifter.lift_function(code, 0x401000, "test_func")
        
        self.assertEqual(func_ir.name, "test_func")
        self.assertEqual(func_ir.address, 0x401000)
        self.assertGreater(len(func_ir.basic_blocks), 0)


class TestLLVMIRLifter(unittest.TestCase):
    """LLVM IR提升器测试"""
    
    def test_lift_simple_function(self):
        """测试提升简单函数"""
        lifter = LLVMIRLifter(Architecture.X86)
        code = b"\x55\xc3"  # push rbp; ret
        
        func_ir = lifter.lift_function(code, 0x401000, "test_func")
        
        self.assertEqual(func_ir.name, "test_func")
        self.assertEqual(func_ir.address, 0x401000)


class TestIRLifter(unittest.TestCase):
    """IR提升框架测试"""
    
    def setUp(self):
        """测试前准备"""
        self.temp_dir = tempfile.mkdtemp()
    
    def tearDown(self):
        """测试后清理"""
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)
    
    def test_create_vex_lifter(self):
        """测试创建VEX提升器"""
        lifter = IRLifter(Architecture.X86_64, IRType.VEX)
        
        self.assertEqual(lifter.arch, Architecture.X86_64)
        self.assertEqual(lifter.ir_type, IRType.VEX)
    
    def test_create_llvm_lifter(self):
        """测试创建LLVM IR提升器"""
        lifter = IRLifter(Architecture.X86_64, IRType.LLVM_IR)
        
        self.assertEqual(lifter.ir_type, IRType.LLVM_IR)
    
    def test_lift_binary(self):
        """测试提升二进制文件"""
        test_file = os.path.join(self.temp_dir, "test.bin")
        with open(test_file, "wb") as f:
            f.write(b"\x7fELF" + b"\x00" * 100)
        
        lifter = IRLifter(Architecture.X86_64)
        result = lifter.lift_binary(test_file)
        
        self.assertTrue(result.success)
        self.assertGreater(len(result.functions), 0)
    
    def test_lift_binary_not_found(self):
        """测试提升不存在的文件"""
        lifter = IRLifter(Architecture.X86_64)
        result = lifter.lift_binary("/nonexistent/file.bin")
        
        self.assertFalse(result.success)
        self.assertEqual(len(result.errors), 1)
    
    def test_add_analysis_pass(self):
        """测试添加分析pass"""
        lifter = IRLifter(Architecture.X86_64)
        
        pass1 = ConstantPropagationPass()
        pass2 = DeadCodeEliminationPass()
        
        lifter.add_analysis_pass(pass1)
        lifter.add_analysis_pass(pass2)
        
        self.assertEqual(len(lifter.analysis_passes), 2)
    
    def test_lift_function(self):
        """测试提升单个函数"""
        lifter = IRLifter(Architecture.X86_64)
        code = b"\x55\x48\x89\xe5\x90\xc3"
        
        func_ir = lifter.lift_function(code, 0x401000, "main")
        
        self.assertEqual(func_ir.name, "main")
        self.assertEqual(func_ir.address, 0x401000)
    
    def test_export_ir(self):
        """测试导出IR"""
        lifter = IRLifter(Architecture.X86_64)
        code = b"\x55\xc3"
        
        func_ir = lifter.lift_function(code, 0x401000, "test")
        
        output_path = os.path.join(self.temp_dir, "test.ir")
        success = lifter.export_ir(func_ir, output_path)
        
        self.assertTrue(success)
        self.assertTrue(os.path.exists(output_path))


class TestAnalysisPasses(unittest.TestCase):
    """分析Pass测试"""
    
    def test_constant_propagation_pass(self):
        """测试常量传播pass"""
        pass_instance = ConstantPropagationPass()
        
        self.assertEqual(pass_instance.get_name(), "ConstantPropagationPass")
        
        block = BasicBlock(
            start_address=0x401000,
            end_address=0x401008,
            instructions=[]
        )
        func_ir = FunctionIR(
            name="test",
            address=0x401000,
            basic_blocks=[block],
            ir_type=IRType.VEX
        )
        
        result = pass_instance.run(func_ir)
        self.assertIsInstance(result, FunctionIR)
    
    def test_dead_code_elimination_pass(self):
        """测试死代码消除pass"""
        pass_instance = DeadCodeEliminationPass()
        
        self.assertEqual(pass_instance.get_name(), "DeadCodeEliminationPass")
    
    def test_type_inference_pass(self):
        """测试类型推断pass"""
        pass_instance = IRTypeInferencePass()
        
        self.assertEqual(pass_instance.get_name(), "IRTypeInferencePass")


if __name__ == '__main__':
    unittest.main()