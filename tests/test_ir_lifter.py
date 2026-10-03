# -*- coding: utf-8 -*-

"""
IR lifting framework unit tests
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
    """Architecture enum tests"""

    def test_architecture_values(self):
        """Architecture enum values"""
        self.assertEqual(Architecture.X86.value, "x86")
        self.assertEqual(Architecture.X86_64.value, "x86_64")
        self.assertEqual(Architecture.ARM.value, "arm")
        self.assertEqual(Architecture.ARM64.value, "arm64")
        self.assertEqual(Architecture.MIPS.value, "mips")


class TestIRTypeEnum(unittest.TestCase):
    """IR type enum tests"""

    def test_ir_type_values(self):
        """IR type enum values"""
        self.assertEqual(IRType.VEX.value, "vex")
        self.assertEqual(IRType.LLVM_IR.value, "llvm_ir")
        self.assertEqual(IRType.BIR.value, "bir")


class TestInstructionDataclass(unittest.TestCase):
    """Instruction dataclass tests"""

    def test_instruction_creation(self):
        """Test instruction creation"""
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
    """IRInstruction dataclass tests"""

    def test_ir_instruction_creation(self):
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
    """BasicBlock dataclass tests"""

    def test_basic_block_creation(self):
        """Test basic block creation"""
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
    """FunctionIR dataclass tests"""

    def test_function_ir_creation(self):
        """Test function IR creation"""
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
    """LifterResult dataclass tests"""

    def test_lifter_result_success(self):
        """Test successful lift result"""
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
        """Test failed lift result"""
        result = LifterResult(
            success=False,
            functions=[],
            architecture=Architecture.X86_64,
            ir_type=IRType.VEX,
            errors=["file not found"]
        )

        self.assertFalse(result.success)
        self.assertEqual(len(result.errors), 1)


class TestCapstoneDisassembler(unittest.TestCase):
    """Capstone disassembler tests"""

    def test_x86_disassembly(self):
        """Test x86 disassembly"""
        disassembler = CapstoneDisassembler(Architecture.X86)
        code = b"\x55\x48\x89\xe5\x90\xc3"  # push rbp; mov rbp, rsp; nop; ret

        instructions = disassembler.disassemble(code, 0x401000)

        self.assertGreater(len(instructions), 0)
        self.assertEqual(instructions[0].mnemonic, "push")
        self.assertEqual(instructions[-1].mnemonic, "ret")

    def test_arm_disassembly(self):
        """Test ARM disassembly"""
        disassembler = CapstoneDisassembler(Architecture.ARM)
        code = b"\xe1a00000\x0e12fff1"  # nop; bx lr

        instructions = disassembler.disassemble(code, 0x1000)

        self.assertGreater(len(instructions), 0)


class TestVEXLifter(unittest.TestCase):
    """VEX lifter tests"""

    def test_lift_simple_function(self):
        """Test lifting a simple function"""
        lifter = VEXLifter(Architecture.X86)
        code = b"\x55\x48\x89\xe5\xc3"  # push rbp; mov rbp, rsp; ret

        func_ir = lifter.lift_function(code, 0x401000, "test_func")

        self.assertEqual(func_ir.name, "test_func")
        self.assertEqual(func_ir.address, 0x401000)
        self.assertGreater(len(func_ir.basic_blocks), 0)


class TestLLVMIRLifter(unittest.TestCase):
    """LLVM IR lifter tests"""

    def test_lift_simple_function(self):
        lifter = LLVMIRLifter(Architecture.X86)
        code = b"\x55\xc3"  # push rbp; ret

        func_ir = lifter.lift_function(code, 0x401000, "test_func")

        self.assertEqual(func_ir.name, "test_func")
        self.assertEqual(func_ir.address, 0x401000)


class TestIRLifter(unittest.TestCase):
    """IR lifting framework tests"""

    def setUp(self):
        """pre-test setup"""
        self.m_tmp = tempfile.mkdtemp()

    def tearDown(self):
        """post-test cleanup"""
        if os.path.exists(self.m_tmp):
            shutil.rmtree(self.m_tmp)

    def test_create_vex_lifter(self):
        """Test creating VEX lifter"""
        lifter = IRLifter(Architecture.X86_64, IRType.VEX)

        self.assertEqual(lifter.arch, Architecture.X86_64)
        self.assertEqual(lifter.ir_type, IRType.VEX)

    def test_create_llvm_lifter(self):
        """Test creating LLVM IR lifter"""
        lifter = IRLifter(Architecture.X86_64, IRType.LLVM_IR)

        self.assertEqual(lifter.ir_type, IRType.LLVM_IR)

    def test_lift_binary(self):
        """Test lifting a binary file"""
        test_file = os.path.join(self.m_tmp, "test.bin")
        with open(test_file, "wb") as f:
            f.write(b"\x7fELF" + b"\x00" * 100)

        lifter = IRLifter(Architecture.X86_64)
        result = lifter.lift_binary(test_file)

        self.assertTrue(result.success)
        self.assertGreater(len(result.functions), 0)

    def test_lift_binary_not_found(self):
        """Test lifting a non-existent file"""
        lifter = IRLifter(Architecture.X86_64)
        result = lifter.lift_binary("/nonexistent/file.bin")

        self.assertFalse(result.success)
        self.assertEqual(len(result.errors), 1)

    def test_add_analysis_pass(self):
        """Test adding analysis passes"""
        lifter = IRLifter(Architecture.X86_64)

        pass1 = ConstantPropagationPass()
        pass2 = DeadCodeEliminationPass()

        lifter.add_analysis_pass(pass1)
        lifter.add_analysis_pass(pass2)

        self.assertEqual(len(lifter.analysis_passes), 2)

    def test_lift_function(self):
        """Test lifting a single function"""
        lifter = IRLifter(Architecture.X86_64)
        code = b"\x55\x48\x89\xe5\x90\xc3"

        func_ir = lifter.lift_function(code, 0x401000, "main")

        self.assertEqual(func_ir.name, "main")
        self.assertEqual(func_ir.address, 0x401000)

    def test_export_ir(self):
        lifter = IRLifter(Architecture.X86_64)
        code = b"\x55\xc3"

        func_ir = lifter.lift_function(code, 0x401000, "test")

        output_path = os.path.join(self.m_tmp, "test.ir")
        success = lifter.export_ir(func_ir, output_path)

        self.assertTrue(success)
        self.assertTrue(os.path.exists(output_path))


class TestAnalysisPasses(unittest.TestCase):
    """Analysis pass tests"""

    def test_constant_propagation_pass(self):
        """Test constant propagation pass"""
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
        pass_instance = DeadCodeEliminationPass()

        self.assertEqual(pass_instance.get_name(), "DeadCodeEliminationPass")

    def test_type_inference_pass(self):
        pass_instance = IRTypeInferencePass()

        self.assertEqual(pass_instance.get_name(), "IRTypeInferencePass")


if __name__ == '__main__':
    unittest.main()
