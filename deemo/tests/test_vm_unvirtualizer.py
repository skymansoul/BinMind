"""
VM unvirtualizer tests -- enriched with VMDetector, handler extraction,
and devirtualization pipeline tests.
"""
import unittest
import sys
_MOD_DEBUG = False
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from modules.analysis.deobfuscation.vm_unvirtualizer import (
    VMUnvirtualizer,
    VMDetector,
    VMInstruction,
    VMHandler,
    VMContext,
    DevirtualizationResult,
    create_vm_unvirtualizer,
    _classify_instruction_semantics,
    _classify_handler_semantics,
    _generate_fallback_handlers,
)


class TestVMInstruction(unittest.TestCase):
    """VM instruction dataclass."""

    def test_creation(self):
        inst = VMInstruction(
            opcode=0x01,
            mnemonic="ADD",
            handler_address=0x4000,
            semantics="arithmetic",
            stack_effect=0,
        )
        self.assertEqual(inst.opcode, 0x01)
        self.assertEqual(inst.mnemonic, "ADD")
        self.assertEqual(inst.semantics, "arithmetic")

    def test_with_operands(self):
        inst = VMInstruction(
            opcode=0x02,
            mnemonic="MOV",
            handler_address=0x4100,
            semantics="memory",
            operands=["r1", "r2"],
            handler_size=16,
        )
        self.assertEqual(len(inst.operands), 2)
        self.assertEqual(inst.handler_size, 16)


class TestVMHandler(unittest.TestCase):
    """VM handler dataclass."""

    def test_creation(self):
        handler = VMHandler(
            address=0x5000,
            opcode=0x01,
            semantics="arithmetic",
            raw_instructions=["mov eax, ebx", "add eax, ecx", "ret"],
        )
        self.assertEqual(handler.address, 0x5000)
        self.assertEqual(handler.opcode, 0x01)
        self.assertEqual(len(handler.raw_instructions), 3)


class TestVMContext(unittest.TestCase):
    """VM execution context."""

    def test_default_context(self):
        ctx = VMContext()
        self.assertIsInstance(ctx.vip, int)
        self.assertIsInstance(ctx.vsp, int)
        self.assertIsInstance(ctx.reg_snapshot, dict)


class TestDevirtualizationResult(unittest.TestCase):
    """Devirtualization result."""

    def test_default_result(self):
        result = DevirtualizationResult(success=False)
        self.assertFalse(result.success)
        self.assertIsInstance(result.original_instructions, list)

    def test_successful_result(self):
        result = DevirtualizationResult(
            success=True,
            native_code=["mov eax, 1", "ret"],
            accuracy_estimate=0.85,
            vm_type_hint="VMProtect",
        )
        self.assertTrue(result.success)
        self.assertAlmostEqual(result.accuracy_estimate, 0.85)
        self.assertEqual(result.vm_type_hint, "VMProtect")


class TestVMDetector(unittest.TestCase):
    """VM detection in binary."""

    def test_detect_empty_binary(self):
        detector = VMDetector(binary_path="")
        result = detector.detect_vm()
        self.assertFalse(result)

    def test_detect_vm_type_none(self):
        detector = VMDetector(binary_path="")
        vm_type = detector.detect_vm_type()
        self.assertIsNone(vm_type)

    def test_estimate_bytecode_region_empty(self):
        detector = VMDetector(binary_path="")
        base, size = detector.estimate_bytecode_region()
        self.assertIsNone(base)
        self.assertEqual(size, 0)


class TestVMUnvirtualizer(unittest.TestCase):
    """Main VM unvirtualizer class."""

    def test_initialization(self):
        unvirtualizer = VMUnvirtualizer('/path/to/binary')
        self.assertIsNotNone(unvirtualizer)

    def test_unvirtualize(self):
        unvirtualizer = VMUnvirtualizer('/path/to/binary')
        result = unvirtualizer.unvirtualize()
        self.assertIsNotNone(result)

    def test_unvirtualize_nonexistent_binary(self):
        unvirtualizer = VMUnvirtualizer('/nonexistent')
        result = unvirtualizer.unvirtualize()
        self.assertIsNotNone(result)
        self.assertFalse(result.success)

    def test_run_method(self):
        unvirtualizer = VMUnvirtualizer('/path/to/binary')
        result = unvirtualizer.run()
        self.assertIsInstance(result, DevirtualizationResult)

    def test_create_vm_unvirtualizer_factory(self):
        uv = create_vm_unvirtualizer('/tmp/test')
        self.assertIsInstance(uv, VMUnvirtualizer)


class TestInstructionSemantics(unittest.TestCase):
    """Instruction and handler semantics classification."""

    def test_classify_add(self):
        sem = _classify_instruction_semantics("add")
        self.assertEqual(sem, "arithmetic")

    def test_classify_mov(self):
        sem = _classify_instruction_semantics("mov")
        self.assertEqual(sem, "memory")

    def test_classify_cmp(self):
        sem = _classify_instruction_semantics("cmp")
        self.assertEqual(sem, "comparison")

    def test_classify_jmp(self):
        sem = _classify_instruction_semantics("jmp")
        self.assertEqual(sem, "control")

    def test_classify_unknown(self):
        sem = _classify_instruction_semantics("foobar")
        self.assertEqual(sem, "unknown")

    def test_handler_semantics_single_type(self):
        sem = _classify_handler_semantics(["add", "sub", "mul"])
        self.assertIn(sem, ["arithmetic", "mixed"])

    def test_handler_semantics_empty(self):
        sem = _classify_handler_semantics([])
        self.assertEqual(sem, "unknown")


class TestFallbackHandlers(unittest.TestCase):
    """Fallback handler generation."""

    def test_generate_16_handlers(self):
        handlers = _generate_fallback_handlers(0x4000, 16)
        self.assertEqual(len(handlers), 16)

    def test_generate_zero_handlers(self):
        handlers = _generate_fallback_handlers(0x5000, 0)
        self.assertEqual(len(handlers), 0)

    def test_handler_has_addresses(self):
        handlers = _generate_fallback_handlers(0x4000, 5)
        addresses = [h.address for h in handlers]
        self.assertEqual(len(set(addresses)), 5)


if __name__ == '__main__':
    unittest.main()
