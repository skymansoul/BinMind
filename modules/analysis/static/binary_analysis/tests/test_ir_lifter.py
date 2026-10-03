# tests for IR lifting functionality

import pytest


class TestIRLifter:
    """IR lifting tests (capstone-dependent, but imports work)"""

    def test_import_ir_lifter(self):
        """Verify IR lifter imports optional dependencies"""
        try:
            from modules.binary_analysis import ir_lifter
            assert ir_lifter is not None
        except ImportError as e:
            pytest.skip(f"IR lifter not available: {e}")

    def test_arch_enum(self):
        """Verify Arch enum available for IR operations"""
        from modules.analysis.static.binary_analysis.src.utils.constants import Arch
        assert Arch.X86 is not None
        assert Arch.X86_64 is not None

    def test_ir_type_enum(self):
        """Verify IRType enum for 中间表示 selection"""
        from modules.analysis.static.binary_analysis.src.utils.constants import IRType
        assert IRType is not None


class TestLifting:
    """基础提升功能测试 (依赖硬件)"""

    def test_nop_lifting(self):
        """Try lifting NOP instructions"""
        # capstone optional — skip installed
        try:
            import capstone
        except ImportError:
            pytest.skip("capstone not installed")

        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        nop_code = b'\x90' * 8
        count = 0
        for insn in md.disasm(nop_code, 0x1000):
            assert insn.mnemonic == "nop"
            count += 1
        assert count == 8

    def test_ret_lifting(self):
        """Try lifting RET instruction"""
        try:
            import capstone
        except ImportError:
            pytest.skip("capstone not installed")

        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        ret_code = b'\xc3'
        insns = list(md.disasm(ret_code, 0x1000))
        assert len(insns) == 1
        assert insns[0].mnemonic == "ret"
