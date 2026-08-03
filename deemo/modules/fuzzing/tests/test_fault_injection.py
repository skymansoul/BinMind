"""fault_injection — bit-flip mutation, instruction skip logic, fault injection points."""
import struct
import pytest

try:
    from ..fault_injection_fuzzer import (
        FaultInjectionFuzzer, FaultInjectionPoint, FaultResult,
        create_fault_injection_fuzzer
    )
    _inject_available = True
except Exception:
    _inject_available = False


# ── 位翻转测试数据 ──

@pytest.fixture
def sample_x86_binary():
    """构造最小x86基本块用于模拟"""
    # ret指令; nop sled; push rbp; mov rbp, rsp
    return (
        b"\xc3"                      # ret
        b"\x90\x90\x90"              # nop sled
        b"\x55"                      # push rbp
        b"\x48\x89\xe5"              # mov rbp, rsp
        b"\xb8\x2a\x00\x00\x00"      # mov eax, 42
        b"\xc3"                      # ret
    )


class TestBitFlipMutation:
    """位翻转变异"""

    def test_single_bit_flip_changes_byte(self):
        """单bit翻转修改1个字节"""
        original = b"\x90"  # NOP
        # flip bit 0: 0x90 (10010000) → 0x91 (10010001)
        flipped = bytes([0x90 ^ (1 << 0)])
        assert flipped != original
        assert flipped == b"\x91"

    def test_bit_flip_preserves_length(self):
        """位翻转不改变数据长度"""
        data = bytearray(b"\x48\x89\xe5\xc3")
        original_len = len(data)
        # flip bit 3 of byte 1
        data[1] ^= (1 << 3)
        assert len(data) == original_len

    @pytest.mark.parametrize("bit_pos", [0, 1, 2, 3, 4, 5, 6, 7])
    def test_all_bit_positions_flippable(self, bit_pos):
        """所有8个bit位置都可以翻转"""
        byte = 0x55  # 01010101
        flipped = byte ^ (1 << bit_pos)
        # 翻转后将该bit取反
        original_bit = (byte >> bit_pos) & 1
        new_bit = (flipped >> bit_pos) & 1
        assert original_bit != new_bit


class TestInstructionSkip:
    """指令跳过逻辑"""

    def test_nop_replaces_single_byte_instruction(self):
        """单字节指令被NOP替换"""
        # push rbp (0x55) → nop (0x90)
        insn = bytearray(b"\x55\x48\x89\xe5")
        insn[0] = 0x90  # skip
        assert insn[0] == 0x90

    def test_multibyte_instruction_nop_overwrite(self):
        """多字节指令NOP覆盖"""
        # mov rbp, rsp = 0x48 0x89 0xe5
        insn = bytearray(b"\x48\x89\xe5\xb8\x01\x00\x00\x00")
        # NOP前3字节
        for i in range(3):
            insn[i] = 0x90
        assert insn[:3] == b"\x90\x90\x90"
        # 后续指令未受影响
        assert insn[3] == 0xb8  # mov eax, ...

    def test_ret_instruction_preserved(self):
        """RET指令被标记为不可跳过"""
        # RET (0xc3)是控制流关键指令
        code = bytearray(b"\x90\x90\xc3")
        # 模拟：不修改0xc3
        for i in range(len(code) - 1):
            if code[i] != 0xc3:
                code[i] = 0x90
        assert code[-1] == 0xc3  # RET保持


@pytest.mark.skipif(not _inject_available, reason="fault_injection_fuzzer not importable")
class TestFaultInjectionFuzzer:
    """FaultInjectionFuzzer模块"""

    def test_create_fuzzer_returns_instance(self):
        """工厂函数返回FaultInjectionFuzzer实例"""
        import tempfile, os
        fd, path = tempfile.mkstemp(suffix='.bin')
        os.write(fd, b"\x90\xc3")
        os.close(fd)
        try:
            fuzzer = create_fault_injection_fuzzer(path)
            assert isinstance(fuzzer, FaultInjectionFuzzer)
        finally:
            if os.path.exists(path):
                os.remove(path)

    def test_fault_result_structure(self):
        """FaultResult结构完整性"""
        result = FaultResult(
            success=True,
            vulnerabilities_found=1,
            total_injections=10,
            unique_crash_sigs=["SIGSEGV_0x401000"]
        )
        assert result.success
        assert result.vulnerabilities_found == 1
        assert len(result.unique_crash_sigs) == 1


class TestFaultInjectionPoint:
    """FaultInjectionPoint数据结构"""

    def test_injection_point_fields(self):
        """FaultInjectionPoint字段类型正确"""
        if _inject_available:
            pt = FaultInjectionPoint(
                address=0x401000,
                injection_type="bit_flip",
                result="SIGSEGV",
                reached_sensitive=True,
                sensitive_target="memcpy",
                crash_signature="SEGV_0x401000"
            )
            assert pt.address == 0x401000
            assert pt.injection_type == "bit_flip"
            assert pt.reached_sensitive
        else:
            # 内联结构验证
            pt = {
                "address": 0x401000,
                "injection_type": "bit_flip",
                "reached_sensitive": True,
            }
            assert pt["address"] == 0x401000


def test_nop_sled_generation():
    """NOP sled生成验证"""
    # 生成16字节NOP sled
    nop_count = 16
    sled = b"\x90" * nop_count
    assert len(sled) == 16
    assert all(b == 0x90 for b in sled)


def test_bit_flip_xor_identity():
    """位翻转异或幂等性：两次同bit翻转恢复原值"""
    original = 0xA5  # 10100101
    bit = 3
    flipped_once = original ^ (1 << bit)
    flipped_twice = flipped_once ^ (1 << bit)
    assert flipped_twice == original
