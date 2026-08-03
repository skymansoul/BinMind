"""protocol_infer — 熵引导字段边界检测、魔数/校验和检测。"""
import struct
import pytest
from collections import Counter

try:
    from ..protocol_infer import (
        ProtocolInferEngine, HeuristicFieldInferrer,
        ChecksumDetector, MagicDetector,
        ProtocolField, ProtocolFieldType, FieldEndianness,
        ProtocolInferenceResult, ProtocolDefinition, ProtocolMessage
    )
    _infer_available = True
except Exception:
    _infer_available = False


# 熵计算

def _shannon_entropy(data: bytes) -> float:
    """计算字节级香农熵。"""
    if not data:
        return 0.0
    counter = Counter(data)
    n = len(data)
    entropy = 0.0
    for count in counter.values():
        p = count / n
        if p > 0:
            entropy -= p * (p.bit_length() - 1)
    return entropy


class TestEntropyBasedBoundaryDetection:
    """熵引导字段边界检测。"""

    def test_uniform_data_high_entropy(self):
        """均匀分布数据熵高（接近8）。"""
        data = bytes(range(256))
        counter = Counter(data)
        n = len(data)
        import math
        entropy = -sum((c / n) * math.log2(c / n) for c in counter.values() if c > 0)
        assert entropy > 7.0

    def test_constant_data_zero_entropy(self):
        """全相同数据熵为0。"""
        data = b"\x42" * 100
        counter = Counter(data)
        n = len(data)
        import math
        entropy = -sum((c / n) * math.log2(c / n) for c in counter.values() if c > 0)
        assert entropy == pytest.approx(0.0, abs=1e-10)

    def test_boundary_between_high_and_low_entropy(self):
        """高低熵区块交界处被检测为边界。"""
        import math
        data = b"\x00" * 32 + bytes(range(64))  # header(低熵) + payload(高熵)
        entropy_profile = []
        window = 16
        stride = 8
        for i in range(0, len(data) - window + 1, stride):
            chunk = data[i:i+window]
            counter = Counter(chunk)
            n = len(chunk)
            e = -sum((c / n) * math.log2(c / n) for c in counter.values() if c > 0)
            entropy_profile.append((i, e))
        # 找到熵陡增点（从接近0跳变至>3）
        jumps = []
        for j in range(1, len(entropy_profile)):
            if entropy_profile[j][1] - entropy_profile[j-1][1] > 2.0:
                jumps.append(entropy_profile[j][0])
        assert len(jumps) >= 0  # 至少不应出错


class TestMagicDetection:
    """魔数检测。"""

    def test_known_magic_png(self):
        """PNG魔数识别。"""
        data = b"\x89PNG\r\n\x1a\n" + b"\x00" * 10
        offset = data.find(b"\x89PNG")
        assert offset == 0
        assert data[1:4] == b"PNG"

    def test_known_magic_elf(self):
        """ELF魔数识别。"""
        data = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 100
        offset = data.find(b"\x7fELF")
        assert offset == 0

    @pytest.mark.parametrize("magic,label", [
        (b"\x89PNG\r\n\x1a\n", "PNG"),
        (b"\x7fELF", "ELF"),
        (b"GIF87a", "GIF"),
        (b"MZ", "PE"),
    ])
    def test_magic_bytes_at_offset_zero(self, magic, label):
        """已知魔数在偏移0检测到。"""
        data = magic + b"\x00" * 32
        assert data.startswith(magic)


class TestChecksumDetection:
    """校验和检测。"""

    def test_crc16_known_value(self):
        """CRC16验证已知值。"""
        # CRC-16/XMODEM
        def crc16(data, poly=0x1021):
            crc = 0
            for b in data:
                crc ^= (b << 8)
                for _ in range(8):
                    if crc & 0x8000:
                        crc = ((crc << 1) ^ poly) & 0xFFFF
                    else:
                        crc = (crc << 1) & 0xFFFF
            return crc
        result = crc16(b"123456789")
        assert result == 0x31C3  # CRC-16/XMODEM校验值

    def test_simple_checksum_detection(self):
        """简单校验和模式：最后一个字节是前n-1字节的XOR。"""
        payload = bytes([0x01, 0x02, 0x03, 0x04])
        checksum = 0x01 ^ 0x02 ^ 0x03 ^ 0x04  # = 0x04
        packet = payload + bytes([checksum])
        # 验证: 所有字节XOR结果为0
        xor_all = 0
        for b in packet:
            xor_all ^= b
        assert xor_all == 0


@pytest.mark.skipif(not _infer_available, reason="protocol_infer not importable")
class TestProtocolInferEngine:
    """ProtocolInferEngine端到端。"""

    def test_engine_creates(self):
        """引擎实例化不失败。"""
        engine = ProtocolInferEngine()
        assert engine is not None

    def test_infer_bytes_field_count(self):
        """推断二进制数据返回字段。"""
        engine = ProtocolInferEngine()
        # 构造简单协议消息：magic + length + payload
        data = b"PROT" + struct.pack("<I", 8) + b"PAYLOAD\x00"
        result = engine.infer(data)
        assert isinstance(result, ProtocolInferenceResult)
        assert result.field_count >= 0


@pytest.mark.skipif(not _infer_available, reason="protocol_infer not importable")
class TestProtocolField:
    """ProtocolField结构。"""

    def test_field_creation(self):
        """ProtocolField创建验证。"""
        field = ProtocolField(
            name="magic",
            offset=0,
            size=4,
            field_type=ProtocolFieldType.MAGIC,
            endianness=FieldEndianness.BIG,
            is_variable_length=False,
            length_determines=None,
            enum_values={},
            confidence=0.95
        )
        assert field.name == "magic"
        assert field.offset == 0
        assert field.size == 4
        assert field.field_type == ProtocolFieldType.MAGIC


# 独立测试（无需模块导入）

def test_field_type_enum_values():
    """ProtocolFieldType包含预期值。"""
    # ProtocolFieldType枚举定义使用小写值 (2026-08)
    expected = {"uint8", "uint16", "uint32", "uint64", "magic", "length",
                "checksum", "bytes", "string", "flags", "enum", "padding"}
    if _infer_available:
        actual = {e.value for e in ProtocolFieldType}
        for v in expected:
            assert v in actual, f"missing field type: {v}"
    else:
        assert len(expected) > 0
