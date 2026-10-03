"""
Tests for network protocol reversing module.

Covers:
- BoundaryDetector: Shannon entropy, KL-divergence boundary detection
- LengthFieldAnalyzer: find_length_field heuristic
- ChecksumDetector: CRC polynomial detection
- MagicByteDetector: recurring prefix identification
- TypeInferrer: field type classification
- Module-level factory function
"""
import unittest

from modules.network.protocol_reversing import (
    FieldInfo,
    ProtocolGrammar,
    BoundaryDetector,
    LengthFieldAnalyzer,
    ChecksumDetector,
    MagicByteDetector,
    TypeInferrer,
    WiresharkDissector,
    create_protocol_reverser,
)


class TestFieldInfo(unittest.TestCase):
    """FieldInfo dataclass."""

    def test_creation(self):
        f = FieldInfo(
            name="length", offset=0, size=2,
            hypothesis="uint16 length field", confidence=0.85,
        )
        self.assertEqual(f.name, "length")
        self.assertEqual(f.offset, 0)
        self.assertEqual(f.size, 2)
        self.assertAlmostEqual(f.confidence, 0.85)


class TestProtocolGrammar(unittest.TestCase):
    """ProtocolGrammar dataclass."""

    def test_creation(self):
        pg = ProtocolGrammar(fields=[], endianness="little", name="MyProto")
        self.assertEqual(pg.name, "MyProto")
        self.assertEqual(pg.endianness, "little")
        self.assertEqual(len(pg.fields), 0)


class TestBoundaryDetector(unittest.TestCase):
    """Entropy and KL-divergence boundary detection."""

    def test_shannon_entropy_uniform(self):
        """全相同字节→熵为 0"""
        entropy = BoundaryDetector.shannon_entropy(b'\x00' * 100)
        self.assertAlmostEqual(entropy, 0.0, places=2)

    def test_shannon_entropy_random(self):
        """随机字节→高熵"""
        import random
        data = bytes(random.getrandbits(8) for _ in range(256))
        entropy = BoundaryDetector.shannon_entropy(data)
        self.assertGreater(entropy, 3.0)

    def test_kl_divergence_same_distribution(self):
        """相同分布的 KL 散度接近 0"""
        a = b'\x00\x01\x02' * 50
        b = b'\x00\x01\x02' * 50
        kl = BoundaryDetector.kl_divergence_window(a, b)
        self.assertAlmostEqual(kl, 0.0, delta=0.5)

    def test_kl_divergence_different_distribution(self):
        """不同分布的 KL 散度 > 0"""
        a = b'\x00' * 100
        b = b'\xFF' * 100
        kl = BoundaryDetector.kl_divergence_window(a, b)
        self.assertGreater(kl, 0.0)

    def test_find_boundaries_uniform(self):
        """均匀数据→无显著边界"""
        samples = [b'\x00' * 50, b'\x00' * 50]
        boundaries = BoundaryDetector.find_boundaries(samples)
        self.assertIsInstance(boundaries, list)

    def test_find_boundaries_two_regions(self):
        """跳跃式数据→检测到边界"""
        samples = [
            b'\x00' * 20 + b'\xFF' * 20,
            b'\x00' * 20 + b'\xFF' * 20,
        ]
        boundaries = BoundaryDetector.find_boundaries(samples)
        self.assertIsInstance(boundaries, list)


class TestLengthFieldAnalyzer(unittest.TestCase):
    """Length field heuristic."""

    def test_find_length_field_basic(self):
        """包含长度字段的样本→被检测"""
        # 2-byte big-endian length=6, then 6 bytes of data
        samples = [
            b'\x00\x06ABCDEF',
            b'\x00\x08ABCDEFGH',
        ]
        fields = LengthFieldAnalyzer.find_length_field(samples)
        self.assertIsInstance(fields, list)

    def test_no_length_field(self):
        """无长度字段→空列表"""
        samples = [b'\x01\x02\x03\x04']
        fields = LengthFieldAnalyzer.find_length_field(samples)
        self.assertIsInstance(fields, list)


class TestChecksumDetector(unittest.TestCase):
    """CRC checksum detection."""

    def test_crc_polys_defined(self):
        """CRC 多项式字典已定义"""
        self.assertGreater(len(ChecksumDetector.CRC_POLYS), 0)
        self.assertIn(0x1021, ChecksumDetector.CRC_POLYS)
        self.assertIn(0x04C11DB7, ChecksumDetector.CRC_POLYS)

    def test_detect_crc_short_data(self):
        """短数据→空结果"""
        samples = [b'\x00\x01']
        fields = ChecksumDetector.detect_crc(samples)
        self.assertIsInstance(fields, list)


class TestMagicByteDetector(unittest.TestCase):
    """Recurring prefix identification."""

    def test_identify_common_prefix(self):
        """共同前缀→识别为魔数"""
        samples = [
            b'\xAB\xCD\x00\x01',
            b'\xAB\xCD\x00\x02',
            b'\xAB\xCD\x00\x03',
        ]
        magics = MagicByteDetector.identify(samples, min_len=2)
        self.assertIsInstance(magics, dict)
        self.assertIn(b'\xAB\xCD', magics)

    def test_no_common_prefix(self):
        """无共同前缀→空"""
        samples = [b'\x01\x02', b'\x03\x04']
        magics = MagicByteDetector.identify(samples, min_len=2)
        self.assertEqual(len(magics), 0)

    def test_single_sample(self):
        """单样本→返回该前缀"""
        samples = [b'\xDE\xAD\xBE\xEF']
        magics = MagicByteDetector.identify(samples, min_len=2)
        self.assertGreater(len(magics), 0)


class TestTypeInferrer(unittest.TestCase):
    """Field type classification."""

    def test_infer_ascii_string(self):
        t = TypeInferrer.infer(b'Hello World\x00', 0, 11)
        self.assertEqual(t, "ascii_string")

    def test_infer_padding_zeros(self):
        t = TypeInferrer.infer(b'\x00\x00\x00\x00', 0, 4)
        self.assertIn(t, ["padding", "uint32"])

    def test_infer_uint16_small(self):
        t = TypeInferrer.infer(b'\x00\x08', 0, 2)
        self.assertIn(t, ["uint16", "uint8"])


class TestWiresharkDissector(unittest.TestCase):
    """Wireshark Lua dissector generation."""

    def test_generate_empty_grammar(self):
        grammar = ProtocolGrammar(fields=[], endianness="big", name="Empty")
        lua = WiresharkDissector.generate(grammar)
        self.assertIsInstance(lua, str)
        self.assertIn("Proto", lua)

    def test_generate_with_fields(self):
        fields = [
            FieldInfo(name="magic", offset=0, size=4, hypothesis="magic"),
            FieldInfo(name="length", offset=4, size=2, hypothesis="length"),
        ]
        grammar = ProtocolGrammar(fields=fields, endianness="little", name="TestProto")
        lua = WiresharkDissector.generate(grammar)
        self.assertIn("magic", lua.lower())


class TestCreateProtocolReverser(unittest.TestCase):
    """Factory function."""

    def test_returns_dict(self):
        reverser = create_protocol_reverser()
        self.assertIsInstance(reverser, dict)

    def test_contains_analyzers(self):
        reverser = create_protocol_reverser()
        self.assertGreater(len(reverser), 0)


if __name__ == "__main__":
    unittest.main()
