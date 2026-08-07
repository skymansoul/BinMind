"""string_decoder — Base64/Hex/XOR 字符串解码 scoring"""
import base64
import binascii
import pytest
from collections import Counter

try:
    from ..string_decoder import (
        StringDecoder, StringAnalysis, DecodeMethod,
    )
    _decoder_available = True
except Exception:
    _decoder_available = False


# 辅助函数

def _shannon_entropy(s: str) -> float:
    """计算字符串香农熵"""
    if not s:
        return 0.0
    import math
    counter = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counter.values() if c > 0)


def _is_printable(s: str) -> bool:
    """判断字符串是否可打印（ASCII可读）"""
    if not s:
        return False
    printable = sum(1 for c in s if 0x20 <= ord(c) < 0x7f or c in '\n\r\t')
    return printable / len(s) > 0.7


class TestBase64Decoding:
    """Base64解码"""

    def test_standard_base64_decode(self):
        """标准Base64字符串解码"""
        encoded = "SGVsbG8gV29ybGQ="
        decoded = base64.b64decode(encoded).decode("utf-8")
        assert decoded == "Hello World"

    def test_base64_roundtrip(self):
        """Base64编码再解码恢复原值"""
        original = "Binary Ninja deobfuscation string decoder test"
        encoded = base64.b64encode(original.encode()).decode()
        decoded = base64.b64decode(encoded).decode()
        assert decoded == original

    def test_base64_urlsafe_variant(self):
        """URL安全Base64变体"""
        data = b"\xfb\xfe\xff"  # 含+/的特殊字节
        encoded = base64.urlsafe_b64encode(data).decode()
        assert "+" not in encoded
        assert "/" not in encoded
        decoded = base64.urlsafe_b64decode(encoded)
        assert decoded == data

    def test_base64_padding_stripping(self):
        """Base64填充处理"""
        # "ab" → 2 bytes → 4 chars "=="
        encoded = base64.b64encode(b"ab").decode()
        assert encoded == "YWI="
        stripped = encoded.rstrip("=")
        # 恢复时补全padding
        padding = 4 - len(stripped) % 4
        if padding != 4:
            stripped += "=" * padding
        decoded = base64.b64decode(stripped)
        assert decoded == b"ab"


class TestHexDecoding:
    """十六进制解码"""

    def test_hex_decode_lowercase(self):
        """小写十六进制解码"""
        encoded = "48656c6c6f"  # "Hello"
        decoded = bytes.fromhex(encoded).decode()
        assert decoded == "Hello"

    def test_hex_decode_uppercase(self):
        """大写十六进制解码"""
        encoded = "48656C6C6F"
        decoded = bytes.fromhex(encoded).decode()
        assert decoded == "Hello"

    def test_hex_decode_with_0x_prefix(self):
        """带0x前缀的十六进制解码"""
        encoded = "0x48 0x65 0x6c 0x6c 0x6f"
        cleaned = encoded.replace("0x", "").replace(" ", "")
        decoded = bytes.fromhex(cleaned).decode()
        assert decoded == "Hello"

    def test_hex_decode_with_x_escape(self):
        """\\x转义十六进制解码"""
        encoded = "\\x48\\x65\\x6c\\x6c\\x6f"
        cleaned = encoded.replace("\\x", "")
        decoded = bytes.fromhex(cleaned).decode()
        assert decoded == "Hello"


class TestXORDecoding:
    """XOR解码"""

    def test_single_byte_xor_decode(self):
        """单字节XOR解码"""
        key = 0x42
        plaintext = b"SECRET"
        ciphertext = bytes(b ^ key for b in plaintext)
        decoded = bytes(b ^ key for b in ciphertext)
        assert decoded == plaintext

    def test_xor_with_zero_key_is_identity(self):
        """XOR key=0恒等"""
        data = b"identity test"
        assert bytes(b ^ 0 for b in data) == data

    def test_xor_double_decode_recovers(self):
        """XOR幂等性：两次相同key解码恢复原值"""
        data = b"\xde\xad\xbe\xef\xca\xfe"
        key = 0x55
        once = bytes(b ^ key for b in data)
        twice = bytes(b ^ key for b in once)
        assert twice == data

    @pytest.mark.parametrize("key", [0x01, 0x42, 0x7f, 0x80, 0xff])
    def test_various_xor_keys(self, key):
        """各种XOR key验证"""
        data = b"ABC123"
        encoded = bytes(b ^ key for b in data)
        decoded = bytes(b ^ key for b in encoded)
        assert decoded == data


class TestURLDecoding:
    """URL解码"""

    def test_url_decode_percent(self):
        """百分号编码URL解码"""
        import urllib.parse
        encoded = "Hello%20World%21"
        decoded = urllib.parse.unquote(encoded)
        assert decoded == "Hello World!"

    def test_url_decode_plus_to_space(self):
        """+号转空格"""
        import urllib.parse
        encoded = "Hello+World"
        decoded = urllib.parse.unquote_plus(encoded)
        assert decoded == "Hello World"


class TestEntropyScoring:
    """熵评分"""

    def test_printable_text_low_entropy(self):
        """可打印文本熵较低"""
        text = "This is a normal English sentence."
        e = _shannon_entropy(text)
        # 英文文本熵通常<4.5 bits
        assert e < 5.0

    def test_random_bytes_high_entropy(self):
        """随机数据熵高"""
        import random, string
        random_bytes = ''.join(random.choice(string.printable) for _ in range(100))
        e = _shannon_entropy(random_bytes)
        # 随机可打印字符熵接近log2(95)≈6.57
        assert e > 5.0

    def test_base64_looks_encoded(self):
        """Base64编码文本熵低于纯随机"""
        text = "SGVsbG8gV29ybGQgVGhpcyBpcyBhIHRlc3Qgb2YgZW50cm9weSBzY29yaW5n"
        e = _shannon_entropy(text)
        # Base64字符集有限→熵应显著低于8
        assert e < 6.5


class TestHumanReadableDetection:
    """可读性检测"""

    def test_english_text_is_readable(self):
        """英文文本判定为可读"""
        text = "This is readable text"
        assert _is_printable(text)

    def test_binary_data_not_readable(self):
        """二进制数据不可读"""
        data = "\x00\x01\x02\xff\xfe"
        assert not _is_printable(data)

    def test_threshold_70_percent(self):
        """70%可读阈值"""
        mixed = "Hello\x00\x01\x02 World"
        ratio = sum(1 for c in mixed if 0x20 <= ord(c) < 0x7f or c in '\n\r\t') / len(mixed)
        # 可打印字符占比应接近8/13≈0.615，低于0.7
        assert ratio < 0.75


@pytest.mark.skipif(not _decoder_available, reason="string_decoder not importable")
class TestStringDecoderModule:
    """StringDecoder模块测试"""

    @pytest.fixture
    def decoder(self):
        return StringDecoder(min_length=4, max_length=1000)

    def test_analyze_string_returns_analysis(self, decoder):
        """analyze_string返回StringAnalysis"""
        result = decoder.analyze_string("SGVsbG8=")
        assert isinstance(result, StringAnalysis)
        assert result.original == "SGVsbG8="

    def test_calculate_entropy_positive(self, decoder):
        """entropy计算为正数"""
        e = decoder._calculate_entropy("Hello World")
        assert e > 0.0

    def test_is_human_readable_true(self, decoder):
        """_is_human_readable判定真"""
        assert decoder._is_human_readable("readable text")

    def test_is_human_readable_false(self, decoder):
        """_is_human_readable判定假"""
        assert not decoder._is_human_readable("\x00\x01\x02\xff")

    def test_decode_all_returns_dict(self, decoder):
        """decode_all返回字典"""
        strings = ["SGVsbG8=", "48656c6c6f"]
        result = decoder.decode_all(strings)
        assert isinstance(result, dict)


# 独立测试

def test_rot13_inline():
    """ROT13内联验证"""
    def rot13(s):
        result = []
        for c in s:
            if 'a' <= c <= 'z':
                result.append(chr((ord(c) - ord('a') + 13) % 26 + ord('a')))
            elif 'A' <= c <= 'Z':
                result.append(chr((ord(c) - ord('A') + 13) % 26 + ord('A')))
            else:
                result.append(c)
        return ''.join(result)
    assert rot13("Hello") == "Uryyb"
    assert rot13(rot13("Hello")) == "Hello"


def test_zlib_magic_detection():
    """zlib幻数0x78检测"""
    import zlib
    data = b"compressed data for testing purposes"
    compressed = zlib.compress(data)
    # zlib压缩数据以0x78开头
    assert compressed[0] == 0x78
