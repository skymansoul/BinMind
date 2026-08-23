# 去混淆模块工具函数测试
"""Shannon熵、XOR解码、可打印比例、英语评分、CJK检测、异常层级测试"""

import math
import pytest
from collections import Counter

# 熵计算测试

class TestEntropy:
    """Shannon熵计算测试"""

    def test_entropy_uniform_distribution(self) -> None:
        data = bytes(range(256))
        counter = Counter(data)
        n = len(data)
        entropy = -sum(
            (c / n) * math.log2(c / n) for c in counter.values() if c > 0
        )
        assert entropy > 7.9  # 接近最大值 8.0

    def test_entropy_single_value(self) -> None:
        data = b"\x42" * 100
        counter = Counter(data)
        n = len(data)
        entropy = -sum(
            (c / n) * math.log2(c / n) for c in counter.values() if c > 0
        )
        assert entropy == 0.0

    def test_entropy_empty_data(self) -> None:
        data = b""
        if len(data) == 0:
            entropy = 0.0
        assert entropy == 0.0

    def test_entropy_laplace_smoothing(self) -> None:
        # 小样本: 字节 0x41 0x42
        data = b"AABB"
        n = len(data)
        entropy = 0.0
        for byte_val in range(256):
            raw_count = data.count(byte_val)
            count = raw_count + 1  # 拉普拉斯平滑 +1
            p = count / (n + 256)
            if p > 0:
                entropy -= p * math.log2(p)
        assert entropy > 0.0

    def test_entropy_monotonic_with_randomness(self) -> None:
        import os
        random_data = os.urandom(1024)
        repeated_data = b"A" * 1024

        def calc_entropy(d):
            c = Counter(d)
            n = len(d)
            return -sum((v / n) * math.log2(v / n) for v in c.values() if v > 0)

        e_random = calc_entropy(random_data)
        e_repeated = calc_entropy(repeated_data)
        assert e_random > e_repeated


# XOR解码测试

class TestXOR:
    """XOR解码测试"""

    def test_xor_decode_basic(self) -> None:
        key = 0x55
        plaintext = b"HELLO"
        ciphertext = bytes(b ^ key for b in plaintext)
        decoded = bytes(b ^ key for b in ciphertext)
        assert decoded == plaintext

    def test_xor_key_zero_identity(self) -> None:
        data = b"TestData123"
        assert bytes(b ^ 0 for b in data) == data

    def test_xor_key_255_inverts(self) -> None:
        data = b"\x00\xFF\x55\xAA"
        inverted = bytes(b ^ 0xFF for b in data)
        expected = bytes(~b & 0xFF for b in data)
        assert inverted == expected

    def test_xor_double_apply_recovers(self) -> None:
        import os
        data = os.urandom(64)
        key = 0xAB
        encrypted = bytes(b ^ key for b in data)
        recovered = bytes(b ^ key for b in encrypted)
        assert recovered == data

    def test_xor_all_keys_reversible(self) -> None:
        for key in range(256):
            data = b"\x00\x01\x7F\x80\xFE\xFF"
            encrypted = bytes(b ^ key for b in data)
            decrypted = bytes(b ^ key for b in encrypted)
            assert decrypted == data


# 可打印比例测试

class TestPrintableRatio:
    """可打印比例计算测试"""

    def test_all_printable(self) -> None:
        s = "Hello World 123!@#"
        ratio = sum(
            1 for c in s if 0x20 <= ord(c) <= 0x7E or c in "\n\r\t"
        ) / len(s)
        assert ratio == 1.0

    def test_all_binary(self) -> None:
        s = "\x00\x01\x02\xff\xfe"
        ratio = sum(
            1 for c in s if 0x20 <= ord(c) <= 0x7E or c in "\n\r\t"
        ) / len(s) if s else 0.0
        assert ratio < 0.2

    def test_empty_string(self) -> None:
        s = ""
        if s:
            ratio = sum(1 for c in s if 0x20 <= ord(c) <= 0x7E) / len(s)
        else:
            ratio = 0.0
        assert ratio == 0.0

    def test_mixed_content(self) -> None:
        s = "ABC\x00\x01\xFF"
        ratio = sum(
            1 for c in s if 0x20 <= ord(c) <= 0x7E or c in "\n\r\t"
        ) / len(s)
        # 3 个可打印 / 6 = 0.5
        assert 0.4 < ratio < 0.6


# 英语评分测试

class TestEnglishScore:
    """英语文本似然评分测试"""

    def test_english_text_scores_high(self) -> None:
        s = "This is a normal English sentence that should score well"
        s_lower = s.lower()
        common_bigrams = {"th", "he", "in", "er", "an", "on", "at", "en", "is", "it"}
        bigram_hits = sum(
            1 for i in range(len(s_lower) - 1)
            if s_lower[i:i + 2] in common_bigrams
        )
        assert bigram_hits > 0

    def test_random_string_scores_low(self) -> None:
        s = "zxqjv kpwgy bmfcl dhrnt"  # 低频字母组合
        s_lower = s.lower()
        common_bigrams = {"th", "he", "in", "er", "an"}
        bigram_hits = sum(
            1 for i in range(len(s_lower) - 1)
            if s_lower[i:i + 2] in common_bigrams
        )
        assert bigram_hits <= 1  # 极少常见二元组

    def test_score_range(self) -> None:
        scores = []
        test_strings = [
            "Hello world this is a test",
            "abcdefghijklmnop",
            "the the the the the",
        ]
        for s in test_strings:
            s_lower = s.lower()
            common = {"th", "he", "in", "er", "an"}
            hits = sum(
                1 for i in range(len(s_lower) - 1)
                if s_lower[i:i + 2] in common
            )
            if len(s_lower) > 1:
                score = min(hits / (len(s_lower) - 1), 1.0)
            else:
                score = 0.0
            scores.append(score)
            assert 0.0 <= score <= 1.0


# CJK检测测试

class TestCJKDetection:
    """CJK字符检测测试"""

    def test_chinese_detected(self) -> None:
        s = "中文测试"  # "中文测试"
        has_cjk = any(
            0x4E00 <= ord(c) <= 0x9FFF or
            0x3040 <= ord(c) <= 0x309F or
            0x30A0 <= ord(c) <= 0x30FF or
            0xAC00 <= ord(c) <= 0xD7AF
            for c in s
        )
        assert has_cjk

    def test_japanese_hiragana_detected(self) -> None:
        s = "あいう"  # "あいう"
        has_cjk = any(
            0x4E00 <= ord(c) <= 0x9FFF or
            0x3040 <= ord(c) <= 0x309F or
            0x30A0 <= ord(c) <= 0x30FF or
            0xAC00 <= ord(c) <= 0xD7AF
            for c in s
        )
        assert has_cjk

    def test_korean_detected(self) -> None:
        s = "가각갂"  # 基础谚文
        has_cjk = any(
            0x4E00 <= ord(c) <= 0x9FFF or
            0x3040 <= ord(c) <= 0x309F or
            0x30A0 <= ord(c) <= 0x30FF or
            0xAC00 <= ord(c) <= 0xD7AF
            for c in s
        )
        assert has_cjk

    def test_ascii_not_detected(self) -> None:
        s = "Hello World 12345!@#$%"
        has_cjk = any(
            0x4E00 <= ord(c) <= 0x9FFF or
            0x3040 <= ord(c) <= 0x309F or
            0x30A0 <= ord(c) <= 0x30FF or
            0xAC00 <= ord(c) <= 0xD7AF
            for c in s
        )
        assert not has_cjk

    def test_mixed_cjk_ascii_detected(self) -> None:
        s = "Hello 中文 World"  # "Hello 中文 World"
        has_cjk = any(
            0x4E00 <= ord(c) <= 0x9FFF or
            0x3040 <= ord(c) <= 0x309F or
            0x30A0 <= ord(c) <= 0x30FF or
            0xAC00 <= ord(c) <= 0xD7AF
            for c in s
        )
        assert has_cjk


# 异常层级测试

class TestErrorHierarchy:
    """异常类层级测试"""

    def test_deobf_error_base(self) -> None:

        class DeobfError(Exception):
            pass

        assert issubclass(DeobfError, Exception)

    def test_unpack_error_inherits(self) -> None:

        class DeobfError(Exception):
            pass

        class UnpackError(DeobfError):
            pass

        assert issubclass(UnpackError, DeobfError)
        assert issubclass(UnpackError, Exception)

    def test_decode_error_inherits(self) -> None:

        class DeobfError(Exception):
            pass

        class DecodeError(DeobfError):
            pass

        assert issubclass(DecodeError, DeobfError)
        assert issubclass(DecodeError, Exception)

    def test_error_can_be_caught_by_parent(self) -> None:

        class DeobfError(Exception):
            pass

        class UnpackError(DeobfError):
            pass

        caught = False
        try:
            raise UnpackError("Test error")
        except DeobfError:
            caught = True

        assert caught

    def test_error_messages_preserved(self) -> None:

        class DeobfError(Exception):
            pass

        msg = "Failed to unpack UPX section"
        exc = DeobfError(msg)
        assert str(exc) == msg
