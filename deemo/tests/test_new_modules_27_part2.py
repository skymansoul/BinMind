"""
测试第二十七次补充的新模块 (Part 2)

测试内容:
- 二进制加密流量解密辅助与密钥提取
- 多平台二进制文件格式 Fuzzer 生成
- 集成测试
"""

import pytest
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.crypto_traffic_decrypt import (
    CryptoTrafficAnalyzer, KeyExtractor, TrafficDecryptor,
    KeyMaterial, DecryptionResult, TrafficAnalysisResult,
    EncryptionType, KeySourceType, extract_keys, decrypt_traffic
)

from modules.binary_format_fuzzer import (
    FormatFuzzerGenerator, FuzzerConfig, FuzzerHarness, TestCase,
    FormatStructure, FormatField, FileFormatType, FuzzerType,
    MutationStrategy, generate_format_fuzzer, generate_test_corpus,
    ELF_STRUCTURE, PE_STRUCTURE, MACH_O_STRUCTURE
)
TestCase.__test__ = False  # Prevent pytest from collecting dataclass


class TestCryptoTrafficDecrypt:
    """测试加密流量解密"""

    def test_encryption_type_enum(self):
        assert EncryptionType.AES_256_CBC.value == "aes_256_cbc"
        assert EncryptionType.DES_CBC.value == "des_cbc"
        assert EncryptionType.XOR.value == "xor"

    def test_key_source_type_enum(self):
        assert KeySourceType.HARDCODED.value == "hardcoded"
        assert KeySourceType.MEMORY_DUMP.value == "memory_dump"

    def test_key_material_dataclass(self):
        key = KeyMaterial(
            key=b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f',
            key_type=EncryptionType.AES_128_CBC,
            source=KeySourceType.HARDCODED,
            source_location='offset:0x100',
            iv=b'\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f',
            confidence=0.8
        )
        assert len(key.key) == 16
        assert key.key_type == EncryptionType.AES_128_CBC
        assert key.confidence == 0.8

    def test_key_extractor_init(self):
        extractor = KeyExtractor()
        assert len(extractor.key_patterns) > 0
        assert len(extractor.crypto_api_patterns) > 0

    def test_calculate_entropy(self):
        extractor = KeyExtractor()
        high_entropy_data = bytes([i % 256 for i in range(256)])
        high_entropy = extractor._calculate_entropy(high_entropy_data)
        assert high_entropy > 7.0

        low_entropy_data = bytes([0] * 256)
        low_entropy = extractor._calculate_entropy(low_entropy_data)
        assert low_entropy < 1.0

    def test_infer_encryption_type(self):
        extractor = KeyExtractor()
        assert extractor._infer_encryption_type(16) == EncryptionType.AES_128_CBC
        assert extractor._infer_encryption_type(32) == EncryptionType.AES_256_CBC
        assert extractor._infer_encryption_type(8) == EncryptionType.DES_CBC

    def test_traffic_decryptor_init(self):
        decryptor = TrafficDecryptor()
        assert decryptor.config is not None

    def test_decrypt_xor(self):
        decryptor = TrafficDecryptor()
        key = KeyMaterial(
            key=b'\x41\x41\x41\x41',  # 'AAAA'
            key_type=EncryptionType.XOR,
            source=KeySourceType.EXTERNAL
        )
        encrypted = bytes([0 ^ 0x41, 1 ^ 0x41, 2 ^ 0x41, 3 ^ 0x41])
        result = decryptor._decrypt_xor(encrypted, key)
        assert result.success == True
        assert result.decrypted_data == bytes([0, 1, 2, 3])

    def test_crypto_traffic_analyzer_init(self):
        analyzer = CryptoTrafficAnalyzer()
        assert analyzer.key_extractor is not None
        assert analyzer.decryptor is not None

    def test_detect_encryption(self):
        analyzer = CryptoTrafficAnalyzer()
        encrypted_data = bytes([i % 256 for i in range(256)])
        assert analyzer._detect_encryption(encrypted_data) == True

        text_data = b'Hello World! This is a test message.'
        assert analyzer._detect_encryption(text_data) == False


class TestBinaryFormatFuzzer:
    """测试二进制格式 Fuzzer"""

    def test_file_format_type_enum(self):
        assert FileFormatType.ELF.value == "elf"
        assert FileFormatType.PE.value == "pe"
        assert FileFormatType.MACH_O.value == "mach_o"

    def test_fuzzer_type_enum(self):
        assert FuzzerType.LIBFUZZER.value == "libfuzzer"
        assert FuzzerType.AFL.value == "afl"

    def test_mutation_strategy_enum(self):
        assert MutationStrategy.RANDOM.value == "random"
        assert MutationStrategy.BIT_FLIP.value == "bit_flip"

    def test_format_field_dataclass(self):
        field = FormatField(
            name='e_magic', offset=0, size=4, type='bytes',
            description='Magic number', valid_values=[b'\x7fELF'],
            is_critical=True
        )
        assert field.name == 'e_magic'
        assert field.offset == 0
        assert field.is_critical == True

    def test_elf_structure(self):
        assert ELF_STRUCTURE.format_type == FileFormatType.ELF
        assert ELF_STRUCTURE.magic_bytes == b'\x7fELF'
        assert len(ELF_STRUCTURE.fields) > 20

    def test_pe_structure(self):
        assert PE_STRUCTURE.format_type == FileFormatType.PE
        assert PE_STRUCTURE.magic_bytes == b'MZ'
        assert len(PE_STRUCTURE.fields) > 10

    def test_mach_o_structure(self):
        assert MACH_O_STRUCTURE.format_type == FileFormatType.MACH_O
        assert len(MACH_O_STRUCTURE.fields) > 5

    def test_fuzzer_config_dataclass(self):
        config = FuzzerConfig(
            fuzzer_type=FuzzerType.LIBFUZZER,
            target_format=FileFormatType.ELF,
            max_input_size=4096, timeout_ms=1000
        )
        assert config.fuzzer_type == FuzzerType.LIBFUZZER
        assert config.target_format == FileFormatType.ELF

    def test_format_fuzzer_generator_init(self):
        config = FuzzerConfig(
            fuzzer_type=FuzzerType.LIBFUZZER,
            target_format=FileFormatType.ELF
        )
        generator = FormatFuzzerGenerator(config)
        assert generator.config.fuzzer_type == FuzzerType.LIBFUZZER

    def test_generate_libfuzzer_harness(self):
        config = FuzzerConfig(
            fuzzer_type=FuzzerType.LIBFUZZER,
            target_format=FileFormatType.ELF
        )
        generator = FormatFuzzerGenerator(config)
        harness = generator.generate_harness()
        assert len(harness.harness_code) > 0
        assert 'LLVMFuzzerTestOneInput' in harness.harness_code
        assert harness.fuzzer_type == FuzzerType.LIBFUZZER

    def test_generate_dictionary(self):
        config = FuzzerConfig(
            fuzzer_type=FuzzerType.LIBFUZZER,
            target_format=FileFormatType.ELF
        )
        generator = FormatFuzzerGenerator(config)
        dictionary = generator.generate_dictionary()
        assert len(dictionary) > 0
        assert '7f454c46' in dictionary

    def test_generate_test_cases(self):
        config = FuzzerConfig(
            fuzzer_type=FuzzerType.LIBFUZZER,
            target_format=FileFormatType.ELF
        )
        generator = FormatFuzzerGenerator(config)
        test_cases = generator.generate_test_cases(10)
        assert len(test_cases) == 10
        for tc in test_cases:
            assert len(tc.data) > 0

    def test_generate_minimal_valid_file(self):
        config = FuzzerConfig(
            fuzzer_type=FuzzerType.LIBFUZZER,
            target_format=FileFormatType.ELF
        )
        generator = FormatFuzzerGenerator(config)
        min_file = generator._generate_minimal_valid_file(ELF_STRUCTURE)
        assert len(min_file) > 0
        assert min_file[:4] == b'\x7fELF'

    def test_apply_mutation(self):
        config = FuzzerConfig(
            fuzzer_type=FuzzerType.LIBFUZZER,
            target_format=FileFormatType.ELF
        )
        generator = FormatFuzzerGenerator(config)
        base_data = bytes([0] * 100)

        mutated = generator._apply_mutation(base_data, ELF_STRUCTURE, MutationStrategy.BIT_FLIP)
        assert mutated != base_data

        mutated = generator._apply_mutation(base_data, ELF_STRUCTURE, MutationStrategy.MAGIC_VALUES)
        assert mutated != base_data

    def test_save_harness(self):
        config = FuzzerConfig(
            fuzzer_type=FuzzerType.LIBFUZZER,
            target_format=FileFormatType.ELF
        )
        generator = FormatFuzzerGenerator(config)
        harness = generator.generate_harness()

        with tempfile.TemporaryDirectory() as tmpdir:
            saved_files = generator.save_harness(harness, tmpdir)
            assert 'harness' in saved_files
            assert os.path.exists(saved_files['harness'])
            assert 'dictionary' in saved_files
            assert os.path.exists(saved_files['dictionary'])


class TestIntegration:
    """集成测试"""

    def test_all_modules_importable(self):
        from modules import jit_analyzer
        from modules import syscall_table_recovery
        from modules import ai_function_namer
        from modules import crypto_traffic_decrypt
        from modules import binary_format_fuzzer

        assert jit_analyzer is not None
        assert syscall_table_recovery is not None
        assert ai_function_namer is not None
        assert crypto_traffic_decrypt is not None
        assert binary_format_fuzzer is not None

    def test_main_py_imports(self):
        import importlib.util
        with open(os.path.join(os.path.dirname(os.path.dirname(__file__)), "main.py"), 'r') as f:
            content = f.read()
        assert 'from modules.jit_analyzer import' in content
        assert 'from modules.syscall_table_recovery import' in content
        assert 'from modules.ai_function_namer import' in content
        assert 'from modules.crypto_traffic_decrypt import' in content
        assert 'from modules.binary_format_fuzzer import' in content


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
