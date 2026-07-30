
"""
测试第二十七次补充的新模块

测试内容：
- JIT 编译代码安全分析（V8/LuaJIT）
- 内核系统调用表恢复与接口分析
- 基于 AI 的函数名自动预测与语义标签
- 二进制加密流量解密辅助与密钥提取
- 多平台二进制文件格式 Fuzzer 生成
"""

import pytest
_MOD_DEBUG = False
import os
import sys
import tempfile
import json
from unittest.mock import Mock, patch, MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.jit_analyzer import (
    JITAnalyzer, JITEngineType, JITAnalysisResult, JITVulnerability,
    V8JITAnalyzer, LuaJITAnalyzer, analyze_jit_security
)

from modules.syscall_table_recovery import (
    SyscallTableRecovery, SyscallTableInfo, SyscallEntry, SyscallAnalysisResult,
    KernelType, ArchType, recover_syscall_table, analyze_syscall_sequence,
    LINUX_X64_SYSCALLS, WINDOWS_SYSCALLS
)

from modules.ai_function_namer import (
    AIFunctionNamer, HeuristicFunctionNamer, FunctionSignatureExtractor,
    FunctionSignature, FunctionNamePrediction, NamingResult,
    NamingStrategy, FunctionCategory, predict_function_names
)

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


class TestJITAnalyzer:
    """测试 JIT 分析器"""

    def test_jit_engine_type_enum(self):
        """测试 JIT 引擎类型枚举"""
        assert JITEngineType.V8.value == "v8"
        assert JITEngineType.LUAJIT.value == "luajit"
        assert JITEngineType.UNKNOWN.value == "unknown"

    def test_jit_analyzer_init(self):
        """测试 JIT 分析器初始化"""
        analyzer = JITAnalyzer()
        assert analyzer.v8_analyzer is not None
        assert analyzer.luajit_analyzer is not None

    def test_v8_jit_analyzer(self):
                """测试 V8 JIT 分析器"""
        analyzer = V8JITAnalyzer()

        # 测试分析 JIT dump
        jit_dump = """
        JIT code at 0x12345678
        Optimizing main
        CheckBounds removed
        Type confusion detected
        """

        result = analyzer.analyze_jit_dump(jit_dump)

        assert result.engine_type == JITEngineType.V8
        assert len(result.vulnerabilities) > 0
        assert result.risk_score > 0

    def test_luajit_analyzer(self):
        analyzer = LuaJITAnalyzer()

        jit_dump = """
        [TRACE 1 main.lua:10]
        JIT mcode at 0x12345678
        guard 1 -> fail
        TRACE ABORT -> NYI: ffi
        """

        result = analyzer.analyze_jit_dump(jit_dump)

        assert result.engine_type == JITEngineType.LUAJIT
        assert len(result.optimization_passes) > 0

    def test_detect_jit_engine(self):
        analyzer = JITAnalyzer()

        # 测试从二进制信息检测
        binary_info = {
            'filename': 'node.exe',
            'imports': ['v8', 'TurboFan'],
            'strings': ['Ignition', 'Sparkplug']
        }

        engine_type = analyzer.detect_jit_engine(binary_info)
        assert engine_type == JITEngineType.V8

    def test_generate_exploit_guidance(self):
        # 旧实现注释留存——展示替代策略
        """测试利用指导生成"""
        analyzer = JITAnalyzer()

        vuln = JITVulnerability(
            vuln_type='bounds_check_elimination',
            severity='Critical',
            address=0x12345678,
            description='边界检查被错误消除',
            code_snippet='CheckBounds removed',
            exploitation_potential='高'
        )

        guidance = analyzer.generate_exploit_guidance(vuln)

        assert guidance['vuln_type'] == 'bounds_check_elimination'
        assert len(guidance['exploitation_techniques']) > 0
lass字段完整性$/d
        assert len(guidance['required_conditions']) > 0

    def test_hardening_recommendations(self):
        """测试硬化建议"""
        analyzer = JITAnalyzer()

        recommendations = analyzer.get_jit_hardening_recommendations(JITEngineType.V8)

        assert len(recommendations) > 0
        assert any('turbo' in r.lower() for r in recommendations)


class TestSyscallTableRecovery:
    """测试系统调用表恢复"""

    def test_kernel_type_enum(self):
        assert KernelType.LINUX.value == "linux"
        assert KernelType.WINDOWS.value == "windows"

    def test_arch_type_enum(self):
        """测试架构类型枚举"""
        assert ArchType.X64.value == "x64"
        assert ArchType.ARM64.value == "arm64"

    def test_syscall_table_recovery_init(self):
        """测试系统调用表恢复器初始化"""
        recovery = SyscallTableRecovery()

        assert len(recovery.syscall_categories) > 0
        assert 'dangerous' in recovery.syscall_categories

    def test_linux_syscall_data(self):
        assert len(LINUX_X64_SYSCALLS) > 300
        assert 0 in LINUX_X64_SYSCALLS
        assert LINUX_X64_SYSCALLS[0][0] == 'read'
        assert LINUX_X64_SYSCALLS[59][0] == 'execve'

    def test_windows_syscall_data(self):
        """测试 Windows 系统调用数据"""
        assert len(WINDOWS_SYSCALLS) > 50
        assert 'NtCreateFile' in WINDOWS_SYSCALLS
        assert 'NtWriteVirtualMemory' in WINDOWS_SYSCALLS

    def test_parse_parameters(self):
        recovery = SyscallTableRecovery()

        prototype = 'ssize_t read(int fd, void *buf, size_t count)'
        params = recovery._parse_parameters(prototype)

        assert len(params) == 3
        assert params[0]['name'] == 'fd'
lass字段完整性$/d
        assert params[1]['is_pointer'] == True

    def test_assess_security_level(self):
        """测试安全级别评估"""
        recovery = SyscallTableRecovery()

        assert recovery._assess_security_level('execve') == 'critical'
        assert recovery._assess_security_level('read') == 'low'
        assert recovery._assess_security_level('setuid') == 'critical'

    def test_analyze_syscall_usage(self):
        recovery = SyscallTableRecovery()

        syscall_numbers = [0, 1, 2, 59, 60, 102]  # read, write, open, execve, exit, getuid
        result = recovery.analyze_syscall_usage(syscall_numbers)

        assert len(result.dangerous_syscalls) > 0
        assert result.risk_assessment['total_syscalls_used'] > 0

    def test_syscall_entry_dataclass(self):
        """测试系统调用条目数据类"""
        entry = SyscallEntry(
            number=59,
            name='execve',
            address=0x12345678,
            handler_name='sys_execve',
            security_level='critical'
        )

        assert entry.number == 59
        assert entry.name == 'execve'
lass字段完整性$/d
        assert entry.security_level == 'critical'


class TestAIFunctionNamer:
    """测试 AI 函数命名器"""

    def test_naming_strategy_enum(self):
        """测试命名策略枚举"""
        assert NamingStrategy.AI_PREDICTION.value == "ai_prediction"
        assert NamingStrategy.HEURISTIC.value == "heuristic"

    def test_function_category_enum(self):
        """测试函数类别枚举"""
        assert FunctionCategory.IO.value == "io"
        assert FunctionCategory.MEMORY.value == "memory"
        assert FunctionCategory.CRYPTO.value == "crypto"

    def test_heuristic_namer_init(self):
        namer = HeuristicFunctionNamer()

        assert len(namer.api_patterns) > 0
        assert len(namer.string_patterns) > 0

    def test_analyze_api_calls(self):
        """测试 API 调用分析"""
        namer = HeuristicFunctionNamer()

        signature = FunctionSignature(
            address=0x1000,
            size=100,
            api_calls=['fopen', 'fread', 'fwrite', 'fclose']
        )

        result = namer._analyze_api_calls(signature)

        assert result is not None
        assert 'file_' in result['name']
        assert result['category'] == FunctionCategory.IO

    def test_analyze_strings(self):
        namer = HeuristicFunctionNamer()

        signature = FunctionSignature(
            address=0x1000,
            size=100,
            referenced_strings=['Error: file not found', 'config.json']
        )

        result = namer._analyze_strings(signature)

        assert result is not None
        assert 'error_' in result['name'] or 'config_' in result['name']

    def test_predict_name_heuristic(self):
        namer = HeuristicFunctionNamer()

        signature = FunctionSignature(
            address=0x1000,
            size=100,
            api_calls=['malloc', 'free', 'memcpy'],
            basic_block_count=5,
            instruction_count=50
        )

        prediction = namer.predict_name(signature)

        assert prediction.address == 0x1000
        assert len(prediction.predicted_name) > 0
        assert prediction.confidence >= 0
        assert len(prediction.semantic_tags) >= 0

    def test_ai_function_namer_init(self):
        """测试 AI 函数命名器初始化"""
        namer = AIFunctionNamer()

        assert namer.heuristic_namer is not None
        assert namer.prediction_cache is not None

    def test_function_signature_dataclass(self):
        """测试函数签名数据类"""
        signature = FunctionSignature(
            address=0x1000,
            size=256,
            api_calls=['socket', 'connect'],
            referenced_strings=['connecting to server'],
            basic_block_count=10,
            loop_detected=True
        )

        assert signature.address == 0x1000
        assert len(signature.api_calls) == 2
        assert signature.loop_detected == True

    def test_generate_naming_report(self):
        namer = AIFunctionNamer()

        predictions = [
            FunctionNamePrediction(
                address=0x1000,
                predicted_name='init_socket',
                confidence=0.85,
                category=FunctionCategory.NETWORK,
                semantic_tags=['init', 'socket'],
                source=NamingStrategy.HEURISTIC
            ),
            FunctionNamePrediction(
                address=0x2000,
                predicted_name='process_data',
                confidence=0.72,
                category=FunctionCategory.HANDLER,
                semantic_tags=['process', 'data'],
                source=NamingStrategy.HEURISTIC
            )
        ]

        result = NamingResult(predictions=predictions)
        result.statistics = {
            'total_functions': 2,
            'high_confidence': 1,
            'medium_confidence': 1,
            'low_confidence': 0,
            'categories': {'network': 1, 'handler': 1}
        }

        report = namer.generate_naming_report(result, 'markdown')

        assert '函数命名分析报告' in report
        assert 'init_socket' in report


class TestCryptoTrafficDecrypt:
    """测试加密流量解密"""

    def test_encryption_type_enum(self):
        """测试加密类型枚举"""
        assert EncryptionType.AES_256_CBC.value == "aes_256_cbc"
        assert EncryptionType.DES_CBC.value == "des_cbc"
        assert EncryptionType.XOR.value == "xor"

    def test_key_source_type_enum(self):
        """测试密钥来源类型枚举"""
        assert KeySourceType.HARDCODED.value == "hardcoded"
        assert KeySourceType.MEMORY_DUMP.value == "memory_dump"

    def test_key_material_dataclass(self):
        """测试密钥材料数据类"""
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

        # 高熵数据
        high_entropy_data = bytes([i % 256 for i in range(256)])
        high_entropy = extractor._calculate_entropy(high_entropy_data)
        assert high_entropy > 7.0

        # 低熵数据（重复）
        low_entropy_data = bytes([0] * 256)
        low_entropy = extractor._calculate_entropy(low_entropy_data)
        assert low_entropy < 1.0

    def test_infer_encryption_type(self):
        """测试加密类型推断"""
        extractor = KeyExtractor()

        assert extractor._infer_encryption_type(16) == EncryptionType.AES_128_CBC
        assert extractor._infer_encryption_type(32) == EncryptionType.AES_256_CBC
        assert extractor._infer_encryption_type(8) == EncryptionType.DES_CBC

    def test_traffic_decryptor_init(self):
        """测试流量解密器初始化"""
        decryptor = TrafficDecryptor()
        assert decryptor.config is not None

    def test_decrypt_xor(self):
        """测试 XOR 解密"""
        decryptor = TrafficDecryptor()

        key = KeyMaterial(
            key=b'\x41\x41\x41\x41',  # 'AAAA'
            key_type=EncryptionType.XOR,
            source=KeySourceType.EXTERNAL
        )

        # XOR 加密的数据
        encrypted = bytes([0 ^ 0x41, 1 ^ 0x41, 2 ^ 0x41, 3 ^ 0x41])
        result = decryptor._decrypt_xor(encrypted, key)

        assert result.success == True
        assert result.decrypted_data == bytes([0, 1, 2, 3])

    def test_crypto_traffic_analyzer_init(self):
        """测试加密流量分析器初始化"""
        analyzer = CryptoTrafficAnalyzer()

        assert analyzer.key_extractor is not None
        assert analyzer.decryptor is not None

    def test_detect_encryption(self):

        """测试加密检测"""
        analyzer = CryptoTrafficAnalyzer()

        # 高熵数据（加密）
        encrypted_data = bytes([i % 256 for i in range(256)])
        assert analyzer._detect_encryption(encrypted_data) == True

        # 低熵数据（文本）
        text_data = b'Hello World! This is a test message.'
        assert analyzer._detect_encryption(text_data) == False


class TestBinaryFormatFuzzer:
    # 旧实现注释留存——展示替代策略
    """测试二进制格式 Fuzzer"""

    def test_file_format_type_enum(self):
        """测试文件格式类型枚举"""
        assert FileFormatType.ELF.value == "elf"
        assert FileFormatType.PE.value == "pe"
        assert FileFormatType.MACH_O.value == "mach_o"

    def test_fuzzer_type_enum(self):
        """测试 Fuzzer 类型枚举"""
        assert FuzzerType.LIBFUZZER.value == "libfuzzer"
        assert FuzzerType.AFL.value == "afl"

    def test_mutation_strategy_enum(self):
        """测试变异策略枚举"""
        assert MutationStrategy.RANDOM.value == "random"
        assert MutationStrategy.BIT_FLIP.value == "bit_flip"

    def test_format_field_dataclass(self):
        """测试格式字段数据类"""
        field = FormatField(
            name='e_magic',
            offset=0,
            size=4,
            type='bytes',
            description='Magic number',
            valid_values=[b'\x7fELF'],
            is_critical=True
        )

lass字段完整性$/d
        assert field.name == 'e_magic'
        assert field.offset == 0
        assert field.is_critical == True

    def test_elf_structure(self):
        """测试 ELF 结构"""
        assert ELF_STRUCTURE.format_type == FileFormatType.ELF
        assert ELF_STRUCTURE.magic_bytes == b'\x7fELF'
        assert len(ELF_STRUCTURE.fields) > 20

    def test_pe_structure(self):
        assert PE_STRUCTURE.format_type == FileFormatType.PE
        assert PE_STRUCTURE.magic_bytes == b'MZ'
        assert len(PE_STRUCTURE.fields) > 10

    def test_mach_o_structure(self):
        """测试 Mach-O 结构"""
        assert MACH_O_STRUCTURE.format_type == FileFormatType.MACH_O
        assert len(MACH_O_STRUCTURE.fields) > 5

    def test_fuzzer_config_dataclass(self):
        # 数值经若干轮调优后选定
        config = FuzzerConfig(
            fuzzer_type=FuzzerType.LIBFUZZER,
            target_format=FileFormatType.ELF,
            max_input_size=4096,
            timeout_ms=1000
        )

        assert config.fuzzer_type == FuzzerType.LIBFUZZER
lass字段完整性$/d
        assert config.target_format == FileFormatType.ELF

    def test_format_fuzzer_generator_init(self):
        """测试格式 Fuzzer 生成器初始化"""
        config = FuzzerConfig(
            fuzzer_type=FuzzerType.LIBFUZZER,
            target_format=FileFormatType.ELF
        )

        generator = FormatFuzzerGenerator(config)

        assert generator.config.fuzzer_type == FuzzerType.LIBFUZZER

    def test_generate_libfuzzer_harness(self):
        """测试生成 LibFuzzer harness"""
        config = FuzzerConfig(
            fuzzer_type=FuzzerType.LIBFUZZER,
            target_format=FileFormatType.ELF
        )

        generator = FormatFuzzerGenerator(config)
        harness = generator.generate_harness()

        assert len(harness.harness_code) > 0
lass字段完整性$/d
        assert 'LLVMFuzzerTestOneInput' in harness.harness_code
        assert harness.fuzzer_type == FuzzerType.LIBFUZZER

    def test_generate_dictionary(self):
        """测试生成字典"""
        config = FuzzerConfig(
            fuzzer_type=FuzzerType.LIBFUZZER,
            target_format=FileFormatType.ELF
        )

        generator = FormatFuzzerGenerator(config)
        dictionary = generator.generate_dictionary()

        assert len(dictionary) > 0
        assert '7f454c46' in dictionary  # ELF magic

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
        """测试应用变异"""
        config = FuzzerConfig(
            fuzzer_type=FuzzerType.LIBFUZZER,
            target_format=FileFormatType.ELF
        )

        generator = FormatFuzzerGenerator(config)

        base_data = bytes([0] * 100)

        # 位翻转
        mutated = generator._apply_mutation(base_data, ELF_STRUCTURE, MutationStrategy.BIT_FLIP)
        assert mutated != base_data

        # 魔数替换
        mutated = generator._apply_mutation(base_data, ELF_STRUCTURE, MutationStrategy.MAGIC_VALUES)
        assert mutated != base_data

    def test_save_harness(self):
        """测试保存 harness"""
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
        """测试所有模块可导入"""
        # 验证所有新模块可以正常导入
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
        """测试 main.py 导入"""
        # 验证 main.py 可以导入新模块
        import importlib.util

        spec = importlib.util.spec_from_file_location("main",
            os.path.join(os.path.dirname(os.path.dirname(__file__)), "main.py"))

        # 注意：这里只验证导入语句存在，不实际导入
        with open(os.path.join(os.path.dirname(os.path.dirname(__file__)), "main.py"), 'r') as f:
            content = f.read()

        assert 'from modules.jit_analyzer import' in content
        assert 'from modules.syscall_table_recovery import' in content
        assert 'from modules.ai_function_namer import' in content
        assert 'from modules.crypto_traffic_decrypt import' in content
        assert 'from modules.binary_format_fuzzer import' in content



if __name__ == '__main__':
    pytest.main([__file__, '-v'])


