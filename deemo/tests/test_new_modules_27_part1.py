"""
测试第二十七次补充的新模块 (Part 1)

测试内容:
- JIT 编译代码安全分析（V8/LuaJIT）
- 内核系统调用表恢复与接口分析
- AI 函数名自动预测与语义标签
"""

import pytest
import os
import sys

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


class TestJITAnalyzer:
    """测试 JIT 分析器"""

    def test_jit_engine_type_enum(self):
        assert JITEngineType.V8.value == "v8"
        assert JITEngineType.LUAJIT.value == "luajit"
        assert JITEngineType.UNKNOWN.value == "unknown"

    def test_jit_analyzer_init(self):
        analyzer = JITAnalyzer()
        assert analyzer.v8_analyzer is not None
        assert analyzer.luajit_analyzer is not None

    def test_v8_jit_analyzer(self):
        analyzer = V8JITAnalyzer()
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
        binary_info = {
            'filename': 'node.exe',
            'imports': ['v8', 'TurboFan'],
            'strings': ['Ignition', 'Sparkplug']
        }
        engine_type = analyzer.detect_jit_engine(binary_info)
        assert engine_type == JITEngineType.V8

    def test_generate_exploit_guidance(self):
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
        assert len(guidance['required_conditions']) > 0

    def test_hardening_recommendations(self):
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
        assert ArchType.X64.value == "x64"
        assert ArchType.ARM64.value == "arm64"

    def test_syscall_table_recovery_init(self):
        recovery = SyscallTableRecovery()
        assert len(recovery.syscall_categories) > 0
        assert 'dangerous' in recovery.syscall_categories

    def test_linux_syscall_data(self):
        assert len(LINUX_X64_SYSCALLS) > 300
        assert 0 in LINUX_X64_SYSCALLS
        assert LINUX_X64_SYSCALLS[0][0] == 'read'
        assert LINUX_X64_SYSCALLS[59][0] == 'execve'

    def test_windows_syscall_data(self):
        assert len(WINDOWS_SYSCALLS) > 50
        assert 'NtCreateFile' in WINDOWS_SYSCALLS
        assert 'NtWriteVirtualMemory' in WINDOWS_SYSCALLS

    def test_parse_parameters(self):
        recovery = SyscallTableRecovery()
        prototype = 'ssize_t read(int fd, void *buf, size_t count)'
        params = recovery._parse_parameters(prototype)
        assert len(params) == 3
        assert params[0]['name'] == 'fd'
        assert params[1]['is_pointer'] == True

    def test_assess_security_level(self):
        recovery = SyscallTableRecovery()
        assert recovery._assess_security_level('execve') == 'critical'
        assert recovery._assess_security_level('read') == 'low'
        assert recovery._assess_security_level('setuid') == 'critical'

    def test_analyze_syscall_usage(self):
        recovery = SyscallTableRecovery()
        syscall_numbers = [0, 1, 2, 59, 60, 102]
        result = recovery.analyze_syscall_usage(syscall_numbers)
        assert len(result.dangerous_syscalls) > 0
        assert result.risk_assessment['total_syscalls_used'] > 0

    def test_syscall_entry_dataclass(self):
        entry = SyscallEntry(
            number=59, name='execve', address=0x12345678,
            handler_name='sys_execve', security_level='critical'
        )
        assert entry.number == 59
        assert entry.name == 'execve'
        assert entry.security_level == 'critical'


class TestAIFunctionNamer:
    """测试 AI 函数命名器"""

    def test_naming_strategy_enum(self):
        assert NamingStrategy.AI_PREDICTION.value == "ai_prediction"
        assert NamingStrategy.HEURISTIC.value == "heuristic"

    def test_function_category_enum(self):
        assert FunctionCategory.IO.value == "io"
        assert FunctionCategory.MEMORY.value == "memory"
        assert FunctionCategory.CRYPTO.value == "crypto"

    def test_heuristic_namer_init(self):
        namer = HeuristicFunctionNamer()
        assert len(namer.api_patterns) > 0
        assert len(namer.string_patterns) > 0

    def test_analyze_api_calls(self):
        namer = HeuristicFunctionNamer()
        signature = FunctionSignature(
            address=0x1000, size=100,
            api_calls=['fopen', 'fread', 'fwrite', 'fclose']
        )
        result = namer._analyze_api_calls(signature)
        assert result is not None
        assert 'file_' in result['name']
        assert result['category'] == FunctionCategory.IO

    def test_analyze_strings(self):
        namer = HeuristicFunctionNamer()
        signature = FunctionSignature(
            address=0x1000, size=100,
            referenced_strings=['Error: file not found', 'config.json']
        )
        result = namer._analyze_strings(signature)
        assert result is not None
        assert 'error_' in result['name'] or 'config_' in result['name']

    def test_predict_name_heuristic(self):
        namer = HeuristicFunctionNamer()
        signature = FunctionSignature(
            address=0x1000, size=100,
            api_calls=['malloc', 'free', 'memcpy'],
            basic_block_count=5, instruction_count=50
        )
        prediction = namer.predict_name(signature)
        assert prediction.address == 0x1000
        assert len(prediction.predicted_name) > 0
        assert prediction.confidence >= 0

    def test_ai_function_namer_init(self):
        namer = AIFunctionNamer()
        assert namer.heuristic_namer is not None
        assert namer.prediction_cache is not None

    def test_function_signature_dataclass(self):
        signature = FunctionSignature(
            address=0x1000, size=256,
            api_calls=['socket', 'connect'],
            referenced_strings=['connecting to server'],
            basic_block_count=10, loop_detected=True
        )
        assert signature.address == 0x1000
        assert len(signature.api_calls) == 2
        assert signature.loop_detected == True

    def test_generate_naming_report(self):
        namer = AIFunctionNamer()
        predictions = [
            FunctionNamePrediction(
                address=0x1000, predicted_name='init_socket',
                confidence=0.85, category=FunctionCategory.NETWORK,
                semantic_tags=['init', 'socket'], source=NamingStrategy.HEURISTIC
            ),
            FunctionNamePrediction(
                address=0x2000, predicted_name='process_data',
                confidence=0.72, category=FunctionCategory.HANDLER,
                semantic_tags=['process', 'data'], source=NamingStrategy.HEURISTIC
            )
        ]
        result = NamingResult(predictions=predictions)
        result.statistics = {
            'total_functions': 2, 'high_confidence': 1,
            'medium_confidence': 1, 'low_confidence': 0,
            'categories': {'network': 1, 'handler': 1}
        }
        report = namer.generate_naming_report(result, 'markdown')
        assert '函数命名分析报告' in report
        assert 'init_socket' in report


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
