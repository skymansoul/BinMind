"""
测试栈溢出分析、格式化字符串检测、exploit执行器、反馈环和崩溃分析。
"""
from __future__ import annotations

import os
import tempfile

import pytest


# test stack_overflow_analyzer

class TestStackOverflowAnalyzer:
    """栈溢出分析器单元测试。"""

    def test_analyze_missing_file(self):
        """不存在的文件应返回未溢出结果。"""
        from core.stack_overflow_analyzer import analyze_stack_overflow

        result = analyze_stack_overflow('/nonexistent/bof_test', 'main')
        assert result['overflowable'] is False
        assert 'error' in result

    def test_result_structure(self):
        """结果结构应包含所有预期字段。"""
        from core.stack_overflow_analyzer import analyze_stack_overflow

        result = analyze_stack_overflow('/nonexistent/test', 'main')
        for key in ('overflowable', 'padding', 'has_canary',
                     'canary_leak_path', 'strategy', 'exploit_params'):
            assert key in result

    def test_static_analysis_without_angr(self):
        """无 angr 时应回退到静态分析。"""
        # 此测试确保模块在无 angr 环境也可导入和运行
        from core.stack_overflow_analyzer import _static_overflow_analysis

        result = _static_overflow_analysis('/nonexistent/test', 'main', None)
        assert isinstance(result, dict)
        assert 'overflowable' in result


# test format_string_detector

class TestFormatStringDetector:
    """格式化字符串检测器单元测试。"""

    def test_detect_missing_file(self):
        """不存在的文件应返回空列表。"""
        from core.format_string_detector import detect_format_string_vulns

        findings = detect_format_string_vulns('/nonexistent/fmt_test')
        assert isinstance(findings, list)
        assert len(findings) == 0

    def test_offset_to_arg_x86_64(self):
        """x86_64 偏移转换应正确。"""
        from core.format_string_detector import format_offset_to_arg_position

        pos = format_offset_to_arg_position(1, arch_bits=64)
        assert 'rdi' in pos

        pos = format_offset_to_arg_position(7, arch_bits=64)
        assert '7' in pos

    def test_offset_to_arg_i386(self):
        """i386 偏移转换应正确。"""
        from core.format_string_detector import format_offset_to_arg_position

        pos = format_offset_to_arg_position(1, arch_bits=32)
        assert '1' in pos

    def test_static_pattern_detection(self):
        """静态模式匹配应识别 printf(variable) 模式。"""
        from core.format_string_detector import _static_format_detect

        pseudocode = '''
        void vuln() {
            char buf[64];
            read(0, buf, 64);
            printf(buf);
        }
        '''
        findings = _static_format_detect('vuln', pseudocode)
        assert len(findings) >= 1
        assert findings[0]['format_func'] == 'printf'
        assert findings[0]['format_arg'] == 'buf'


# test exploit_executor

class TestExploitExecutor:
    """exploit 执行器单元测试。"""

    def test_dry_run_syntax_ok(self):
        """dry-run 模式应正确检查语法。"""
        from core.exploit_executor import execute_exploit

        with tempfile.NamedTemporaryFile(
            mode='w', suffix='.py', delete=False,
        ) as f:
            f.write('print("hello world")\n')
            script_path = f.name

        try:
            result = execute_exploit(
                script_path, '/nonexistent/target',
                sandbox='dry-run',
            )
            assert result['success'] is True
        finally:
            os.unlink(script_path)

    def test_dry_run_syntax_error(self):
        """dry-run 模式应检测语法错误。"""
        from core.exploit_executor import execute_exploit

        with tempfile.NamedTemporaryFile(
            mode='w', suffix='.py', delete=False,
        ) as f:
            f.write('this is not valid python @@@\n')
            script_path = f.name

        try:
            result = execute_exploit(
                script_path, '/nonexistent/target',
                sandbox='dry-run',
            )
            assert result['success'] is False
        finally:
            os.unlink(script_path)

    def test_missing_script(self):
        """不存在的脚本应返回错误。"""
        from core.exploit_executor import execute_exploit

        result = execute_exploit('/nonexistent/exploit.py', '/target')
        assert result['success'] is False
        assert 'not found' in result['error']

    def test_is_successful_with_flag(self):
        """检测到 flag{...} 应判定为成功。"""
        from core.exploit_executor import is_exploit_successful

        assert is_exploit_successful({
            'success': True, 'exit_code': 0,
            'stdout': 'flag{test_flag_here}',
        }) is True

    def test_is_successful_with_shell(self):
        """shell_obtained 标志应判定为成功。"""
        from core.exploit_executor import is_exploit_successful

        assert is_exploit_successful({
            'shell_obtained': True, 'exit_code': 1,
        }) is True


# test feedback_loop

class TestFeedbackLoop:
    """反馈迭代环单元测试。"""

    def test_extract_script_from_json(self):
        """应从 LLM JSON 响应中正确提取脚本。"""
        from core.feedback_loop import _extract_script_from_llm_response

        response = '{"optimized_script": "from pwn import *\\nprint(1)"}'
        script = _extract_script_from_llm_response(response)
        assert 'from pwn' in script

    def test_extract_script_from_code_block(self):
        """应从 Markdown 代码块中提取脚本。"""
        from core.feedback_loop import _extract_script_from_llm_response

        response = 'Here is the fix:\n```python\nfrom pwn import *\npwn()\n```'
        script = _extract_script_from_llm_response(response)
        assert 'from pwn' in script

    def test_extract_empty(self):
        """空响应应返回空字符串。"""
        from core.feedback_loop import _extract_script_from_llm_response

        assert _extract_script_from_llm_response('') == ''
        assert _extract_script_from_llm_response('no code here') == ''

    def test_error_signature(self):
        """错误签名应去重。"""
        from core.feedback_loop import _error_signature

        sig1 = _error_signature({'signal': 'SIGSEGV', 'exit_code': -11})
        sig2 = _error_signature({'signal': 'SIGSEGV', 'exit_code': -11})
        assert sig1 == sig2  # 相同错误应产生相同签名


# test crash_analyzer_llm

class TestCrashAnalyzerLLM:
    """LLM 崩溃分析器单元测试。"""

    def test_heuristic_fallback(self):
        """无 LLM 时应回退到启发式分析。"""
        from core.crash_analyzer_llm import _fallback_heuristic_analysis

        crash = {
            'crash_type': 'SIGSEGV',
            'severity': 'High',
            'registers': {'rip': '0x41414141'},
        }
        result = _fallback_heuristic_analysis(crash)
        assert result['source'] == 'heuristic'
        assert result['crash_type'] == 'SIGSEGV'
        assert 'root_cause' in result

    def test_analyze_without_llm(self):
        """无 API key 时应工作（回退到启发式）。"""
        # 确保 OPENAI_API_KEY 为空
        import config
        old_key = config.OPENAI_API_KEY
        config.OPENAI_API_KEY = ''

        try:
            from core.crash_analyzer_llm import analyze_crash_with_llm

            crash = {'crash_type': 'heap-buffer-overflow', 'raw': 'ASAN: heap overflow'}
            result = analyze_crash_with_llm(crash)
            assert 'root_cause' in result
            assert result['source'] == 'heuristic'
        finally:
            config.OPENAI_API_KEY = old_key
