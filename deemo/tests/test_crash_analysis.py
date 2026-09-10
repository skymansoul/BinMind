# test_crash_analysis -- 寄存器解析和启发式分析，format_string/double_free/sigabrt都要覆盖
# 这玩意儿出bug就会把crash类型搞错，影响整个vuln分析管线
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.analysis.dynamic.crash_analysis import (
    parse_registers_from_text,
    REGISTER_PATTERNS,
    REGISTER_NAMES,
    CrashAnalyzer
)


class TestRegisterParsing(unittest.TestCase):
    """寄存器文本解析 -- 支持=号/冒号/空格三种格式，还有gdb的info registers输出"""

    def test_parse_register_format_equals(self):
        """rax = 0x414141... 这种是pwntools的输出格式"""
        text = "rax = 0x4141414141414141"
        result = parse_registers_from_text(text)
        self.assertIn('rax', result)
        self.assertEqual(result['rax'], '0x4141414141414141')

    def test_parse_register_format_colon(self):
        text = "RAX: 0x4141414141414141"
        result = parse_registers_from_text(text)
        self.assertIn('rax', result)
        self.assertEqual(result['rax'], '0x4141414141414141')

    def test_parse_register_format_space(self):
        text = "rax 0x4141414141414141"
        result = parse_registers_from_text(text)
        self.assertIn('rax', result)
        self.assertEqual(result['rax'], '0x4141414141414141')

    def test_parse_register_multiple(self):
        text = """
        rax = 0x0000000000000000
        rbx = 0x0000000000000000
        rcx: 0x1234567890abcdef
        rbp 0x4141414141414141
        """
        result = parse_registers_from_text(text)
        self.assertIn('rax', result)
        self.assertIn('rbx', result)
        self.assertIn('rcx', result)
        self.assertIn('rbp', result)
        self.assertEqual(result['rbp'], '0x4141414141414141')

    def test_parse_register_gdb_format(self):
        """gdb info registers的输出，有三列：寄存器名、hex值、decimal值"""
        text = """
        rax            0x0      0
        rbx            0x0      0
        rcx            0x7ffff7a04d40   140737347882304
        rdx            0x7ffff7dd18d0   140737351858384
        rsi            0x0      0
        rdi            0x1      1
        rbp            0x7fffffffe180   0x7fffffffe180
        rsp            0x7fffffffe140   0x7fffffffe140
        r8             0x0      0
        r9             0x7ffff7dd04c0   140737351853248
        r10            0x0      0
        r11            0x246    582
        r12            0x555555555040   93824992235584
        r13            0x7fffffffe280   140737488347776
        r14            0x0      0
        r15            0x0      0
        rip            0x55555555514a   0x55555555514a <main+31>
        """
        result = parse_registers_from_text(text)
        self.assertIn('rax', result)
        self.assertIn('rip', result)
        self.assertIn('rbp', result)

    def test_parse_register_empty_text(self):
        # 空字符串直接返回空dict
        result = parse_registers_from_text('')
        self.assertEqual(result, {})

    def test_parse_register_no_registers(self):
        text = "This is some text without any register information."
        result = parse_registers_from_text(text)
        self.assertEqual(result, {})

    def test_parse_register_32bit(self):
        """32bit的寄存器也要能解析：eax/ebx/ecx/eip"""
        text = """
        eax = 0x00000000
        ebx = 0x00000000
        ecx: 0x12345678
        eip 0x41414141
        """
        result = parse_registers_from_text(text)
        self.assertIn('eax', result)
        self.assertIn('ebx', result)
        self.assertIn('ecx', result)
        self.assertIn('eip', result)
        self.assertEqual(result['eip'], '0x41414141')


class TestCrashAnalyzer(unittest.TestCase):
    """CrashAnalyzer测试 -- 启发式分析和完整analyze流程"""

    def setUp(self):
        self.analyzer = CrashAnalyzer(openai_client=None)

    def test_parse_crash_info_registers_dict(self):
        # registers以dict形式传入
        crash_data = {
            'registers': {
                'rax': '0x0',
                'rbp': '0x41414141',
                'rip': '0x42424242'
            }
        }
        parsed = self.analyzer.parse_crash_info(crash_data)
        self.assertIn('rax: 0x0', parsed['registers'])
        self.assertIn('rbp: 0x41414141', parsed['registers'])

    def test_parse_crash_info_stack_trace_list(self):
        crash_data = {
            'stack_trace': [
                '#0  0x000055555555514a in main ()',
                '#1  0x00007ffff7c29d90 in __libc_start_call_main ()'
            ]
        }
        parsed = self.analyzer.parse_crash_info(crash_data)
        self.assertIn('in main ()', parsed['stack_trace'])

    def test_parse_crash_info_with_signal(self):
        """signal字段要合并到program_output里"""
        crash_data = {
            'registers': {'rax': '0x0'},
            'signal': 'SIGSEGV',
            'output': 'Segmentation fault'
        }
        parsed = self.analyzer.parse_crash_info(crash_data)
        self.assertIn('SIGSEGV', parsed['program_output'])

    def test_heuristic_analysis_rip_controlled(self):
        """RIP被覆盖成0x414141... => 高危，可控EIP"""
        crash_data = {
            'registers': {
                'rip': '0x4141414141414141',
                'rbp': '0x4141414141414141'
            }
        }
        result = self.analyzer.heuristic_analysis(crash_data)
        self.assertEqual(result['exploitability'], 'High')

    def test_heuristic_analysis_sigabrt_stack_chk(self):
        # SIGABRT + __stack_chk_fail => 栈保护被触发，Canary
        crash_data = {
            'signal': 'SIGABRT',
            'stack_trace': ['#0  __libc_start_main', '__stack_chk_fail']
        }
        result = self.analyzer.heuristic_analysis(crash_data)
        self.assertIn('Canary', result['vulnerability_type'])

    def test_heuristic_analysis_format_string(self):
        """输出里有一堆%x => format string attack"""
        crash_data = {
            'output': '%x%x%x%x'
        }
        result = self.analyzer.heuristic_analysis(crash_data)
        self.assertIn('Format', result['vulnerability_type'])

    def test_heuristic_analysis_double_free(self):
        crash_data = {
            'output': 'double free or corruption'
        }
        result = self.analyzer.heuristic_analysis(crash_data)
        self.assertIn('Double Free', result['vulnerability_type'])

    def test_analyze_without_ai(self):
        """没有openai_client的情况下analyze也能跑，走启发式分析"""
        crash_data = {
            'registers': {'rip': '0x4141414141414141'},
            'signal': 'SIGSEGV'
        }
        result = self.analyzer.analyze(crash_data)
        self.assertIn('parsed_info', result)
        self.assertIn('heuristic_analysis', result)
        self.assertIn('combined', result)


if __name__ == '__main__':
    unittest.main()
