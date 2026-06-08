import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.crash_analysis import (
    parse_registers_from_text,
    REGISTER_PATTERNS,
    REGISTER_NAMES,
    CrashAnalyzer
)


class TestRegisterParsing(unittest.TestCase):

    def test_parse_register_format_equals(self):
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
        result = parse_registers_from_text('')
        self.assertEqual(result, {})

    def test_parse_register_no_registers(self):
        text = "This is some text without any register information."
        result = parse_registers_from_text(text)
        self.assertEqual(result, {})

    def test_parse_register_32bit(self):
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

    def setUp(self):
        self.analyzer = CrashAnalyzer(openai_client=None)

    def test_parse_crash_info_registers_dict(self):
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
        crash_data = {
            'registers': {'rax': '0x0'},
            'signal': 'SIGSEGV',
            'output': 'Segmentation fault'
        }
        parsed = self.analyzer.parse_crash_info(crash_data)
        self.assertIn('SIGSEGV', parsed['program_output'])

    def test_heuristic_analysis_rip_controlled(self):
        crash_data = {
            'registers': {
                'rip': '0x4141414141414141',
                'rbp': '0x4141414141414141'
            }
        }
        result = self.analyzer.heuristic_analysis(crash_data)
        self.assertEqual(result['exploitability'], 'High')

    def test_heuristic_analysis_sigabrt_stack_chk(self):
        crash_data = {
            'signal': 'SIGABRT',
            'stack_trace': ['#0  __libc_start_main', '__stack_chk_fail']
        }
        result = self.analyzer.heuristic_analysis(crash_data)
        self.assertIn('Canary', result['vulnerability_type'])

    def test_heuristic_analysis_format_string(self):
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
