"""
crash_analyzer_llm 模块测试 —— LLM 深度崩溃分析。

实际 API:
  - analyze_crash_with_llm(crash_data, binary_path=None, decompiled_context=None, binfo=None)
  - batch_analyze_crashes(crashes, binary_path, parallel=False)
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.crash_analyzer_llm import analyze_crash_with_llm, batch_analyze_crashes


class TestCrashAnalyzerLLM(unittest.TestCase):

    def setUp(self):
        self.sample_crash = {
            'registers': {
                'rip': '0x4141414141414141',
                'rsp': '0x7fffffffe000',
                'rbp': '0x4141414141414141',
            },
            'stack_trace': [
                '#0 0x4141414141414141 in ?? ()',
                '#1 0x00007ffff7c29d90 in __libc_start_main ()',
            ],
            'fault_instruction': 'ret',
            'signal': 'SIGSEGV',
            'output': 'Segmentation fault (core dumped)',
        }

    def test_analyze_without_api_key(self):
        """无 API Key 时应降级返回基础分析。"""
        old_key = os.environ.get('OPENAI_API_KEY', '')
        os.environ.pop('OPENAI_API_KEY', None)
        try:
            result = analyze_crash_with_llm(self.sample_crash)
            self.assertIsInstance(result, dict)
            self.assertIn('crash_type', result)
        finally:
            if old_key:
                os.environ['OPENAI_API_KEY'] = old_key

    def test_analyze_return_keys(self):
        result = analyze_crash_with_llm(self.sample_crash)
        self.assertIsInstance(result, dict)
        for key in ('crash_type', 'root_cause', 'exploitability'):
            self.assertIn(key, result, f'Result should contain key: {key}')

    def test_analyze_with_binfo(self):
        binfo = {'arch': 'x86-64', 'bits': 64}
        result = analyze_crash_with_llm(self.sample_crash, binfo=binfo)
        self.assertIsInstance(result, dict)

    def test_analyze_with_decompiled_context(self):
        ctx = 'int main() { char buf[64]; gets(buf); return 0; }'
        result = analyze_crash_with_llm(
            self.sample_crash, decompiled_context=ctx,
        )
        self.assertIsInstance(result, dict)

    def test_analyze_with_binary_path(self):
        result = analyze_crash_with_llm(
            self.sample_crash, binary_path='/nonexistent/bin',
        )
        self.assertIsInstance(result, dict)

    def test_empty_crash_data(self):
        result = analyze_crash_with_llm({})
        self.assertIsInstance(result, dict)


class TestBatchAnalyzeCrashes(unittest.TestCase):

    def test_empty_list(self):
        result = batch_analyze_crashes([], binary_path='/nonexistent/bin')
        self.assertIsInstance(result, list)
        self.assertEqual(len(result), 0)

    def test_single_crash(self):
        crash = {'registers': {'rip': '0x0'}, 'signal': 'SIGSEGV'}
        result = batch_analyze_crashes([crash], binary_path='/nonexistent/bin')
        self.assertIsInstance(result, list)
        self.assertEqual(len(result), 1)

    def test_multiple_crashes(self):
        crashes = [
            {'registers': {'rip': '0x0'}, 'signal': 'SIGSEGV'},
            {'registers': {'rip': '0x1'}, 'signal': 'SIGABRT'},
        ]
        result = batch_analyze_crashes(crashes, binary_path='/nonexistent/bin')
        self.assertEqual(len(result), 2)


if __name__ == '__main__':
    unittest.main()
