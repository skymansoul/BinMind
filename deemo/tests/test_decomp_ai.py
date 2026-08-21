# test_decomp_ai -- 测ANSI strip/函数名sanitize/AI响应解析/模拟分析
# _simulate_analysis是在没有LLM时的fallback，只依赖关键词匹配
import os
import sys
import unittest
import json
import re

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.analysis.decompiler.decomp_ai import (
    sanitize_function_name,
    strip_ansi_escape,
    DecompilerAI
)


class TestStripAnsiEscape(unittest.TestCase):
    """strip_ansi_escape -- 去除ANSI颜色转义码，radare2输出经常带这个"""

    def test_empty_text(self):
        self.assertEqual(strip_ansi_escape(''), '')
        self.assertEqual(strip_ansi_escape(None), None)

    def test_plain_text(self):
        # 纯文本原封不动
        text = 'Hello, world!'
        self.assertEqual(strip_ansi_escape(text), text)

    def test_basic_color_codes(self):
        text = '\x1b[31mRed\x1b[0m'
        self.assertEqual(strip_ansi_escape(text), 'Red')

    def test_multiple_color_codes(self):
        text = '\x1b[31mRed\x1b[32mGreen\x1b[33mYellow\x1b[0m'
        self.assertEqual(strip_ansi_escape(text), 'RedGreenYellow')

    def test_rgb_color_codes(self):
        """RGB格式: \\x1b[38;2;R;G;Bm"""
        text = '\x1b[38;2;197;15;31mColor\x1b[0m'
        self.assertEqual(strip_ansi_escape(text), 'Color')

    def test_bold_and_reset(self):
        text = '\x1b[1mBold\x1b[0m'
        self.assertEqual(strip_ansi_escape(text), 'Bold')

    def test_real_world_disassembly(self):
        """真实radare2输出的例子，混合了地址颜色、指令颜色、关键字颜色"""
        text = '            \x1b[38;2;19;161;14m0x004011cd\x1b[0m      \x1b[38;2;204;204;204mf3\x1b[0m             \x1b[1;38;2;231;72;86minvalid\x1b[0m\x1b[0m\x1b[0m'
        expected = '            0x004011cd      f3             invalid'
        self.assertEqual(strip_ansi_escape(text), expected)

    def test_mixed_content(self):
        # 多行混合内容，每行都有不同的颜色
        text = '\x1b[38;2;58;150;221m;-- vuln:\x1b[0m\n            \x1b[38;2;19;161;14m0x004011cd\x1b[0m      \x1b[38;2;204;204;204m55\x1b[0m             \x1b[38;2;136;23;152mpush\x1b[38;2;58;150;221m rbp\x1b[0m'
        expected = ';-- vuln:\n            0x004011cd      55             push rbp'
        self.assertEqual(strip_ansi_escape(text), expected)


class TestSanitizeFunctionName(unittest.TestCase):

    def test_normal_function_name(self):
        result = sanitize_function_name('main')
        self.assertEqual(result, 'main')

    def test_function_name_with_underscore(self):
        result = sanitize_function_name('_start')
        self.assertEqual(result, '_start')

    def test_function_name_with_dots(self):
        # 点号应该保留（如sym.main）
        result = sanitize_function_name('sym.main')
        self.assertEqual(result, 'sym.main')

    def test_function_name_with_newline(self):
        """换行符必须被清理掉"""
        result = sanitize_function_name('main\nls')
        self.assertNotIn('\n', result)

    def test_function_name_with_semicolon(self):
        # 分号是命令分隔符，必须清理
        result = sanitize_function_name('main;rm -rf /')
        self.assertNotIn(';', result)
        self.assertNotIn('rm -rf /', result)

    def test_function_name_with_ampersand(self):
        result = sanitize_function_name('main&evil')
        self.assertNotIn('&', result)

    def test_function_name_with_special_chars(self):
        # $()这种shell substitution必须去掉
        result = sanitize_function_name('main$(evil)')
        self.assertNotIn('$(', result)
        self.assertNotIn(')', result)

    def test_function_name_with_spaces(self):

        result = sanitize_function_name('main func')
        self.assertNotIn(' ', result)

    def test_empty_function_name(self):
        """空字符串fallback到'main'"""
        result = sanitize_function_name('')
        self.assertEqual(result, 'main')

    def test_none_function_name(self):
        # None也要fallback到'main'
        result = sanitize_function_name(None)
        self.assertEqual(result, 'main')

    def test_all_dangerous_chars(self):
        """所有危险字符都不能出现在输出里"""
        result = sanitize_function_name('main;\n&|<>$(){}[]')
        self.assertNotIn(';', result)
        self.assertNotIn('\n', result)
        self.assertNotIn('&', result)
        self.assertNotIn('|', result)


class TestDecompilerAI(unittest.TestCase):
    """DecompilerAI -- AI驱动的反编译分析主类"""

    def setUp(self):
        self.decompiler = DecompilerAI('./test_binary', openai_client=None)

    def test_check_radare2(self):
        # available_decompilers是一个dict，key是工具名
        available = self.decompiler.available_decompilers
        self.assertIsInstance(available, dict)

    def test_parse_ai_response_valid_json(self):
        """标准JSON格式响应应该被正确解析"""
        response = '''
{
    "vulnerabilities": [
        {
            "type": "Stack Overflow",
            "location": "line 42",
            "description": "Buffer overflow",
            "severity": "High",
            "exploitation": "Overflow buffer to control RIP",
            "code_snippet": "gets(buffer)"
        }
    ],
    "summary": "Found a stack overflow vulnerability",
    "risk_level": "High"
}
'''
        result = self.decompiler._parse_ai_response(response)

        self.assertFalse(result.get('parse_error'))
        self.assertIn('vulnerabilities', result)
        self.assertEqual(len(result['vulnerabilities']), 1)
        self.assertEqual(result['vulnerabilities'][0]['type'], 'Stack Overflow')
        self.assertEqual(result['risk_level'], 'High')

    def test_parse_ai_response_with_code_block(self):
        """json包裹在```json代码块里也能正确提取"""
        response = '''
```json
{
    "vulnerabilities": [],
    "summary": "No significant vulnerabilities found",
    "risk_level": "Low"
}
```
'''
        result = self.decompiler._parse_ai_response(response)

        self.assertFalse(result.get('parse_error'))
        self.assertEqual(result['risk_level'], 'Low')
        self.assertEqual(len(result['vulnerabilities']), 0)

    def test_parse_ai_response_invalid_json(self):
        """纯文本无法解析时应该有parse_error"""
        response = 'This is just plain text, not JSON at all.'
        result = self.decompiler._parse_ai_response(response)

        self.assertTrue(result.get('parse_error'))
        self.assertEqual(len(result['vulnerabilities']), 0)
        self.assertIn('raw_response', result)

    def test_parse_ai_response_malformed_json(self):
        """vulnerabilities不是数组时应该修正为空数组"""
        response = '''
{
    "vulnerabilities": "should be an array",
    "summary": "test"
}
'''
        result = self.decompiler._parse_ai_response(response)

        self.assertFalse(result.get('parse_error'))
        self.assertEqual(result['vulnerabilities'], [])

    def test_parse_ai_response_empty(self):
        # 空字符串 => parse_error
        result = self.decompiler._parse_ai_response('')

        self.assertTrue(result.get('parse_error'))
        self.assertEqual(len(result['vulnerabilities']), 0)

    def test_parse_ai_response_missing_fields(self):
        """缺少summary和risk_level时应该有默认值"""
        response = '{"vulnerabilities": [{"type": "Test"}]}'
        result = self.decompiler._parse_ai_response(response)

        self.assertFalse(result.get('parse_error'))
        self.assertIn('summary', result)
        self.assertIn('risk_level', result)

    def test_simulate_analysis_dangerous_funcs(self):
        """gets/system/strcpy都应该被模拟分析检测到"""
        binary_info = {
            'imports': {
                'dangerous_functions': ['gets', 'system', 'strcpy']
            }
        }
        pseudocode = '''
void vuln() {
    char buffer[100];
    gets(buffer);
}
'''
        result = self.decompiler._simulate_analysis(pseudocode, binary_info, 'vuln')

        self.assertIn('vulnerabilities', result)
        self.assertGreater(len(result['vulnerabilities']), 0)

        vuln_types = [v['type'] for v in result['vulnerabilities']]
        self.assertTrue(any('gets' in v or '栈溢出' in v.lower() for v in vuln_types))
        self.assertTrue(any('system' in v or '命令注入' in v.lower() for v in vuln_types))

    def test_simulate_analysis_no_dangerous_funcs(self):
        """没有危险函数时risk_level=Low, mode=simulation"""
        binary_info = {
            'imports': {
                'dangerous_functions': []
            }
        }
        pseudocode = '''
void safe() {
    char buffer[100];
    fgets(buffer, sizeof(buffer), stdin);
}
'''
        result = self.decompiler._simulate_analysis(pseudocode, binary_info, 'safe')

        self.assertEqual(result['risk_level'], 'Low')
        self.assertEqual(result['mode'], 'simulation')


if __name__ == '__main__':
    unittest.main()
