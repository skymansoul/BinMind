import os
import sys
import unittest
import json
import re

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.decomp_ai import (
    sanitize_function_name,
    strip_ansi_escape,
    DecompilerAI
)


class TestStripAnsiEscape(unittest.TestCase):

    def test_empty_text(self):
        self.assertEqual(strip_ansi_escape(''), '')
        self.assertEqual(strip_ansi_escape(None), None)

    def test_plain_text(self):
        text = 'Hello, world!'
        self.assertEqual(strip_ansi_escape(text), text)

    def test_basic_color_codes(self):
        text = '\x1b[31mRed\x1b[0m'
        self.assertEqual(strip_ansi_escape(text), 'Red')

    def test_multiple_color_codes(self):
        text = '\x1b[31mRed\x1b[32mGreen\x1b[33mYellow\x1b[0m'
        self.assertEqual(strip_ansi_escape(text), 'RedGreenYellow')

    def test_rgb_color_codes(self):
        text = '\x1b[38;2;197;15;31mColor\x1b[0m'
        self.assertEqual(strip_ansi_escape(text), 'Color')

    def test_bold_and_reset(self):
        text = '\x1b[1mBold\x1b[0m'
        self.assertEqual(strip_ansi_escape(text), 'Bold')

    def test_real_world_disassembly(self):
        text = '            \x1b[38;2;19;161;14m0x004011cd\x1b[0m      \x1b[38;2;204;204;204mf3\x1b[0m             \x1b[1;38;2;231;72;86minvalid\x1b[0m\x1b[0m\x1b[0m'
        expected = '            0x004011cd      f3             invalid'
        self.assertEqual(strip_ansi_escape(text), expected)

    def test_mixed_content(self):
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
        result = sanitize_function_name('sym.main')
        self.assertEqual(result, 'sym.main')

    def test_function_name_with_newline(self):
        result = sanitize_function_name('main\nls')
        self.assertNotIn('\n', result)

    def test_function_name_with_semicolon(self):
        result = sanitize_function_name('main;rm -rf /')
        self.assertNotIn(';', result)
        self.assertNotIn('rm -rf /', result)

    def test_function_name_with_ampersand(self):
        result = sanitize_function_name('main&evil')
        self.assertNotIn('&', result)

    def test_function_name_with_special_chars(self):
        result = sanitize_function_name('main$(evil)')
        self.assertNotIn('$(', result)
        self.assertNotIn(')', result)

    def test_function_name_with_spaces(self):
        result = sanitize_function_name('main func')
        self.assertNotIn(' ', result)

    def test_empty_function_name(self):
        result = sanitize_function_name('')
        self.assertEqual(result, 'main')

    def test_none_function_name(self):
        result = sanitize_function_name(None)
        self.assertEqual(result, 'main')

    def test_all_dangerous_chars(self):
        result = sanitize_function_name('main;\n&|<>$(){}[]')
        self.assertNotIn(';', result)
        self.assertNotIn('\n', result)
        self.assertNotIn('&', result)
        self.assertNotIn('|', result)


class TestDecompilerAI(unittest.TestCase):

    def setUp(self):
        self.decompiler = DecompilerAI('./test_binary', openai_client=None)

    def test_check_radare2(self):
        available = self.decompiler.available_decompilers
        self.assertIsInstance(available, dict)

    def test_parse_ai_response_valid_json(self):
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
        response = '''
Here is my analysis:

```json
{
    "vulnerabilities": [],
    "summary": "No significant vulnerabilities found",
    "risk_level": "Low"
}
```

Let me know if you need more details.
'''
        result = self.decompiler._parse_ai_response(response)
        
        self.assertFalse(result.get('parse_error'))
        self.assertEqual(result['risk_level'], 'Low')
        self.assertEqual(len(result['vulnerabilities']), 0)

    def test_parse_ai_response_invalid_json(self):
        response = 'This is just plain text, not JSON at all.'
        result = self.decompiler._parse_ai_response(response)
        
        self.assertTrue(result.get('parse_error'))
        self.assertEqual(len(result['vulnerabilities']), 0)
        self.assertIn('raw_response', result)

    def test_parse_ai_response_malformed_json(self):
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
        result = self.decompiler._parse_ai_response('')
        
        self.assertTrue(result.get('parse_error'))
        self.assertEqual(len(result['vulnerabilities']), 0)

    def test_parse_ai_response_missing_fields(self):
        response = '{"vulnerabilities": [{"type": "Test"}]}'
        result = self.decompiler._parse_ai_response(response)
        
        self.assertFalse(result.get('parse_error'))
        self.assertIn('summary', result)
        self.assertIn('risk_level', result)

    def test_simulate_analysis_dangerous_funcs(self):
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
