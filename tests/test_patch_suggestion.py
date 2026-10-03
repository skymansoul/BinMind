
"""
智能补丁建议模块单元测试
"""

import os
import sys
import unittest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.patch_suggestion import PatchSuggester, PatchSuggestion


class TestPatchSuggestion(unittest.TestCase):
    """测试补丁建议结果类"""

    def test_to_dict(self):
        """测试转换为字典"""
        suggestion = PatchSuggestion()
        suggestion.patch_id = "patch123"
        suggestion.vuln_id = 1
        suggestion.vuln_type = "stack_overflow"
        suggestion.patch_diff = "--- a/file.c\n+++ b/file.c\n@@ -1 +1 @@\n-old\n+new"
        suggestion.description = "修复说明"
        suggestion.confidence = 0.85
        suggestion.suggestion_type = "boundary_check"
        suggestion.target_function = "main"
        suggestion.target_offset = 0x1234

        result = suggestion.to_dict()

        self.assertEqual(result['patch_id'], "patch123")
        self.assertEqual(result['vuln_id'], 1)
        self.assertEqual(result['vuln_type'], "stack_overflow")
        self.assertIn("@@ -1 +1 @@", result['patch_diff'])
        self.assertEqual(result['confidence'], 0.85)
        self.assertEqual(result['target_function'], "main")
        self.assertEqual(result['target_offset'], 0x1234)

    def test_default_values(self):
        """测试默认值"""
        suggestion = PatchSuggestion()

        self.assertEqual(suggestion.patch_id, "")
        self.assertEqual(suggestion.vuln_id, 0)
        self.assertEqual(suggestion.confidence, 0.0)


class TestPatchSuggester(unittest.TestCase):
    """测试补丁建议器"""

    def setUp(self):
        self.suggester = PatchSuggester()

    def test_generate_default_patch_stack_overflow(self):
        """测试栈溢出默认补丁"""
        patch = self.suggester._generate_default_patch("", "stack_overflow")

        self.assertIn("strcpy(buffer, input)", patch)
        self.assertIn("strlen(input) >= BUFFER_SIZE", patch)
        self.assertIn("return;  // 防止栈溢出", patch)

    def test_generate_default_patch_format_string(self):
        patch = self.suggester._generate_default_patch("", "format_string")

        self.assertIn("-    printf(user_input);", patch)
        self.assertIn("+    printf(\"%s\", user_input);", patch)

    def test_generate_default_patch_integer_overflow(self):
        """测试整数溢出默认补丁"""
        patch = self.suggester._generate_default_patch("", "integer_overflow")

        self.assertIn("INT_MAX - b", patch)
        self.assertIn("return -1;  // 防止整数溢出", patch)

    def test_generate_default_patch_use_after_free(self):
        """测试UAF默认补丁"""
        patch = self.suggester._generate_default_patch("", "use_after_free")

        self.assertIn("free(data);", patch)
        self.assertIn("data = NULL;  // 防止UAF", patch)

    def test_generate_default_description(self):
        """测试默认修复说明"""
        desc = self.suggester._generate_default_description("stack_overflow")
        self.assertIn("边界检查", desc)
        self.assertIn("strncpy", desc)
        self.assertIn("strcpy", desc)

        desc = self.suggester._generate_default_description("format_string")
        self.assertIn("参数化", desc)

        desc = self.suggester._generate_default_description("unknown")
        self.assertIn("分析漏洞上下文", desc)

    def test_parse_ai_response_with_patch(self):
        """测试解析AI响应（包含补丁）"""
        response = """## 修复说明
这是修复说明内容。

# 建议补丁
# ```diff
# --- a/test.c
# +++ b/test.c
@@ -1,3 +1,5 @@
 void func() {
+    // 添加检查
     printf("hello");
 }
```

# 置信度
0.95"""

        result = self.suggester._parse_ai_response(response)

        self.assertIn("void func()", result['patch'])
        self.assertEqual(result['description'], "这是修复说明内容。")
        self.assertEqual(result['confidence'], 0.95)

    def test_parse_ai_response_no_patch(self):
        """测试解析AI响应（无补丁）"""
        response = "修复建议：添加边界检查。置信度：0.7"

        result = self.suggester._parse_ai_response(response)

        self.assertEqual(result['patch'], "")
        self.assertEqual(result['description'], "修复建议：添加边界检查。置信度：0.7")
        self.assertEqual(result['confidence'], 0.7)

    def test_build_prompt(self):
        """测试构建提示词"""
        prompt = self.suggester._build_prompt(
            decompiled_code="void func() { ... }",
            vuln_type="stack_overflow",
            function_name="test_func",
            instruction_offset=0x100,
            protection_info={"NX": True, "ASLR": True}
        )

        self.assertIn("stack_overflow", prompt)
        self.assertIn("test_func", prompt)
        self.assertIn("0x100", prompt)
        self.assertIn("NX", prompt)
        self.assertIn("ASLR", prompt)

    def test_suggestion_type_detection(self):
        """测试建议类型检测"""
        response = "建议使用strncpy替代strcpy进行安全的字符串复制。"
        result = self.suggester._parse_ai_response(response)
        self.assertEqual(result['suggestion_type'], 'safe_function')

        response = "建议在free后将指针置空。"
        result = self.suggester._parse_ai_response(response)
        self.assertEqual(result['suggestion_type'], 'null_after_free')

        response = "建议添加边界检查防止缓冲区溢出。"
        result = self.suggester._parse_ai_response(response)
        self.assertEqual(result['suggestion_type'], 'boundary_check')

    def test_generate_suggestion_no_ai(self):
        """测试无AI时生成建议"""
        suggestion = self.suggester.generate_suggestion(
            decompiled_code="void func(char *input) { char buf[100]; strcpy(buf, input); }",
            vuln_type="stack_overflow",
            function_name="vulnerable_func"
        )

        self.assertEqual(suggestion.vuln_type, "stack_overflow")
        self.assertEqual(suggestion.target_function, "vulnerable_func")
        self.assertIn("strcpy", suggestion.patch_diff)
        self.assertEqual(suggestion.confidence, 0.5)

    @patch('modules.patch_suggestion.OpenAI')
    def test_generate_suggestion_with_ai(self, mock_openai):
        """测试使用AI生成建议"""
        mock_client = MagicMock()
        mock_openai.return_value = mock_client
        mock_client.chat.completions.create.return_value.choices[0].message.content = """## 修复说明
修复缓冲区溢出漏洞。

# 建议补丁
# ```diff
# --- a/test.c
# +++ b/test.c
@@ -1 +1 @@
-old code
+new code
```

# 置信度
0.9"""

        with patch('modules.patch_suggestion.Config.AI_PROVIDER', 'openai'):
            with patch('modules.patch_suggestion.Config.OPENAI_API_KEY', 'test_key'):
                suggester = PatchSuggester()
                suggestion = suggester.generate_suggestion(
                    decompiled_code="void func() {}",
                    vuln_type="stack_overflow"
                )

        self.assertEqual(suggestion.confidence, 0.9)
        self.assertGreater(len(suggestion.patch_diff), 0)

    def test_format_patch_for_report(self):
        """测试格式化补丁用于报告"""
        suggestion = PatchSuggestion()
        suggestion.patch_id = "123"
        suggestion.vuln_type = "stack_overflow"
        suggestion.target_function = "main"
        suggestion.target_offset = 0x40
        suggestion.confidence = 0.85
        suggestion.description = "测试说明"
        suggestion.patch_diff = "diff content"

        formatted = self.suggester.format_patch_for_report(suggestion)

        self.assertIn("补丁建议 ID: 123", formatted)
        self.assertIn("stack_overflow", formatted)
        self.assertIn("main", formatted)
        self.assertIn("0x40", formatted)
        self.assertIn("85.0%", formatted)



if __name__ == '__main__':
    unittest.main()


