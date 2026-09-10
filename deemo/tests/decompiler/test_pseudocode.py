# 结构化伪代码测试 : 验证从 flat 输出到结构化表示的转换

import pytest
import os
import json
# import sys  -- conftest handles this

from modules.analysis.decompiler.structured_pseudocode import (
    StructuredPseudocodeGenerator,
    StructuredPseudocode,
    CodeBlock,
    BlockType,
    OutputFormat,
    VariableInfo,
    generate_structured_pseudocode,
    format_structured_output,
)


# 测试用的伪代码片段

SIMPLE_FUNC = """\
int max(int a, int b) {
    int result;
    if (a > b) {
        result = a;
    } else {
        result = b;
    }
    return result;
}"""

LOOP_FUNC = """\
int sum_array(int *arr, int len) {
    int i;
    int total;
    total = 0;
    for (i = 0; i < len; i++) {
        total = total + arr[i];
    }
    return total;
}"""

WHILE_FUNC = """\
int gcd(int a, int b) {
    while (b != 0) {
        int temp;
        temp = b;
        b = a % b;
        a = temp;
    }
    return a;
}"""

SWITCH_FUNC = """\
char *get_status(int code) {
    char *result;
    switch(code) {
        case 200:
            result = "OK";
            break;
        case 404:
            result = "Not Found";
            break;
        default:
            result = "Unknown";
            break;
    }
    return result;
}"""

NESTED_FUNC = """\
int complex_logic(int x, int y) {
    int result;
    if (x > 0) {
        if (y > 0) {
            result = x + y;
        } else {
            result = x - y;
        }
    } else {
        for (int i = 0; i < 10; i++) {
            result = result + i;
        }
    }
    return result;
}"""

GOTO_FUNC = """\
void spaghetti() {
    int a;
    a = 1;
    goto label_b;
label_a:
    a = a + 2;
    return;
label_b:
    a = a * 3;
    goto label_a;
}"""

TRY_CATCH_FUNC = """\
int safe_divide(int a, int b) {
    int result;
    try {
        result = a / b;
    } catch (int e) {
        result = -1;
    }
    return result;
}"""

EMPTY_FUNC = """\
void noop() {
}"""

BADLY_FORMATTED = """\
unknown do_stuff(in_1, in_2) {
    var_3 = in_1 + in_2;
    goto LAB_001100;
    if (var_3 > 100) {
        // ... TODO: implement
    }
}"""

# Tests


class TestStructuredPseudocodeGenerator:
    """测试核心生成器"""

    @classmethod
    def setup_class(cls):
        cls.generator = StructuredPseudocodeGenerator()

    def test_generate_simple_function(self):
        """基本函数 — 应正确识别函数签名和 if/else"""
        sp = self.generator.generate(SIMPLE_FUNC, with_types=True)

        assert sp.function_name == "max"
        assert sp.return_type == "int"
        assert len(sp.parameters) == 2
        assert sp.parameters[0].name == "a"
        assert sp.parameters[1].name == "b"
        assert sp.root_block is not None
        assert sp.root_block.block_type == BlockType.FUNCTION
        # 应该有 if/else 子块
        assert len(sp.root_block.children) >= 1

    def test_generate_loop_function(self):
        """for 循环函数 — 应识别循环和变量"""
        sp = self.generator.generate(LOOP_FUNC, with_types=True)

        assert sp.function_name == "sum_array"
        assert len(sp.variables) >= 2  # i, total at minimum
        assert "total" in sp.variables
        assert "i" in sp.variables
        # 控制流提示应包括 LOOPED
        assert any("LOOPED" in h or "loop" in h.lower() or "for" in h.lower()
                   for h in sp.control_flow_hints), \
            f"Expected loop hint, got: {sp.control_flow_hints}"

    def test_generate_while_function(self):
        """while 循环函数 — 应识别 while"""
        sp = self.generator.generate(WHILE_FUNC, with_types=True)

        assert sp.function_name == "gcd"
        # 检查是否有 while 类型的子块
        has_while = False
        def _check_children(block):
            nonlocal has_while
            if block.block_type == BlockType.WHILE:
                has_while = True
            for c in block.children:
                _check_children(c)
        if sp.root_block:
            _check_children(sp.root_block)
        assert has_while, "Should contain a WHILE block"

    def test_generate_switch_function(self):
        """switch 函数 — 应识别 switch/case/default"""
        sp = self.generator.generate(SWITCH_FUNC, with_types=True)

        assert sp.function_name == "get_status"
        # 控制流提示应包括 SWITCH
        assert any("SWITCH" in h for h in sp.control_flow_hints), \
            f"Expected SWITCH hint, got: {sp.control_flow_hints}"

    def test_generate_nested_function(self):
        """嵌套控制流 — 应正确构建嵌套块树"""
        sp = self.generator.generate(NESTED_FUNC, with_types=True)

        assert sp.function_name == "complex_logic"
        assert sp.root_block is not None
        # 应有深层嵌套结构
        assert len(sp.root_block.children) >= 1
        # DEEP_NESTING 提示
        assert any("NEST" in h for h in sp.control_flow_hints), \
            f"Expected nesting hint, got: {sp.control_flow_hints}"

    def test_generate_goto_function(self):
        """有 goto 的函数 — 应标记 GOTO_PRESENT"""
        sp = self.generator.generate(GOTO_FUNC, with_types=True)

        assert sp.function_name == "spaghetti"
        assert any("GOTO" in h for h in sp.control_flow_hints), \
            f"Expected GOTO hint, got: {sp.control_flow_hints}"

    def test_generate_try_catch(self):
        """try/catch 函数 — 应识别异常处理块"""
        sp = self.generator.generate(TRY_CATCH_FUNC, with_types=True)

        assert sp.function_name == "safe_divide"
        # 检查 try/catch 子块
        has_try = False
        def _check_try(block):
            nonlocal has_try
            if block.block_type == BlockType.TRY:
                has_try = True
            for c in block.children:
                _check_try(c)
        if sp.root_block:
            _check_try(sp.root_block)
        assert has_try, "Should contain a TRY block"

    def test_generate_empty_function(self):
        """空函数 — 不应崩溃"""
        sp = self.generator.generate(EMPTY_FUNC, with_types=True)
        assert sp.function_name == "noop"
        assert sp.root_block is not None

    def test_generate_badly_formatted(self):
        """劣质伪代码 — 应能优雅降级，且产生 warning"""
        sp = self.generator.generate(BADLY_FORMATTED, with_types=True)
        # 不应崩溃
        assert sp is not None
        # 应有 warning 或 hint 标记 goto
        has_issue = sp.warnings or any(
            "GOTO" in h for h in sp.control_flow_hints
        )
        assert has_issue, "Bad code should produce warnings or goto hints"

    def test_variable_extraction(self):
        """变量提取 — 类型、名称、引用计数"""
        sp = self.generator.generate(SIMPLE_FUNC, with_types=True)

        assert "result" in sp.variables
        var = sp.variables["result"]
        assert var.type_hint == "int"
        assert var.is_local is True
        assert var.references >= 1  # 至少被引用一次（除了声明）

    def test_parameter_info(self):
        """函数参数应被正确标记"""
        sp = self.generator.generate(SIMPLE_FUNC, with_types=True)

        param_names = [p.name for p in sp.parameters]
        assert "a" in param_names
        assert "b" in param_names
        for p in sp.parameters:
            assert p.is_parameter is True


class TestOutputFormats:
    """输出格式测试"""

    @classmethod
    def setup_class(cls):
        cls.generator = StructuredPseudocodeGenerator()

    def test_format_plain(self):
        """plain text 输出 — 应有缩进和函数签名"""
        sp = self.generator.generate(SIMPLE_FUNC)
        output = self.generator.format_output(sp, OutputFormat.PLAIN)

        assert "int max(int a, int b)" in output or "int max(" in output
        assert "return result" in output or "return" in output

    def test_format_markdown(self):
        """markdown 输出 — 应有 markdown 语法元素"""
        sp = self.generator.generate(SIMPLE_FUNC)
        output = self.generator.format_output(sp, OutputFormat.MARKDOWN)

        assert "# Structured Pseudocode" in output
        assert "```" in output
        assert "Variable Table" in output or "max" in output

    def test_format_html(self):
        """HTML 输出 — 应有 HTML 标签和 CSS"""
        sp = self.generator.generate(SIMPLE_FUNC)
        output = self.generator.format_output(sp, OutputFormat.HTML)

        assert "<!DOCTYPE html>" in output
        assert "<style>" in output
        assert '<span class="kw">' in output

    def test_format_plain_loop(self):
        """loop 函数的纯文本输出应有 for 关键字"""
        sp = self.generator.generate(LOOP_FUNC)
        output = self.generator.format_output(sp, OutputFormat.PLAIN)
        assert "for" in output.lower()


class TestConvenienceFunctions:
    """便捷函数测试"""

    def test_generate_structured_pseudocode(self):
        """一站式函数 — generate_structured_pseudocode"""
        sp = generate_structured_pseudocode(SIMPLE_FUNC, "max")
        assert isinstance(sp, StructuredPseudocode)
        assert sp.function_name == "max"

    def test_format_structured_output_markdown(self):
        """格式化函数 — format_structured_output markdown"""
        sp = generate_structured_pseudocode(SIMPLE_FUNC, "max")
        md = format_structured_output(sp, "markdown")
        assert "# Structured Pseudocode" in md

    def test_format_structured_output_html(self):
        """格式化函数 — format_structured_output html"""
        sp = generate_structured_pseudocode(SIMPLE_FUNC, "max")
        html_out = format_structured_output(sp, "html")
        assert "<!DOCTYPE html>" in html_out

    def test_format_structured_output_plain(self):
        """格式化函数 — format_structured_output plain"""
        sp = generate_structured_pseudocode(SIMPLE_FUNC, "max")
        plain = format_structured_output(sp, "plain")
        assert "int max" in plain or "max(" in plain


class TestObfuscationDetection:
    """混淆代码检测测试"""

    @classmethod
    def setup_class(cls):
        cls.generator = StructuredPseudocodeGenerator()

    def test_opaque_predicate_detection(self):
        """不透明谓词: if (x ^ y == z) 模式"""
        code = """\
void test() {
    int a;
    a = 0;
    if (a ^ 0xDEAD == 0xBEEF) {
        a = 1;
    }
    return;
}"""
        sp = self.generator.generate(code)
        assert any("OPAQUE" in w or "opaque" in w.lower() or "不透明" in w
                   for w in sp.warnings), \
            f"Expected opaque predicate warning, got: {sp.warnings}"

    def test_dead_code_detection(self):
        """死代码: if (1==0)"""
        code = """\
void dead() {
    int x;
    if (1 == 0) {
        x = 999;
    }
    return;
}"""
        sp = self.generator.generate(code)
        assert any("DEAD" in w or "dead" in w.lower() or "死代码" in w
                   for w in sp.warnings), \
            f"Expected dead code warning, got: {sp.warnings}"

    def test_no_false_positive_on_clean_code(self):
        """干净代码不应产生警告"""
        sp = self.generator.generate(SIMPLE_FUNC)
        assert len(sp.warnings) == 0, \
            f"Clean code should have no warnings, got: {sp.warnings}"


class TestJSONSerialization:
    """JSON 序列化测试"""

    def test_to_json(self):
        gen = StructuredPseudocodeGenerator()
        sp = gen.generate(SIMPLE_FUNC, with_types=True)
        json_str = gen.to_json(sp)

        assert json_str is not None
        data = json.loads(json_str)
        assert data['function_name'] == 'max'
        assert data['return_type'] == 'int'
        assert len(data['parameters']) == 2
        assert 'result' in data['variables']
        assert data['root_block'] is not None
        assert 'control_flow_hints' in data


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
