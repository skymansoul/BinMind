
import pytest
import yaml
_MOD_DEBUG = False
from modules.analysis_rule_dsl import (
    AnalysisPipeline,
    RuleParser,
    RuleEngine,
    PipelineExecutor,
    AnalysisRule,
    RuleCondition,
    RuleMatch,
    Severity,
    BUFFER_OVERFLOW_RULES
)


class TestAnalysisRule:
    """分析规则测试"""

    def test_rule_creation(self):
        """测试规则创建"""
        rule = AnalysisRule(
            rule_id="test_1",
            name="Test Rule",
            description="A test rule",
            severity="HIGH",
            category="test"
        )

        assert rule.rule_id == "test_1"
        assert rule.severity == "HIGH"
        assert rule.enabled is True

    def test_rule_evaluation_exact_match(self):
        """测试精确匹配"""
        rule = AnalysisRule(
            rule_id="exact_1",
            name="Exact Match",
            description="",
            severity="HIGH",
            category="test",
            conditions=[
                RuleCondition(field="type", operator="==", value="buffer_overflow")
            ]
        )

        context = {"type": "buffer_overflow"}
        assert rule.evaluate(context) is True

        context = {"type": "sql_injection"}
        assert rule.evaluate(context) is False

    def test_rule_evaluation_pattern(self):
        """测试模式匹配"""
        rule = AnalysisRule(
            rule_id="pattern_1",
            name="Pattern Match",
            description="",
            severity="HIGH",
            category="test",
            pattern="strcpy\\("
        )

        assert rule.evaluate({"target": "strcpy(dest, src)"}) is True
        assert rule.evaluate({"target": "printf(form)"}) is False

    def test_rule_evaluation_numeric(self):
        """测试数值比较"""
        rule = AnalysisRule(
            rule_id="numeric_1",
            name="Numeric Compare",
            description="",
            severity="MEDIUM",
            category="test",
            conditions=[
                RuleCondition(field="size", operator=">", value=100)
            ]
        )

        assert rule.evaluate({"size": 150}) is True
        assert rule.evaluate({"size": 50}) is False

    def test_rule_disabled(self):
        """测试禁用规则"""
        rule = AnalysisRule(
            rule_id="disabled_1",
            name="Disabled",
            description="",
            severity="HIGH",
            category="test",
            enabled=False
        )

        assert rule.evaluate({"type": "anything"}) is False


class TestRuleParser:
    """规则解析器测试"""

    def test_parse_yaml(self):
        """测试 YAML 解析"""
        yaml_content = """
rules:
  - id: rule_1
    name: Test Rule
    description: A test
    severity: HIGH
    category: test
    conditions:
      - field: type
        operator: "=="
        value: buffer_overflow
"""
        parser = RuleParser()
        rules = parser.parse_yaml(yaml_content)

        assert len(rules) == 1
        assert rules[0].rule_id == "rule_1"
        assert len(rules[0].conditions) == 1

    def test_parse_json(self):
        """测试 JSON 解析"""
        json_content = """
{
    "rules": [
        {
            "id": "json_rule_1",
            "name": "JSON Rule",
            "severity": "CRITICAL",
            "category": "test"
        }
    ]
}
"""
        parser = RuleParser()
        rules = parser.parse_json(json_content)

        assert len(rules) == 1
        assert rules[0].rule_id == "json_rule_1"

    def test_get_rule(self):
        """测试获取规则"""
        parser = RuleParser()
        parser.parse_yaml(BUFFER_OVERFLOW_RULES)

        rule = parser.get_rule("strcpy_no_size")

        assert rule is not None
        assert rule.name == "不安全的字符串复制"

    def test_list_rules(self):
        """测试列出规则"""
        parser = RuleParser()
        parser.parse_yaml(BUFFER_OVERFLOW_RULES)

        all_rules = parser.list_rules()
        buffer_rules = parser.list_rules(category="buffer_overflow")

        assert len(all_rules) > 0
        assert all(r.category == "buffer_overflow" for r in buffer_rules)


