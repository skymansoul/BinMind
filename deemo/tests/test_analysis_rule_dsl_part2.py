
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



class TestRuleEngine:
    """规则引擎测试"""

    def test_evaluate(self):
                """测试规则评估"""
        yaml_content = """
rules:
  - id: vuln_type
    name: Vuln Type
    severity: HIGH
    category: test
    conditions:
      - field: vuln_type
        operator: "=="
        value: buffer_overflow
"""
        parser = RuleParser()
        parser.parse_yaml(yaml_content)

        engine = RuleEngine(parser)

        matches = engine.evaluate({
            'vuln_type': 'buffer_overflow',
            'location': 'main.c:100'
        })

        assert len(matches) == 1
        assert matches[0].rule_id == "vuln_type"
        assert matches[0].severity == "HIGH"

    def test_evaluate_batch(self):
        """测试批量评估"""
        yaml_content = """
rules:
  - id: check_type
    name: Check Type
    severity: MEDIUM
    category: test
    conditions:
      - field: type
        operator: "=="
        value: overflow
"""
        parser = RuleParser()
        parser.parse_yaml(yaml_content)

        engine = RuleEngine(parser)

        contexts = [
            {'type': 'overflow', 'data': 'a'},
            {'type': 'injection', 'data': 'b'},
            {'type': 'overflow', 'data': 'c'}
        ]

        matches = engine.evaluate_batch(contexts)

lass字段完整性$/d
        assert len(matches) == 2  # 两个匹配

    def test_callback(self):
        """测试回调"""
        yaml_content = """
rules:
  - id: test_callback
    name: Callback Test
    severity: LOW
    category: test
    pattern: "test"
"""
        parser = RuleParser()
        parser.parse_yaml(yaml_content)

        engine = RuleEngine(parser)

        callback_results = []
        def callback(match):
            callback_results.append(match.rule_id)

        engine.register_match_callback(callback)

        engine.evaluate({'target': 'this is a test'})

        assert len(callback_results) == 1


class TestAnalysisPipeline:
    """分析管道测试"""

    def test_pipeline_creation(self):
        """测试管道创建"""
        pipeline = AnalysisPipeline()

        assert pipeline.rule_parser is not None
        assert pipeline.rule_engine is not None
        assert pipeline.executor is not None

    def test_load_builtin_rules(self):
        """测试加载内置规则"""
        pipeline = AnalysisPipeline()

        count = pipeline.load_rules_yaml(BUFFER_OVERFLOW_RULES)

        assert count > 0

    def test_evaluate_rules_directly(self):
        """测试直接评估规则"""
        pipeline = AnalysisPipeline()
        pipeline.load_rules_yaml(BUFFER_OVERFLOW_RULES)

        context = {
            'target': 'strcpy(buffer, input)',
            'type': 'buffer_overflow',
            'location': 'main.c:100'
        }

        matches = pipeline.evaluate_rules(context)

        assert isinstance(matches, list)

    def test_register_match_callback(self):
        pipeline = AnalysisPipeline()
        pipeline.load_rules_yaml(BUFFER_OVERFLOW_RULES)

        results = []
        def handler(match):
            results.append(match)

        pipeline.register_match_callback(handler)

        pipeline.evaluate_rules({'target': 'gets(input)'})

        assert len(results) > 0


class TestRuleMatch:
    """规则匹配测试"""

    def test_match_creation(self):
        """测试匹配创建"""
        match = RuleMatch(
            rule_id="test_1",
            rule_name="Test Match",
            severity="HIGH",
            matched_value="test_data",
            context={'key': 'value'},
            confidence=0.95,
            location="main.c:50"
        )

lass字段完整性$/d
        assert match.rule_id == "test_1"
        assert match.severity == "HIGH"
        assert match.confidence == 0.95
