"""核心逻辑测试。

覆盖：RuleEngine、VulnerabilityRule 匹配、规则导入导出、
RuleCondition 操作符、dot-notation 字段访问。
"""

import sys, os, json, pytest, tempfile

_cur = os.path.dirname(os.path.abspath(__file__))
_patch = os.path.dirname(_cur)
if _patch not in sys.path:
    sys.path.insert(0, _patch)

from rule_engine import (
    RuleEngine, Rule, RuleCondition, RuleAction, VulnerabilityRule,
    OPERATORS,
)


class TestRuleCondition:
    """RuleCondition —— 各操作符下的字段匹配。"""

    def test_equals_match(self):
        cond = RuleCondition(field="type", operator="equals", value="overflow")
        assert cond.matches({"type": "overflow"}) is True

    def test_equals_no_match(self):
        cond = RuleCondition(field="type", operator="equals", value="overflow")
        assert cond.matches({"type": "use-after-free"}) is False

    def test_contains_list(self):
        cond = RuleCondition(field="functions", operator="contains", value="strcpy")
        assert cond.matches({"functions": ["strcpy", "gets", "printf"]}) is True

    def test_contains_string(self):
        cond = RuleCondition(field="description", operator="contains", value="overflow")
        assert cond.matches({"description": "buffer overflow detected"}) is True

    def test_contains_not_found(self):
        cond = RuleCondition(field="functions", operator="contains", value="malloc")
        assert cond.matches({"functions": ["strcpy"]}) is False

    def test_not_contains(self):
        cond = RuleCondition(field="functions", operator="not_contains", value="gets")
        assert cond.matches({"functions": ["strcpy", "printf"]}) is True

    def test_starts_with(self):
        cond = RuleCondition(field="path", operator="starts_with", value="/usr/bin")
        assert cond.matches({"path": "/usr/bin/python"}) is True
        assert cond.matches({"path": "/opt/bin/python"}) is False

    def test_ends_with(self):
        cond = RuleCondition(field="path", operator="ends_with", value=".exe")
        assert cond.matches({"path": "test.exe"}) is True

    def test_exists(self):
        cond = RuleCondition(field="vulnerability", operator="exists")
        assert cond.matches({"vulnerability": "yes"}) is True
        assert cond.matches({}) is False

    def test_not_exists(self):
        cond = RuleCondition(field="vulnerability", operator="not_exists")
        assert cond.matches({}) is True
        assert cond.matches({"vulnerability": "yes"}) is False

    def test_regex_match(self):
        cond = RuleCondition(field="name", operator="regex", value=r"^CWE-\d+", regex=True)
        assert cond.matches({"name": "CWE-121"}) is True
        assert cond.matches({"name": "OTHER"}) is False

    def test_none_data(self):
        cond = RuleCondition(field="key", operator="equals", value="x")
        assert cond.matches(None) is False


class TestRuleAction:
    """RuleAction —— 报告/标签/严重度执行。"""

    def test_report_vulnerability(self):
        action = RuleAction(action_type="report_vulnerability",
                            parameters={"vulnerability_type": "Stack Overflow",
                                        "severity": "Critical"})
        result = action.execute({"file": "test.bin"})
        assert result['action_type'] == 'report_vulnerability'
        assert result['vulnerability_type'] == 'Stack Overflow'
        assert result['severity'] == 'Critical'

    def test_add_tag(self):
        action = RuleAction(action_type="add_tag",
                            parameters={"tag": "memory-safety"})
        result = action.execute({})
        assert result['tag'] == 'memory-safety'

    def test_set_severity(self):
        action = RuleAction(action_type="set_severity",
                            parameters={"severity": "High"})
        result = action.execute({})
        assert result['severity'] == 'High'


class TestVulnerabilityRule:
    """VulnerabilityRule —— from_dict、语言过滤、执行。"""

    def test_from_dict(self):
        data = {
            "id": "CWE-121",
            "name": "Stack Buffer Overflow",
            "enabled": True,
            "conditions": [{"field": "funcs", "operator": "contains", "value": "gets"}],
            "actions": [{"type": "report_vulnerability",
                         "parameters": {"vulnerability_type": "Stack Overflow", "severity": "Critical"}}],
        }
        rule = VulnerabilityRule.from_dict(data)
        assert rule.id == "CWE-121"
        assert len(rule.conditions) == 1
        assert len(rule.actions) == 1
        assert rule.enabled is True

    def test_disabled_rule_does_not_match(self):
        data = {
            "id": "DISABLED-RULE",
            "enabled": False,
            "conditions": [{"field": "funcs", "operator": "equals", "value": "x"}],
            "actions": [],
        }
        rule = VulnerabilityRule.from_dict(data)
        assert rule.matches({"funcs": "x"}) is False

    def test_language_filtering(self):
        data = {
            "id": "RUST-ONLY",
            "enabled": True,
            "target_languages": ["rust"],
            "conditions": [{"field": "funcs", "operator": "exists"}],
            "actions": [],
        }
        rule = VulnerabilityRule.from_dict(data)
        # c/c++ 二进制不应匹配
        assert rule.matches({"funcs": "main"}, {"language": "c/c++"}) is False
        # rust 二进制应匹配
        assert rule.matches({"funcs": "main"}, {"language": "rust"}) is True

    def test_format_filtering(self):
        data = {
            "id": "ELF-ONLY",
            "enabled": True,
            "target_formats": ["ELF"],
            "conditions": [{"field": "funcs", "operator": "exists"}],
            "actions": [],
        }
        rule = VulnerabilityRule.from_dict(data)
        assert rule.matches({"funcs": "main"}, {"format": "PE"}) is False
        assert rule.matches({"funcs": "main"}, {"format": "ELF"}) is True

    def test_execution(self):
        data = {
            "id": "CWE-134",
            "name": "Format String",
            "conditions": [{"field": "imports", "operator": "contains", "value": "printf"}],
            "actions": [
                {"type": "report_vulnerability",
                 "parameters": {"vulnerability_type": "Format String", "severity": "High"}},
                {"type": "add_tag", "parameters": {"tag": "format-string"}},
            ],
        }
        rule = VulnerabilityRule.from_dict(data)
        results = rule.execute({"imports": ["printf", "strcpy"]})
        assert len(results) == 2
        assert results[0]['rule_id'] == 'CWE-134'
        assert results[1]['tag'] == 'format-string'


class TestRuleEngine:
    """RuleEngine —— 加载、匹配、优先级排序。"""

    def test_add_and_match(self):
        engine = RuleEngine()
        rule = Rule(
            name="test_overflows",
            conditions=[{"field": "has_overflow", "operator": "equals", "value": True}],
            priority=10,
        )
        engine.add_rule(rule)
        results = engine.evaluate({"has_overflow": True})
        assert "test_overflows" in results

    def test_no_match(self):
        engine = RuleEngine()
        rule = Rule(name="test", conditions=[
            {"field": "exists", "operator": "exists"},
        ])
        engine.add_rule(rule)
        results = engine.evaluate({"different_field": "yes"})
        assert len(results) == 0

    def test_evaluate_first(self):
        engine = RuleEngine()
        engine.add_rule(Rule(name="high_prio", priority=100,
            conditions=[{"field": "vuln", "operator": "exists"}]))
        engine.add_rule(Rule(name="low_prio", priority=10,
            conditions=[{"field": "vuln", "operator": "exists"}]))
        # 按优先级降序
        first = engine.evaluate_first({"vuln": "yes"})
        assert first == "high_prio"

    def test_disabled_rule_skipped(self):
        engine = RuleEngine()
        r = Rule(name="disabled_test", enabled=False,
                 conditions=[{"field": "x", "operator": "equals", "value": 1}])
        engine.add_rule(r)
        results = engine.evaluate({"x": 1})
        assert len(results) == 0

    def test_remove_rule(self):
        engine = RuleEngine()
        engine.add_rule(Rule(name="to_remove", conditions=[]))
        assert engine.remove_rule("to_remove") is True
        assert engine.remove_rule("nonexistent") is False

    def test_clear(self):
        engine = RuleEngine()
        engine.add_rule(Rule(name="r1", conditions=[]))
        engine.add_rule(Rule(name="r2", conditions=[]))
        engine.clear()
        assert engine.evaluate({"x": 1}) == []

    def test_multiple_conditions_and(self):
        """所有条件必须同时满足（AND 逻辑）。"""
        engine = RuleEngine()
        rule = Rule(name="both", conditions=[
            {"field": "a", "operator": "equals", "value": 1},
            {"field": "b", "operator": "equals", "value": 2},
        ])
        engine.add_rule(rule)
        assert engine.evaluate({"a": 1, "b": 2}) == ["both"]
        assert engine.evaluate({"a": 1, "b": 3}) == []  # b 不匹配

    def test_export_import_roundtrip(self):
        engine = RuleEngine()
        engine.add_rule(Rule(name="r1", conditions=[
            {"field": "f", "operator": "equals", "value": 1}
        ]))
        engine.add_rule(Rule(name="r2", conditions=[
            {"field": "f", "operator": "equals", "value": 2}
        ]))
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            tmp = f.name
        try:
            engine.export_rules(tmp)
            engine2 = RuleEngine()
            engine2.import_rules(tmp)
            assert len(engine2._rules) == 2
            names = [r.name for r in engine2._rules]
            assert "r1" in names
            assert "r2" in names
        finally:
            os.unlink(tmp)

    def test_import_from_builtin(self):
        """导入内置规则 JSON 并验证加载成功。"""
        rules_path = os.path.join(_patch, 'config', 'rules', 'builtin.json')
        if not os.path.isfile(rules_path):
            pytest.skip("builtin.json not found")
        engine = RuleEngine()
        engine.import_rules(rules_path)
        # 应至少有 CWE-121、CWE-122、CWE-134
        assert len(engine._rules) >= 3


class TestOperatorsTable:
    """验证 OPERATORS 查表正确性。"""

    def test_all_operators_present(self):
        for op in ('equals', 'not_equals', 'contains', 'not_contains',
                   'starts_with', 'ends_with', 'regex', 'exists', 'not_exists'):
            assert op in OPERATORS

    def test_equals_operator(self):
        assert OPERATORS['equals'](1, 1) is True
        assert OPERATORS['equals'](1, 2) is False

    def test_contains_str(self):
        assert OPERATORS['contains']("hello world", "world") is True

    def test_regex_operator(self):
        import re
        assert OPERATORS['regex']("abc123", r'\d+') is True
        assert OPERATORS['regex']("abcdef", r'\d+') is False


class TestModuleImports:
    """基础导入测试 —— 验证懒加载机制正常。"""

    def test_can_import_auto_root_cause(self):
        from auto_root_cause import AutoRootCauseAnalyzer
        a = AutoRootCauseAnalyzer()
        assert a is not None

    def test_can_import_rule_engine(self):
        from rule_engine import RuleEngine
        e = RuleEngine()
        assert isinstance(e, RuleEngine)

    def test_can_import_patch_quality(self):
        from patch_quality_evaluator import PatchQualityEvaluator
        e = PatchQualityEvaluator()
        assert e is not None

    def test_can_import_auto_patcher(self):
        from auto_patcher import AutoPatcher  # noqa
        # 仅验证导入不抛异常

    def test_can_import_reliability_predictor(self):
        from reliability_predictor import ReliabilityPredictor  # noqa

    def test_can_import_recompiler_check(self):
        from recompiler_check import RecompilerVerifier  # noqa

    def test_can_import_patch_suggestion(self):
        from patch_suggestion import PatchSuggester  # noqa
