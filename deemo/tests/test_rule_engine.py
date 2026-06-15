import os
import sys
import unittest
import tempfile
import shutil
import json

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.rule_engine import RuleEngine, RuleCondition, RuleAction, VulnerabilityRule


class TestRuleEngine(unittest.TestCase):
    """规则引擎单元测试"""
    
    def setUp(self):
        """设置测试环境"""
        self.temp_dir = tempfile.mkdtemp()
        self.engine = RuleEngine(rules_dir=self.temp_dir)
    
    def tearDown(self):
        """清理测试环境"""
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)
    
    def test_rule_condition_matches(self):
        """测试规则条件匹配"""
        condition = RuleCondition(
            field='function_name',
            operator='contains',
            value='strcpy'
        )
        
        data = {'function_name': 'strcpy_wrapper'}
        self.assertTrue(condition.matches(data))
        
        data = {'function_name': 'memcpy'}
        self.assertFalse(condition.matches(data))
    
    def test_rule_condition_regex(self):
        """测试正则表达式匹配"""
        condition = RuleCondition(
            field='pseudocode',
            operator='equals',
            value=r'\bgets\s*\(',
            regex=True
        )
        
        data = {'pseudocode': 'int foo() { gets(buffer); }'}
        self.assertTrue(condition.matches(data))
        
        data = {'pseudocode': 'int foo() { fgets(buffer, 100, stdin); }'}
        self.assertFalse(condition.matches(data))
    
    def test_rule_condition_numeric(self):
        """测试数值比较"""
        condition = RuleCondition(
            field='buffer_size',
            operator='greater_than',
            value=100
        )
        
        data = {'buffer_size': 200}
        self.assertTrue(condition.matches(data))
        
        data = {'buffer_size': 50}
        self.assertFalse(condition.matches(data))
    
    def test_rule_action_execute(self):
        """测试规则动作执行"""
        action = RuleAction(
            action_type='report_vulnerability',
            parameters={
                'vulnerability_type': 'Buffer Overflow',
                'severity': 'High',
                'description': 'Potential buffer overflow detected'
            }
        )
        
        data = {'function_name': 'unsafe_function'}
        result = action.execute(data)
        
        self.assertIsNotNone(result)
        self.assertEqual(result['action_type'], 'report_vulnerability')
        self.assertEqual(result['parameters']['vulnerability_type'], 'Buffer Overflow')
    
    def test_vulnerability_rule_matches(self):
        """测试漏洞规则匹配"""
        rule_data = {
            'id': 'CWE-121-001',
            'name': 'Stack Buffer Overflow',
            'severity': 'High',
            'cwe_id': 'CWE-121',
            'conditions': [
                {'field': 'function_name', 'operator': 'contains', 'value': 'strcpy'},
                {'field': 'pseudocode', 'operator': 'contains', 'value': 'unsafe'}
            ],
            'actions': [
                {'type': 'report_vulnerability', 'parameters': {'vulnerability_type': 'Buffer Overflow', 'severity': 'High'}}
            ]
        }
        
        rule = VulnerabilityRule(rule_data)
        
        data = {'function_name': 'strcpy_wrapper', 'pseudocode': 'unsafe operation'}
        self.assertTrue(rule.matches(data))
        
        data = {'function_name': 'safe_copy', 'pseudocode': 'safe operation'}
        self.assertFalse(rule.matches(data))
    
    def test_vulnerability_rule_execute(self):
        """测试漏洞规则执行"""
        rule_data = {
            'id': 'TEST-001',
            'name': 'Test Rule',
            'severity': 'Critical',
            'cwe_id': 'CWE-416',
            'conditions': [
                {'field': 'function_name', 'operator': 'equals', 'value': 'dangerous_func'}
            ],
            'actions': [
                {'type': 'report_vulnerability', 'parameters': {'vulnerability_type': 'Use After Free', 'severity': 'Critical'}}
            ]
        }
        
        rule = VulnerabilityRule(rule_data)
        
        data = {'function_name': 'dangerous_func', 'pseudocode': 'some code'}
        results = rule.execute(data)
        
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]['rule_id'], 'TEST-001')
        self.assertEqual(results[0]['parameters']['vulnerability_type'], 'Use After Free')
    
    def test_rule_engine_evaluate(self):
        """测试规则引擎评估"""
        rule_data1 = {
            'id': 'RULE-001',
            'name': 'Dangerous Function Detection',
            'severity': 'High',
            'cwe_id': 'CWE-787',
            'conditions': [
                {'field': 'function_name', 'operator': 'contains', 'value': 'strcpy'}
            ],
            'actions': [
                {'type': 'report_vulnerability', 'parameters': {'vulnerability_type': 'Buffer Overflow', 'severity': 'High'}}
            ]
        }
        
        rule_file = os.path.join(self.temp_dir, 'rule1.json')
        with open(rule_file, 'w') as f:
            json.dump(rule_data1, f)
        
        engine = RuleEngine(rules_dir=self.temp_dir)
        engine.load_rules()
        
        data = {'function_name': 'strcpy_call', 'pseudocode': 'strcpy(dst, src);'}
        results = engine.evaluate(data)
        
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]['parameters']['vulnerability_type'], 'Buffer Overflow')
    
    def test_load_rules_from_directory(self):
        """测试从目录加载规则"""
        rule_data = {
            'id': 'TEST-RULE-001',
            'name': 'Test Rule',
            'severity': 'High',
            'cwe_id': 'CWE-121',
            'description': 'Test rule for loading',
            'enabled': True,
            'target_languages': ['c/c++'],
            'conditions': [
                {'field': 'function_name', 'operator': 'contains', 'value': 'test_func'}
            ],
            'actions': [
                {'type': 'report_vulnerability', 'parameters': {'vulnerability_type': 'Test Vulnerability', 'severity': 'High'}}
            ]
        }
        
        rule_file = os.path.join(self.temp_dir, 'test_rule.json')
        with open(rule_file, 'w') as f:
            json.dump(rule_data, f)
        
        engine = RuleEngine(rules_dir=self.temp_dir)
        engine.load_rules()
        
        self.assertEqual(len(engine.enabled_rules), 1)
        self.assertEqual(engine.enabled_rules[0].id, 'TEST-RULE-001')
    
    def test_rule_disable(self):
        """测试禁用规则"""
        rule_data = {
            'id': 'DISABLE-TEST',
            'name': 'Disable Test',
            'severity': 'Medium',
            'cwe_id': 'CWE-000',
            'enabled': False,
            'conditions': [
                {'field': 'test', 'operator': 'equals', 'value': 'value'}
            ],
            'actions': [
                {'type': 'report_vulnerability', 'parameters': {'vulnerability_type': 'Test'}}
            ]
        }
        
        rule_file = os.path.join(self.temp_dir, 'disabled_rule.json')
        with open(rule_file, 'w') as f:
            json.dump(rule_data, f)
        
        engine = RuleEngine(rules_dir=self.temp_dir)
        engine.load_rules()
        
        self.assertEqual(len(engine.enabled_rules), 0)


if __name__ == '__main__':
    unittest.main()