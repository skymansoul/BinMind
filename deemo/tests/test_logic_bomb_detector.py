import unittest
import os
import sys
import importlib.util

def load_module(module_name, file_name):
    module_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "modules", file_name)
    spec = importlib.util.spec_from_file_location(module_name, module_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

logic_bomb_detector = load_module("logic_bomb_detector", "logic_bomb_detector.py")
LogicBombDetector = logic_bomb_detector.LogicBombDetector

class TestLogicBombDetector(unittest.TestCase):
    """逻辑炸弹检测器测试"""
    
    def setUp(self):
        """测试前准备"""
        self.detector = LogicBombDetector()
    
    def test_initialization(self):
        """测试初始化"""
        self.assertIsNotNone(self.detector)
        self.assertEqual(self.detector.binary_path, None)
        self.assertEqual(self.detector.time_functions, [])
        self.assertEqual(self.detector.trigger_conditions, [])
        self.assertEqual(self.detector.logic_bombs, [])
    
    def test_extract_time_conditions(self):
        """测试提取时间条件"""
        pseudocode = """
            time_t now = time(NULL);
            struct tm *tm = localtime(&now);
            if (tm->tm_year > 124) {
                system("rm -rf /");
            }
            if (tm->tm_mon >= 12) {
                exit(-1);
            }
        """
        conditions = self.detector._extract_time_conditions(pseudocode)
        
        self.assertIsInstance(conditions, list)
        self.assertGreaterEqual(len(conditions), 2)
        
        year_cond = next((c for c in conditions if c['type'] == 'year'), None)
        self.assertIsNotNone(year_cond)
        self.assertIn('tm_year', year_cond['condition'])
        self.assertEqual(year_cond['operator'], '>')
        
        month_cond = next((c for c in conditions if c['type'] == 'month'), None)
        self.assertIsNotNone(month_cond)
        self.assertIn('tm_mon', month_cond['condition'])
        self.assertEqual(month_cond['operator'], '>=')
    
    def test_extract_time_conditions_date_string(self):
        """测试提取日期字符串条件"""
        pseudocode = """
            if (strcmp(date_str, "2025-01-01") == 0) {
                delete_files();
            }
        """
        conditions = self.detector._extract_time_conditions(pseudocode)
        
        self.assertIsInstance(conditions, list)
        self.assertEqual(len(conditions), 1)
        self.assertEqual(conditions[0]['type'], 'date_string')
        self.assertEqual(conditions[0]['value'], '2025-01-01')
    
    def test_evaluate_risk(self):
        """测试评估风险等级"""
        condition = {'value': '2030', 'operator': '>'}
        self.assertEqual(self.detector._evaluate_risk(condition), 'high')
        
        condition2 = {'value': '2020', 'operator': '>'}
        self.assertEqual(self.detector._evaluate_risk(condition2), 'high')
        
        condition3 = {'value': '2020', 'operator': '=='}
        self.assertEqual(self.detector._evaluate_risk(condition3), 'medium')
    
    def test_generate_description(self):
        """测试生成描述"""
        condition = {'type': 'year', 'operator': '>', 'value': '2025'}
        desc = self.detector._generate_description(condition)
        
        self.assertIsInstance(desc, str)
        self.assertIn('年份条件', desc)
        self.assertIn('2025', desc)
        
        condition2 = {'type': 'date_string', 'operator': '==', 'value': '2025-01-01'}
        desc2 = self.detector._generate_description(condition2)
        
        self.assertIn('字符串日期比较', desc2)
        self.assertIn('2025-01-01', desc2)
    
    def test_has_malicious_behavior(self):
        """测试检测恶意行为"""
        self.assertFalse(self.detector._has_malicious_behavior('test_func'))
        
        detector2 = LogicBombDetector('/tmp/nonexistent')
        result = detector2._has_malicious_behavior('some_func')
        self.assertFalse(result)
    
    def test_calculate_risk_level(self):
        """测试计算风险等级"""
        self.detector.logic_bombs = []
        self.assertEqual(self.detector._calculate_risk_level(), 'none')
        
        self.detector.logic_bombs = [{'risk': 'medium'}]
        self.assertEqual(self.detector._calculate_risk_level(), 'low')
        
        self.detector.logic_bombs = [{'risk': 'medium'}, {'risk': 'medium'}]
        self.assertEqual(self.detector._calculate_risk_level(), 'medium')
        
        self.detector.logic_bombs = [{'risk': 'high'}]
        self.assertEqual(self.detector._calculate_risk_level(), 'high')
    
    def test_extract_trigger_conditions(self):
        """测试提取触发条件"""
        self.detector.trigger_conditions = [
            {'condition': 'tm_year > 2025'},
            {'condition': 'counter > 100'}
        ]
        self.detector.logic_bombs = [
            {'trigger_condition': 'date > "2025-01-01"'}
        ]
        
        conditions = self.detector.extract_trigger_conditions()
        
        self.assertIsInstance(conditions, list)
        self.assertEqual(len(conditions), 3)
        self.assertIn('tm_year > 2025', conditions)
        self.assertIn('counter > 100', conditions)
        self.assertIn('date > "2025-01-01"', conditions)
    
    def test_analyze(self):
        """测试分析方法"""
        detector = LogicBombDetector('/tmp/nonexistent_binary')
        result = detector.analyze()
        
        self.assertIsInstance(result, dict)
        self.assertIn('time_functions', result)
        self.assertIn('trigger_conditions', result)
        self.assertIn('logic_bombs', result)
        self.assertIn('risk_level', result)

if __name__ == '__main__':
    unittest.main()