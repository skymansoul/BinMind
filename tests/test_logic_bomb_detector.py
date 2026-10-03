# -*- coding: utf-8 -*-

import unittest
import os
import sys
import importlib.util


def _load_module(module_name, file_name):
    module_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "modules", "malware", file_name,
    )
    spec = importlib.util.spec_from_file_location(module_name, module_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


logic_bomb_detector = _load_module("logic_bomb_detector", "logic_bomb_detector.py")
LogicBombDetector = logic_bomb_detector.LogicBombDetector


class TestLogicBombDetector(unittest.TestCase):

    def setUp(self):
        self.detector = LogicBombDetector()

    def test_init(self):
        self.assertIsNotNone(self.detector)
        self.assertIsNone(self.detector.binary_path)
        self.assertEqual(self.detector.time_functions, [])
        self.assertEqual(self.detector.trigger_conditions, [])
        self.assertEqual(self.detector.logic_bombs, [])

    def test_extract_time_conditions(self):
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

    def test_extract_date_string_condition(self):
        pseudocode = """
            if (strcmp(date_str, "2026-06-01") == 0) {
                delete_files();
            }
        """
        conditions = self.detector._extract_time_conditions(pseudocode)
        self.assertEqual(len(conditions), 1)
        self.assertEqual(conditions[0]['type'], 'date_string')
        self.assertEqual(conditions[0]['value'], '2026-06-01')

    def test_evaluate_risk(self):
        self.assertEqual(
            self.detector._evaluate_risk({'value': '2030', 'operator': '>'}), 'high'
        )
        self.assertEqual(
            self.detector._evaluate_risk({'value': '2020', 'operator': '>'}), 'high'
        )
        self.assertEqual(
            self.detector._evaluate_risk({'value': '2020', 'operator': '=='}), 'medium'
        )

    def test_generate_description(self):
        cond = {'type': 'year', 'operator': '>', 'value': '2025'}
        desc = self.detector._generate_description(cond)
        self.assertIsInstance(desc, str)
        self.assertIn('Year gate', desc)
        self.assertIn('2025', desc)

        cond2 = {'type': 'date_string', 'operator': '==', 'value': '2026-06-01'}
        desc2 = self.detector._generate_description(cond2)
        self.assertIn('String date comparison', desc2)
        self.assertIn('2026-06-01', desc2)

    def test_has_malicious_behavior(self):
        self.assertFalse(self.detector._has_malicious_behavior('test_func'))

        detector2 = LogicBombDetector('/tmp/nonexistent')
        self.assertFalse(detector2._has_malicious_behavior('some_func'))

    def test_calculate_risk_level(self):
        self.detector.logic_bombs = []
        self.assertEqual(self.detector._calculate_risk_level(), 'none')

        self.detector.logic_bombs = [{'risk': 'medium'}]
        self.assertEqual(self.detector._calculate_risk_level(), 'low')

        self.detector.logic_bombs = [{'risk': 'medium'}, {'risk': 'medium'}]
        self.assertEqual(self.detector._calculate_risk_level(), 'medium')

        self.detector.logic_bombs = [{'risk': 'high'}]
        self.assertEqual(self.detector._calculate_risk_level(), 'high')

    def test_extract_trigger_conditions(self):
        self.detector.trigger_conditions = [
            {'condition': 'tm_year > 2025'},
            {'condition': 'counter > 100'},
        ]
        self.detector.logic_bombs = [
            {'trigger_condition': 'date > "2026-06-01"'}
        ]
        conditions = self.detector.extract_trigger_conditions()
        self.assertEqual(len(conditions), 3)
        self.assertIn('tm_year > 2025', conditions)
        self.assertIn('counter > 100', conditions)
        self.assertIn('date > "2026-06-01"', conditions)

    def test_analyze(self):
        detector = LogicBombDetector('/tmp/nonexistent_binary')
        result = detector.analyze()
        self.assertIsInstance(result, dict)
        self.assertIn('time_functions', result)
        self.assertIn('trigger_conditions', result)
        self.assertIn('logic_bombs', result)
        self.assertIn('risk_level', result)


if __name__ == '__main__':
    unittest.main()
