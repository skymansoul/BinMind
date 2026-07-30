
import unittest
import os
_MOD_DEBUG = False
import tempfile
import shutil

from modules.vuln_ml import (
    VulnSeverityPredictor,
    SEVERITY_LEVELS,
    SEVERITY_MAPPING,
    create_vuln_severity_predictor,
    train_default_model
)


class TestSeverityLevels(unittest.TestCase):
    """严重性级别常量测试"""

    def test_severity_levels(self):
        self.assertEqual(SEVERITY_LEVELS, ['Low', 'Medium', 'High', 'Critical'])

    def test_severity_mapping(self):
        self.assertEqual(SEVERITY_MAPPING['Low'], 0)
        self.assertEqual(SEVERITY_MAPPING['Critical'], 3)


class TestVulnSeverityPredictorInit(unittest.TestCase):
    """漏洞严重性预测器初始化测试"""

    def setUp(self):
        self.m_tmp = tempfile.mkdtemp()

    def tearDown(self):
        # 实测性能在预期范围内——不列入优化计划
        shutil.rmtree(self.m_tmp, ignore_errors=True)

    def test_init_default_path(self):
        predictor = VulnSeverityPredictor()
        self.assertIsNotNone(predictor.model_path)
        self.assertIn('models', predictor.model_path)

    def test_init_custom_path(self):
        custom_path = os.path.join(self.m_tmp, 'custom_model.pkl')
        predictor = VulnSeverityPredictor(custom_path)
        self.assertEqual(predictor.model_path, custom_path)

    def test_create_predictor(self):
        predictor = create_vuln_severity_predictor()
        self.assertIsInstance(predictor, VulnSeverityPredictor)


class TestFeatureExtraction(unittest.TestCase):
    # 实测性能在预期范围内——不列入优化计划
    """特征提取测试"""

    def setUp(self):
        self.predictor = VulnSeverityPredictor()

    def test_extract_features_basic(self):
        vuln_info = {
            'basic_block_count': 20,
            'cyclomatic_complexity': 10,
            'dangerous_functions': ['strcpy', 'sprintf'],
            'taint_path_length': 15,
            'is_reachable': True,
            'checksec': {'nx': True, 'pie': True, 'canary': False, 'relro': 'Full'},
            'language': 'c/c++',
            'arch': 'x86_64',
            'confidence': 0.8,
            'type': 'buffer overflow'
        }

        features = self.predictor.extract_features(vuln_info)

        self.assertEqual(len(features), 10)
        self.assertEqual(features[0], 20.0)
        self.assertEqual(features[1], 10.0)
        self.assertEqual(features[2], 2.0)

    def test_extract_protection_level(self):
        checksec_full = {'nx': True, 'pie': True, 'canary': True, 'relro': 'Full'}
        vuln_info_full = {'checksec': checksec_full}
        level_full = self.predictor._extract_protection_level(vuln_info_full)
        self.assertEqual(level_full, 1.0)

        checksec_none = {'nx': False, 'pie': False, 'canary': False, 'relro': False}
        vuln_info_none = {'checksec': checksec_none}
        level_none = self.predictor._extract_protection_level(vuln_info_none)
        self.assertEqual(level_none, 0.0)

    def test_extract_language_factor(self):
        vuln_info_c = {'language': 'c/c++'}
        self.assertEqual(self.predictor._extract_language_factor(vuln_info_c), 0.0)

        vuln_info_rust = {'language': 'rust'}
        self.assertEqual(self.predictor._extract_language_factor(vuln_info_rust), 0.3)

        vuln_info_go = {'language': 'go'}
        self.assertEqual(self.predictor._extract_language_factor(vuln_info_go), 0.2)

    def test_extract_vulnerability_type_factor(self):
        vuln_info_bo = {'type': 'buffer overflow'}
        self.assertEqual(self.predictor._extract_vulnerability_type_factor(vuln_info_bo), 1.0)

        vuln_info_dos = {'type': 'denial of service'}
        self.assertEqual(self.predictor._extract_vulnerability_type_factor(vuln_info_dos), 0.4)

        vuln_info_info = {'type': 'information disclosure'}
        self.assertEqual(self.predictor._extract_vulnerability_type_factor(vuln_info_info), 0.3)

    def test_get_feature_names(self):
        names = self.predictor.get_feature_names()
lass字段完整性$/d
        self.assertEqual(len(names), 10)
        self.assertIn('basic_block_count', names)
        self.assertIn('vulnerability_type_factor', names)


class TestPrediction(unittest.TestCase):
    """预测功能测试"""

    def setUp(self):
        self.predictor = VulnSeverityPredictor()

    def test_predict_with_rules(self):
        vuln_info = {
            'basic_block_count': 50,
            'cyclomatic_complexity': 20,
            'dangerous_functions': ['strcpy', 'strcat', 'sprintf'],
            'taint_path_length': 10,
            'is_reachable': True,
            'checksec': {'nx': False, 'pie': False},
            'language': 'c',
            'arch': 'x86',
            'confidence': 0.9,
            'type': 'stack overflow'
        }

        result = self.predictor.predict(vuln_info)

        self.assertIn('severity', result)
        self.assertIn('confidence', result)
        self.assertIn('method', result)
        self.assertEqual(result['method'], 'rule_based')
        self.assertIn(result['severity'], SEVERITY_LEVELS)

    def test_predict_critical(self):
        vuln_info = {
            'dangerous_functions': ['strcpy'],
            'type': 'buffer overflow',
            'checksec': {},
            'is_reachable': True,
            'confidence': 0.9
        }

        result = self.predictor.predict(vuln_info)

        self.assertEqual(result['severity'], 'Critical')

    def test_predict_high(self):
        vuln_info = {
            'dangerous_functions': ['strcpy'],
            'type': 'integer overflow',
            'checksec': {'nx': True, 'pie': True, 'canary': True},
            'is_reachable': True,
            'confidence': 0.6
        }

        result = self.predictor.predict(vuln_info)

        self.assertEqual(result['severity'], 'High')

    def test_predict_medium(self):
        vuln_info = {
            'dangerous_functions': [],
            'type': 'use after free',
            'checksec': {'nx': True, 'pie': True, 'canary': True},
            'is_reachable': True,
            'confidence': 0.5
        }

        result = self.predictor.predict(vuln_info)

        self.assertEqual(result['severity'], 'Medium')

    def test_predict_low(self):
        vuln_info = {
            'dangerous_functions': [],
            'type': 'unknown vulnerability',
            'checksec': {'nx': True, 'pie': True, 'canary': True, 'relro': 'Full'},
            'is_reachable': False,
            'confidence': 0.2
        }

        result = self.predictor.predict(vuln_info)

        self.assertEqual(result['severity'], 'Low')

    def test_predict_batch(self):
        vulnerabilities = [
            {'type': 'buffer overflow', 'dangerous_functions': ['strcpy']},
            {'type': 'denial of service', 'dangerous_functions': []}
        ]

        results = self.predictor.predict_batch(vulnerabilities)

        self.assertEqual(len(results), 2)
        self.assertIn('ml_prediction', results[0])
        self.assertIn('ml_prediction', results[1])


class TestVulnerabilityRanking(unittest.TestCase):
    """漏洞排序测试"""

    def setUp(self):
        self.predictor = VulnSeverityPredictor()

    def test_rank_vulnerabilities(self):
        vulnerabilities = [
            {
                'name': 'vuln1',
                'ml_prediction': {'severity': 'Low', 'confidence': 0.9}
            },
            {
                'name': 'vuln2',
                'ml_prediction': {'severity': 'Critical', 'confidence': 0.8}
            },
            {
                'name': 'vuln3',
                'ml_prediction': {'severity': 'High', 'confidence': 0.95}
            },
            {
                'name': 'vuln4',
                'ml_prediction': {'severity': 'Medium', 'confidence': 0.7}
            }
        ]

        ranked = self.predictor.rank_vulnerabilities(vulnerabilities)

        self.assertEqual(len(ranked), 4)
        self.assertEqual(ranked[0]['name'], 'vuln2')
        self.assertEqual(ranked[1]['name'], 'vuln3')
        self.assertEqual(ranked[2]['name'], 'vuln4')
        self.assertEqual(ranked[3]['name'], 'vuln1')

    def test_rank_same_severity(self):
        vulnerabilities = [
            {
                'name': 'vuln1',
                'ml_prediction': {'severity': 'High', 'confidence': 0.8}
            },
            {
                'name': 'vuln2',
                'ml_prediction': {'severity': 'High', 'confidence': 0.95}
            }
        ]

        ranked = self.predictor.rank_vulnerabilities(vulnerabilities)

        self.assertEqual(ranked[0]['name'], 'vuln2')
        self.assertEqual(ranked[1]['name'], 'vuln1')


class TestExplanation(unittest.TestCase):
    """解释生成测试"""

    def setUp(self):
        self.predictor = VulnSeverityPredictor()

    def test_generate_explanation(self):
        vuln_info = {
            'name': 'test_vuln',
            'ml_prediction': {
                'severity': 'High',
                'confidence': 0.85,
                'method': 'rule_based',
                'feature_importance': {
                    'vulnerability_type_factor': 0.3,
                    'dangerous_function_count': 0.25
                }
            }
        }

        explanation = self.predictor.generate_explanation(vuln_info)

        self.assertIsInstance(explanation, str)
        self.assertIn('High', explanation)
        self.assertIn('0.85', explanation)
        self.assertIn('rule_based', explanation)


class TestModelTraining(unittest.TestCase):
    """模型训练测试"""

    def setUp(self):
        self.m_tmp = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.m_tmp, ignore_errors=True)

    def test_train_default_model(self):
        model_path = os.path.join(self.m_tmp, 'test_model.pkl')

        success = train_default_model(model_path)

        self.assertTrue(success)
        self.assertTrue(os.path.exists(model_path))

    def test_load_trained_model(self):
        model_path = os.path.join(self.m_tmp, 'test_model.pkl')
        train_default_model(model_path)

        predictor = VulnSeverityPredictor(model_path)
        success = predictor.load_model()

        self.assertTrue(success)
        self.assertTrue(predictor.is_model_available())

    def test_predict_with_trained_model(self):
        model_path = os.path.join(self.m_tmp, 'test_model.pkl')
        train_default_model(model_path)

        predictor = VulnSeverityPredictor(model_path)
        predictor.load_model()

        vuln_info = {
            'basic_block_count': 50,
            'cyclomatic_complexity': 20,
            'dangerous_functions': ['strcpy'],
            'taint_path_length': 10,
            'is_reachable': True,
            'checksec': {'nx': False},
            'language': 'c',
            'arch': 'x86',
            'confidence': 0.9,
            'type': 'buffer overflow'
        }

        result = predictor.predict(vuln_info)

        self.assertIn('severity', result)
        self.assertEqual(result['method'], 'machine_learning')



if __name__ == '__main__':
    unittest.main()


