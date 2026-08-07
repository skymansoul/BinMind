
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


