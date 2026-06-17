import unittest
import os
import sys
import json
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.reliability_predictor import (
    ReliabilityPredictor,
    RuleBasedModel,
    MachineLearningModel,
    ReliabilityLevel,
    FeatureVector
)


class TestReliabilityPredictor(unittest.TestCase):
    """测试可靠性预测模块"""
    
    def setUp(self):
        self.predictor = ReliabilityPredictor()
    
    def test_get_metadata(self):
        """测试获取元数据"""
        metadata = self.predictor.get_metadata()
        self.assertEqual(metadata.name, "ReliabilityPredictor")
        self.assertEqual(metadata.version, "1.0.0")
    
    def test_validate_input(self):
        """测试输入验证"""
        # 有效输入
        valid, error = self.predictor.validate_input(
            vulnerability_type='buffer_overflow',
            architecture='x86_64',
            mitigations=['ASLR', 'NX'],
            payload_size=512,
            gadget_count=10
        )
        self.assertTrue(valid)
        self.assertIsNone(error)
        
        # 缺少必需参数
        valid, error = self.predictor.validate_input(
            vulnerability_type='buffer_overflow',
            architecture='x86_64',
            mitigations=['ASLR'],
            payload_size=512
        )
        self.assertFalse(valid)
        self.assertEqual(error, "缺少必需参数: gadget_count")
        
        # 无效的漏洞类型
        valid, error = self.predictor.validate_input(
            vulnerability_type='invalid_type',
            architecture='x86_64',
            mitigations=['ASLR'],
            payload_size=512,
            gadget_count=10
        )
        self.assertFalse(valid)
        self.assertEqual(error, "无效的漏洞类型: invalid_type")
        
        # 无效的payload大小
        valid, error = self.predictor.validate_input(
            vulnerability_type='buffer_overflow',
            architecture='x86_64',
            mitigations=['ASLR'],
            payload_size=-1,
            gadget_count=10
        )
        self.assertFalse(valid)
        self.assertEqual(error, "payload_size 不能为负数")
    
    def test_predict_basic(self):
        """测试基本预测功能"""
        result = self.predictor.analyze(
            vulnerability_type='buffer_overflow',
            architecture='x86_64',
            mitigations=['NX'],
            payload_size=256,
            gadget_count=15,
            has_info_leak=True
        )
        
        self.assertTrue(result['success'])
        self.assertIn('score', result)
        self.assertIn('level', result)
        self.assertIn('confidence', result)
        self.assertIn('estimated_success_rate', result)
        self.assertIn('factors', result)
        self.assertIn('recommendations', result)
        
        # 验证分数范围
        self.assertGreaterEqual(result['score'], 0.0)
        self.assertLessEqual(result['score'], 1.0)
        
        # 验证置信度范围
        self.assertGreaterEqual(result['confidence'], 0.0)
        self.assertLessEqual(result['confidence'], 1.0)
    
    def test_predict_with_info_leak(self):
        """测试信息泄露对预测的影响"""
        # 有信息泄露
        result_with_leak = self.predictor.analyze(
            vulnerability_type='buffer_overflow',
            architecture='x86_64',
            mitigations=['ASLR', 'NX'],
            payload_size=256,
            gadget_count=10,
            has_info_leak=True
        )
        
        # 无信息泄露
        result_without_leak = self.predictor.analyze(
            vulnerability_type='buffer_overflow',
            architecture='x86_64',
            mitigations=['ASLR', 'NX'],
            payload_size=256,
            gadget_count=10,
            has_info_leak=False
        )
        
        # 有信息泄露的分数应该更高
        self.assertGreater(result_with_leak['score'], result_without_leak['score'])
    
    def test_predict_with_mitigations(self):
        """测试缓解措施对预测的影响"""
        # 无缓解措施
        result_no_mitigation = self.predictor.analyze(
            vulnerability_type='buffer_overflow',
            architecture='x86_64',
            mitigations=[],
            payload_size=256,
            gadget_count=10,
            has_info_leak=True
        )
        
        # 有缓解措施
        result_with_mitigation = self.predictor.analyze(
            vulnerability_type='buffer_overflow',
            architecture='x86_64',
            mitigations=['ASLR', 'NX', 'CFG', 'CET'],
            payload_size=256,
            gadget_count=10,
            has_info_leak=True
        )
        
        # 有缓解措施的分数应该更低
        self.assertLess(result_with_mitigation['score'], result_no_mitigation['score'])
    
    def test_set_model(self):
        """测试切换模型"""
        # 默认模型是rule_based
        self.assertEqual(self.predictor.model_type, 'rule_based')
        
        # 切换到机器学习模型
        result = self.predictor.set_model('ml')
        self.assertTrue(result)
        self.assertEqual(self.predictor.model_type, 'ml')
        
        # 测试机器学习模型预测
        result = self.predictor.analyze(
            vulnerability_type='buffer_overflow',
            architecture='x86_64',
            mitigations=['NX'],
            payload_size=256,
            gadget_count=10
        )
        self.assertTrue(result['success'])
        self.assertEqual(result['model_type'], 'ml')
        
        # 无效模型类型
        result = self.predictor.set_model('invalid')
        self.assertFalse(result)
    
    def test_train_model(self):
        """测试训练模型"""
        # 切换到ML模型
        self.predictor.set_model('ml')
        
        # 创建训练数据
        training_data = [
            {
                'features': {
                    'vulnerability_type': 'buffer_overflow',
                    'architecture': 'x86',
                    'mitigations': [],
                    'payload_size': 100,
                    'gadget_count': 20,
                    'has_info_leak': True
                },
                'target': 0.9
            },
            {
                'features': {
                    'vulnerability_type': 'heap_overflow',
                    'architecture': 'arm64',
                    'mitigations': ['ASLR', 'NX', 'CFG'],
                    'payload_size': 1000,
                    'gadget_count': 2,
                    'has_info_leak': False
                },
                'target': 0.3
            }
        ]
        
        result = self.predictor.train_model(training_data)
        self.assertTrue(result)
    
    def test_export_import_model(self):
        """测试导出和导入模型"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            temp_file = f.name
        
        try:
            # 切换到ML模型
            self.predictor.set_model('ml')
            
            # 导出模型
            result = self.predictor.export_model(temp_file)
            self.assertTrue(result)
            
            # 验证文件存在
            self.assertTrue(os.path.exists(temp_file))
            
            # 创建新实例并导入
            new_predictor = ReliabilityPredictor({'model_type': 'rule_based'})
            result = new_predictor.import_model(temp_file)
            self.assertTrue(result)
            self.assertEqual(new_predictor.model_type, 'ml')
        
        finally:
            if os.path.exists(temp_file):
                os.unlink(temp_file)
    
    def test_reliability_levels(self):
        """测试可靠性等级"""
        # 测试不同场景下的等级
        high_result = self.predictor.analyze(
            vulnerability_type='format_string',
            architecture='x86',
            mitigations=[],
            payload_size=100,
            gadget_count=20,
            has_info_leak=True
        )
        self.assertIn(high_result['level'], ['high', 'critical_success'])
        
        critical_result = self.predictor.analyze(
            vulnerability_type='use_after_free',
            architecture='arm64',
            mitigations=['ASLR', 'NX', 'CFG', 'CET'],
            payload_size=2000,
            gadget_count=1,
            has_info_leak=False,
            requires_memory_layout=True,
            timing_constraints=True,
            dependency_count=5
        )
        self.assertIn(critical_result['level'], ['low', 'critical'])


class TestRuleBasedModel(unittest.TestCase):
    """测试基于规则的模型"""
    
    def test_rule_based_prediction(self):
        """测试规则模型预测"""
        model = RuleBasedModel()
        
        features = FeatureVector(
            vulnerability_type='buffer_overflow',
            architecture='x86_64',
            mitigations=['ASLR', 'NX'],
            payload_size=200,
            gadget_count=15,
            has_info_leak=True,
            requires_memory_layout=False,
            timing_constraints=False,
            dependency_count=2,
            os_version='Linux',
            target_binary_size=1024
        )
        
        prediction = model.predict(features)
        
        self.assertIsNotNone(prediction)
        self.assertGreaterEqual(prediction.score, 0.0)
        self.assertLessEqual(prediction.score, 1.0)


class TestMachineLearningModel(unittest.TestCase):
    """测试机器学习模型"""
    
    def test_ml_prediction(self):
        """测试ML模型预测"""
        model = MachineLearningModel()
        
        features = FeatureVector(
            vulnerability_type='buffer_overflow',
            architecture='x86',
            mitigations=[],
            payload_size=100,
            gadget_count=20,
            has_info_leak=True,
            requires_memory_layout=False,
            timing_constraints=False,
            dependency_count=1,
            os_version='Linux',
            target_binary_size=512
        )
        
        prediction = model.predict(features)
        
        self.assertIsNotNone(prediction)
        self.assertGreaterEqual(prediction.score, 0.0)
        self.assertLessEqual(prediction.score, 1.0)


if __name__ == '__main__':
    unittest.main()