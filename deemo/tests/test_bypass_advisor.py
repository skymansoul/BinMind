#!/usr/bin/env python3
"""
保护机制绕过策略模块测试
"""
import os
import sys
import unittest
import tempfile
import shutil

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.bypass_advisor import (
    BypassAdvisor, BypassStrategy, BypassRecommendation,
    ProtectionStatus, ProtectionType, BypassTechnique
)


class TestBypassAdvisor(unittest.TestCase):
    """保护机制绕过策略推荐器测试类"""

    def setUp(self):
        """测试前准备"""
        self.temp_dir = tempfile.mkdtemp()
        self.advisor = BypassAdvisor(output_dir=self.temp_dir)

    def tearDown(self):
        """测试后清理"""
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)

    def test_protection_type_enum(self):
        """测试保护类型枚举"""
        self.assertEqual(ProtectionType.NX.value, 'nx')
        self.assertEqual(ProtectionType.ASLR.value, 'aslr')
        self.assertEqual(ProtectionType.CANARY.value, 'canary')
        self.assertEqual(ProtectionType.CFG.value, 'cfg')
        self.assertEqual(ProtectionType.RELRO.value, 'relro')

    def test_bypass_technique_enum(self):
        """测试绕过技术枚举"""
        self.assertEqual(BypassTechnique.INFO_LEAK.value, 'info_leak')
        self.assertEqual(BypassTechnique.ROP_CHAIN.value, 'rop_chain')
        self.assertEqual(BypassTechnique.JOP_CHAIN.value, 'jop_chain')
        self.assertEqual(BypassTechnique.STACK_PIVOT.value, 'stack_pivot')
        self.assertEqual(BypassTechnique.SROP.value, 'srop')

    def test_protection_status_dataclass(self):
        """测试 ProtectionStatus 数据类"""
        status = ProtectionStatus(
            protection=ProtectionType.NX,
            enabled=True,
            strength='strong'
        )
        
        self.assertEqual(status.protection, ProtectionType.NX)
        self.assertTrue(status.enabled)
        self.assertEqual(status.strength, 'strong')

    def test_protection_status_to_dict(self):
        """测试 ProtectionStatus 转换为字典"""
        status = ProtectionStatus(
            protection=ProtectionType.ASLR,
            enabled=False,
            strength='disabled'
        )
        
        result = status.to_dict()
        
        self.assertIn('protection', result)
        self.assertIn('enabled', result)
        self.assertIn('strength', result)
        self.assertEqual(result['protection'], 'aslr')
        self.assertFalse(result['enabled'])

    def test_bypass_strategy_dataclass(self):
        """测试 BypassStrategy 数据类"""
        strategy = BypassStrategy(
            protection=ProtectionType.NX,
            techniques=[BypassTechnique.ROP_CHAIN],
            description='ROP链绕过NX',
            prerequisites=['有足够gadget'],
            code_snippet='test code',
            success_rate=0.6,
            difficulty='hard'
        )
        
        self.assertEqual(strategy.protection, ProtectionType.NX)
        self.assertEqual(len(strategy.techniques), 1)
        self.assertEqual(strategy.success_rate, 0.6)

    def test_bypass_strategy_to_dict(self):
        """测试 BypassStrategy 转换为字典"""
        strategy = BypassStrategy(
            protection=ProtectionType.ASLR,
            techniques=[BypassTechnique.INFO_LEAK],
            description='信息泄露绕过ASLR',
            prerequisites=['有信息泄露漏洞'],
            success_rate=0.85,
            difficulty='easy'
        )
        
        result = strategy.to_dict()
        
        self.assertIn('protection', result)
        self.assertIn('techniques', result)
        self.assertIn('success_rate', result)
        self.assertEqual(result['success_rate'], 0.85)

    def test_analyze_protections(self):
        """测试分析保护机制"""
        # 创建模拟二进制文件
        test_file = os.path.join(self.temp_dir, 'test.bin')
        with open(test_file, 'wb') as f:
            f.write(b'\x7fELF' + b'\x00' * 100)
        
        protections = self.advisor.analyze_protections(test_file)
        
        self.assertGreater(len(protections), 0)
        
        # 检查是否有NX保护状态
        nx_protection = next((p for p in protections if p.protection == ProtectionType.NX), None)
        self.assertIsNotNone(nx_protection)

    def test_recommend_bypass_strategies(self):
        """测试推荐绕过策略"""
        test_file = os.path.join(self.temp_dir, 'test.bin')
        with open(test_file, 'wb') as f:
            f.write(b'\x00' * 100)
        
        result = self.advisor.recommend_bypass_strategies(test_file)
        
        self.assertIsInstance(result, BypassRecommendation)
        self.assertGreater(len(result.bypass_strategies), 0)

    def test_recommend_with_info_leak(self):
        """测试带信息泄露的绕过策略推荐"""
        test_file = os.path.join(self.temp_dir, 'test.bin')
        with open(test_file, 'wb') as f:
            f.write(b'\x00' * 100)
        
        result = self.advisor.recommend_bypass_strategies(
            test_file,
            info_leak_points=['格式化字符串漏洞']
        )
        
        self.assertGreater(len(result.bypass_strategies), 0)
        self.assertEqual(len(result.info_leak_points), 1)

    def test_generate_report(self):
        """测试生成报告"""
        test_file = os.path.join(self.temp_dir, 'test.bin')
        with open(test_file, 'wb') as f:
            f.write(b'\x00' * 100)
        
        result = self.advisor.recommend_bypass_strategies(test_file)
        report = self.advisor.generate_report(result)
        
        self.assertIn('保护机制绕过策略报告', report)
        self.assertIn('test.bin', report)

    def test_save_result(self):
        """测试保存结果"""
        test_file = os.path.join(self.temp_dir, 'test.bin')
        with open(test_file, 'wb') as f:
            f.write(b'\x00' * 100)
        
        result = self.advisor.recommend_bypass_strategies(test_file)
        saved_path = self.advisor.save_result(result, 'test_bypass')
        
        self.assertTrue(os.path.exists(saved_path))
        self.assertTrue(saved_path.endswith('.json'))


class TestBypassRecommendation(unittest.TestCase):
    """BypassRecommendation 数据类测试"""

    def test_bypass_recommendation_dataclass(self):
        """测试绕过推荐结果"""
        strategy = BypassStrategy(
            protection=ProtectionType.NX,
            techniques=[BypassTechnique.ROP_CHAIN],
            description='ROP绕过NX',
            prerequisites=['test'],
            success_rate=0.6
        )
        
        result = BypassRecommendation(
            binary_path='/test/bin',
            protections=[
                ProtectionStatus(protection=ProtectionType.NX, enabled=True, strength='strong')
            ],
            bypass_strategies=[strategy],
            info_leak_points=['test leak'],
            available_gadgets=[],
            summary='Test summary',
            timestamp='2024-01-01'
        )
        
        self.assertEqual(len(result.protections), 1)
        self.assertEqual(len(result.bypass_strategies), 1)

    def test_bypass_recommendation_to_dict(self):
        """测试转换为字典"""
        result = BypassRecommendation(
            binary_path='/test/bin',
            protections=[],
            bypass_strategies=[],
            timestamp='2024-01-01'
        )
        
        data = result.to_dict()
        
        self.assertIn('binary_path', data)
        self.assertIn('protections', data)
        self.assertIn('bypass_strategies', data)


if __name__ == '__main__':
    unittest.main()