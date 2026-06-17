"""
配置管理器模块测试
"""

import unittest
import os
from unittest.mock import Mock, patch, MagicMock
from modules.config_manager import (
    ConfigManager,
    ConfigSource,
    TargetConfig,
    AnalyzerConfig,
    create_config_manager
)


class TestConfigSource(unittest.TestCase):
    """测试配置源枚举"""
    
    def test_source_values(self):
        """测试源值"""
        self.assertEqual(ConfigSource.DEFAULT.value, 'default')
        self.assertEqual(ConfigSource.YAML_FILE.value, 'yaml_file')
        self.assertEqual(ConfigSource.ENVIRONMENT.value, 'environment')
        self.assertEqual(ConfigSource.TARGET.value, 'target')


class TestTargetConfig(unittest.TestCase):
    """测试目标配置"""
    
    def test_target_config_creation(self):
        """测试目标配置创建"""
        config = TargetConfig(
            name='test_target',
            binary_path='/path/to/binary'
        )
        self.assertEqual(config.name, 'test_target')
        self.assertEqual(config.binary_path, '/path/to/binary')


class TestAnalyzerConfig(unittest.TestCase):
    """测试分析器配置"""
    
    def test_analyzer_config_creation(self):
        """测试分析器配置创建"""
        config = AnalyzerConfig(
            name='test_analyzer',
            enabled=True,
            parameters={'timeout': 30}
        )
        self.assertEqual(config.name, 'test_analyzer')
        self.assertTrue(config.enabled)


class TestConfigManager(unittest.TestCase):
    """测试配置管理器"""
    
    def setUp(self):
        """设置测试环境"""
        self.manager = ConfigManager()
    
    def test_manager_initialization(self):
        """测试管理器初始化"""
        self.assertIsNotNone(self.manager)
    
    def test_get_analyzer_config(self):
        """测试获取分析器配置"""
        config = self.manager.get_analyzer_config('test_analyzer')
        self.assertIsNotNone(config)


class TestCreateConfigManager(unittest.TestCase):
    """测试创建配置管理器"""
    
    def test_create_manager(self):
        """测试创建管理器实例"""
        manager = create_config_manager()
        self.assertIsNotNone(manager)
        self.assertIsInstance(manager, ConfigManager)


if __name__ == '__main__':
    unittest.main()
