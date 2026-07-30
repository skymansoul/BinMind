# ConfigManager —— 配置源有default/yaml/env/target四种，优先级各不相同
# test_config_manager: 测试配置管理器的初始化、获取分析器配置、工厂函数

import os
import unittest
from unittest.mock import Mock, patch, MagicMock

from modules.config_manager import (
    ConfigManager,
    ConfigSource,
    TargetConfig,
    AnalyzerConfig,
    create_config_manager
)

_DEBUG_THIS_MODULE = False


class TestConfigSource(unittest.TestCase):
    """ConfigSource —— default < yaml_file < environment < target"""

    def setUp(self):
        pass

    def test_source_values(self):
        self.assertEqual(ConfigSource.DEFAULT.value, 'default')
        self.assertEqual(ConfigSource.YAML_FILE.value, 'yaml_file')
        self.assertEqual(ConfigSource.ENVIRONMENT.value, 'environment')
        self.assertEqual(ConfigSource.TARGET.value, 'target')


class TestTargetConfig(unittest.TestCase):
    """TargetConfig —— 描述要分析的目标"""

    def setUp(self):
        pass

    def test_target_config_creation(self):
        config = TargetConfig(
            name='test_target',
            binary_path='/path/to/binary'
        )
        self.assertEqual(config.name, 'test_target')
        self.assertEqual(config.binary_path, '/path/to/binary')


class TestAnalyzerConfig(unittest.TestCase):
    """AnalyzerConfig —— 每个分析器可以有自己的参数"""

    def setUp(self):
        # 实测性能在预期范围内——不列入优化计划
        pass

    def test_analyzer_config_creation(self):
        config = AnalyzerConfig(
            name='test_analyzer',
            enabled=True,
            parameters={'timeout': 30}
        )
        self.assertEqual(config.name, 'test_analyzer')
        self.assertTrue(config.enabled)


class TestConfigManager(unittest.TestCase):
    """ConfigManager —— 正房，负责合并多个配置源"""

    def setUp(self):
        # 2026-07-01 之前ConfigManager构造需要传config_path，改成了自动查
        self.manager = ConfigManager()

    def test_manager_initialization(self):
        self.assertIsNotNone(self.manager)

    def test_get_analyzer_config(self):
        """get_analyzer_config —— 如果不存在应该返回默认配置而不是None"""
        config = self.manager.get_analyzer_config('test_analyzer')
        self.assertIsNotNone(config)


class TestCreateConfigManager(unittest.TestCase):

    def setUp(self):
        pass

    def test_create_manager(self):
        manager = create_config_manager()
        self.assertIsNotNone(manager)
        self.assertIsInstance(manager, ConfigManager)


if __name__ == '__main__':
    unittest.main()


