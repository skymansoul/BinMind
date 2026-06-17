"""
插件管理器模块测试
"""

import unittest
from unittest.mock import Mock, patch
from modules.plugin_manager import (
    PluginManager,
    BaseAnalyzer,
    AnalyzerType,
    AnalyzerMetadata,
    get_plugin_manager
)


class TestAnalyzerType(unittest.TestCase):
    """测试分析器类型枚举"""
    
    def test_type_values(self):
        """测试类型值"""
        self.assertEqual(AnalyzerType.DECOMPILER.value, 'decompiler')
        self.assertEqual(AnalyzerType.STATIC_ANALYZER.value, 'static_analyzer')
        self.assertEqual(AnalyzerType.SYMBOLIC_EXECUTOR.value, 'symbolic_executor')
        self.assertEqual(AnalyzerType.VULNERABILITY_DETECTOR.value, 'vulnerability_detector')


class TestAnalyzerMetadata(unittest.TestCase):
    """测试分析器元数据"""
    
    def test_metadata_creation(self):
        """测试元数据创建"""
        metadata = AnalyzerMetadata(
            name='test_analyzer',
            type=AnalyzerType.STATIC_ANALYZER,
            version='1.0.0',
            description='Test analyzer',
            author='Test Author',
            supported_platforms=['x86_64', 'arm']
        )
        self.assertEqual(metadata.name, 'test_analyzer')
        self.assertEqual(metadata.type, AnalyzerType.STATIC_ANALYZER)
        self.assertEqual(metadata.version, '1.0.0')


class TestPluginManager(unittest.TestCase):
    """测试插件管理器"""
    
    def setUp(self):
        """设置测试环境"""
        self.manager = PluginManager()
    
    def test_manager_initialization(self):
        """测试管理器初始化"""
        self.assertIsNotNone(self.manager)
    
    def test_get_analyzer(self):
        """测试获取分析器"""
        analyzer = self.manager.get_analyzer('static_analyzer')
        self.assertIsNotNone(analyzer)
    
    def test_list_analyzers(self):
        """测试列出分析器"""
        analyzers = self.manager.list_analyzers()
        self.assertIsInstance(analyzers, list)


class TestGetPluginManager(unittest.TestCase):
    """测试获取插件管理器"""
    
    def test_get_manager(self):
        """测试获取管理器实例"""
        manager = get_plugin_manager()
        self.assertIsNotNone(manager)
        self.assertIsInstance(manager, PluginManager)


class TestConcreteAnalyzer(BaseAnalyzer):
    """用于测试的具体分析器实现"""
    
    def analyze(self, **kwargs) -> dict:
        return {"success": True}
    
    @classmethod
    def get_metadata(cls) -> AnalyzerMetadata:
        return AnalyzerMetadata(
            name="TestAnalyzer",
            type=AnalyzerType.UTILITY
        )


class TestBaseAnalyzer(unittest.TestCase):
    """测试基础分析器"""
    
    def test_analyzer_initialization(self):
        """测试分析器初始化"""
        analyzer = TestConcreteAnalyzer()
        self.assertIsNotNone(analyzer)
    
    def test_validate_input(self):
        """测试输入验证"""
        analyzer = TestConcreteAnalyzer()
        result = analyzer.validate_input()
        self.assertTrue(result[0])
    
    def test_metadata_property(self):
        """测试元数据属性"""
        analyzer = TestConcreteAnalyzer()
        metadata = analyzer.get_metadata()
        self.assertIsNotNone(metadata)
        self.assertEqual(metadata.name, 'TestAnalyzer')


if __name__ == '__main__':
    unittest.main()
