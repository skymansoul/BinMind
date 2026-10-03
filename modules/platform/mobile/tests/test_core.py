"""移动端: 核心模块测试"""
import pytest
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'src'))

from mobile_analysis import (
    analyze_mobile_binary, MobilePlatform, MobileBinaryAnalyzer,
    AndroidRTAnalyzer, IOSRuntimeAnalyzer, RuntimeType,
    ART_MAGIC, OAT_MAGIC, MACHO_MAGICS
)


class TestCoreImports:
    """确认核心模块导入及基本常量正确。"""

    def test_mobile_analysis_imports(self):
        """mobile_analysis导出全部预期符号。"""
        assert MobilePlatform.ANDROID == 'android'
        assert MobilePlatform.IOS == 'ios'
        assert ART_MAGIC == b'art\n'
        assert OAT_MAGIC == b'oat\n'
        assert len(MACHO_MAGICS) == 4

    def test_runtime_type_enum(self):
        """RuntimeType枚举值匹配预期。"""
        assert RuntimeType.ART == 'art'
        assert RuntimeType.DALVIK == 'dalvik'
        assert RuntimeType.OBJECTIVE_C == 'objective_c'
        assert RuntimeType.SWIFT == 'swift'

    def test_mobile_binary_analyzer_stub(self):
        """MobileBinaryAnalyzer桩类行为正常。"""
        analyzer = MobileBinaryAnalyzer('/tmp/test.so', 'android')
        assert analyzer.platform == MobilePlatform.ANDROID

    def test_auto_platform_defaults_to_android(self):
        """auto平台默认选android。"""
        analyzer = MobileBinaryAnalyzer('/tmp/test.so', 'auto')
        assert analyzer.platform == MobilePlatform.ANDROID


class TestAnalyzerInstantiation:
    """确认分析器实例化及文件缺失降级。"""

    def test_android_analyzer_instantiation(self):
        """AndroidRTAnalyzer文件缺失时优雅降级。"""
        analyzer = AndroidRTAnalyzer('/nonexistent/file.oat')
        assert analyzer.data == b''
        rt = analyzer.detect_runtime_type()
        assert rt == RuntimeType.ART  # 空数据回退为ART

    def test_ios_analyzer_instantiation(self):
        """IOSRuntimeAnalyzer文件缺失时优雅降级。"""
        analyzer = IOSRuntimeAnalyzer('/nonexistent/file.macho')
        assert analyzer.data == b''
        # Mach-O空数据校验为False
        assert analyzer._verify_is_macho() is False

    def test_file_not_found_returns_error(self):
        """不存在文件返回error字段。"""
        result = analyze_mobile_binary('/nonexistent/file.bin')
        assert 'error' in result
        assert result['error'] == 'File not found'


class TestDataClasses:
    """确认dataclass结构字段默认值。"""

    def test_art_method_defaults(self):
        from mobile_analysis import ArtMethod
        m = ArtMethod('test', 0, 0, 0)
        assert m.name == 'test'
        assert m.is_native is False
        assert m.is_abstract is False
        assert m.is_virtual is False

    def test_oat_file_defaults(self):
        from mobile_analysis import OatFile
        o = OatFile(0x1000, 1, 0x700000, 0x8000, 'interpreter', 'speed', [])
        assert o.dex_file_count == 1
        assert o.compiler_filter == 'speed'

    def test_macho_runtime_class_defaults(self):
        from mobile_analysis import MachORuntimeClass
        c = MachORuntimeClass('MyClass', 'NSObject')
        assert c.name == 'MyClass'
        assert c.superclass == 'NSObject'
        assert c.is_metaclass is False
        assert c.methods == []

    def test_mobile_vulnerability_defaults(self):
        from mobile_analysis import MobileVulnerability
        v = MobileVulnerability()
        assert v.severity == 'Medium'
        assert v.type == ''
        assert v.description == ''
