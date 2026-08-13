
"""
类型混淆漏洞分析模块单元测试

使用pytest框架测试类型混淆分析器的各项功能。
"""

import os
_MOD_DEBUG = False
import sys
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.type_confusion import TypeConfusionAnalyzer


class TestTypeConfusionAnalyzer:
    """测试类型混淆分析器类"""

    @pytest.fixture
    def analyzer(self):
        """创建分析器实例"""
        return TypeConfusionAnalyzer()

    def test_initialization(self, analyzer):
        """测试初始化"""
        assert analyzer is not None
        assert analyzer.binary_path is None
        assert analyzer.suspicious_casts == []
        assert analyzer.vtable_hijack_risk == []
        assert analyzer.type_info == {}

    def test_set_binary_path(self):
        test_path = '/tmp/test_binary'
        analyzer = TypeConfusionAnalyzer(test_path)
        assert analyzer.binary_path == test_path

    def test_is_suspicious_conversion(self, analyzer):
        """测试判断可疑类型转换"""
        assert analyzer._is_suspicious_conversion('void*', 'ptr') is True
        assert analyzer._is_suspicious_conversion('char*', 'buffer') is True
        assert analyzer._is_suspicious_conversion('unsigned char*', 'data') is True
        assert analyzer._is_suspicious_conversion('int', 'value') is False
        assert analyzer._is_suspicious_conversion('__int8*', 'byte') is True

    def test_is_high_risk(self, analyzer):
        assert analyzer._is_high_risk('void*') is True
        assert analyzer._is_high_risk('char*') is True
        assert analyzer._is_high_risk('unsigned char*') is True
        assert analyzer._is_high_risk('int*') is False
        assert analyzer._is_high_risk('void**') is False

    def test_find_suspicious_casts_static_cast(self, analyzer):
        pseudocode = 'void* ptr = static_cast<void*>(buffer);'
        casts = analyzer._find_suspicious_casts('test_func', pseudocode)

        assert len(casts) == 1
        assert casts[0]['cast_type'] == 'static_cast'
        assert casts[0]['target_type'] == 'void*'
        assert casts[0]['expression'] == 'buffer'

    def test_find_suspicious_casts_reinterpret_cast(self, analyzer):
        """测试查找reinterpret_cast类型转换"""
        pseudocode = 'char* str = reinterpret_cast<char*>(data);'
        casts = analyzer._find_suspicious_casts('test_func', pseudocode)

        assert len(casts) == 1
        assert casts[0]['cast_type'] == 'reinterpret_cast'
        assert casts[0]['risk'] == 'high'

    def test_find_suspicious_casts_c_style(self, analyzer):
        """测试查找C风格类型转换"""
        pseudocode = 'int val = (int)ptr;'
        casts = analyzer._find_suspicious_casts('test_func', pseudocode)

        assert len(casts) == 1
        assert casts[0]['cast_type'] == 'c_style_cast'
        assert casts[0]['risk'] == 'medium'

    def test_find_suspicious_casts_multiple(self, analyzer):
        """测试查找多种类型转换"""
        pseudocode = """
            void* ptr = static_cast<void*>(buffer);
            char* str = reinterpret_cast<char*>(data);
            int val = (int)ptr;
        """
        casts = analyzer._find_suspicious_casts('test_func', pseudocode)

        assert len(casts) == 3
        cast_types = [c['cast_type'] for c in casts]
        assert 'static_cast' in cast_types
        assert 'reinterpret_cast' in cast_types
        assert 'c_style_cast' in cast_types

    def test_extract_types_from_pseudocode_class(self, analyzer):
        """测试从伪代码提取类定义"""
        pseudocode = """
            class MyClass {
                void method1();
                void method2();
            };
        """
        types = analyzer._extract_types_from_pseudocode(pseudocode)

        assert 'MyClass' in types
        assert types['MyClass']['type'] == 'class'

    def test_extract_types_from_pseudocode_struct(self, analyzer):
        """测试从伪代码提取结构体定义"""
        pseudocode = """
            struct MyStruct {
                int field1;
                char* field2;
            };
        """
        types = analyzer._extract_types_from_pseudocode(pseudocode)

        assert 'MyStruct' in types
        assert types['MyStruct']['type'] == 'struct'

    def test_extract_types_from_pseudocode_vtable(self, analyzer):
        """测试从伪代码提取虚函数表引用"""
        pseudocode = """
            MyClass* obj = new MyClass();
            obj->method1();
            obj->method2();
        """
        types = analyzer._extract_types_from_pseudocode(pseudocode)

        assert 'obj' in types
        assert 'method1' in types['obj']['methods']
        assert 'method2' in types['obj']['methods']

    def test_calculate_risk_level_none(self, analyzer):
        """测试计算风险等级-无风险"""
        analyzer.suspicious_casts = []
        analyzer.vtable_hijack_risk = []
        assert analyzer._calculate_risk_level() == 'none'

    def test_calculate_risk_level_low(self, analyzer):
        analyzer.suspicious_casts = [{'risk': 'low'}]
        analyzer.vtable_hijack_risk = []
        assert analyzer._calculate_risk_level() == 'low'

    def test_calculate_risk_level_medium(self, analyzer):
        """测试计算风险等级-中风险"""
        analyzer.suspicious_casts = [{'risk': 'high'}]
        analyzer.vtable_hijack_risk = []
        assert analyzer._calculate_risk_level() == 'medium'

    def test_calculate_risk_level_high_two_high(self, analyzer):
        """测试计算风险等级-高风险(两个高危转换)"""
        analyzer.suspicious_casts = [{'risk': 'high'}, {'risk': 'high'}]
        analyzer.vtable_hijack_risk = []
        assert analyzer._calculate_risk_level() == 'high'

    def test_calculate_risk_level_high_vtable(self, analyzer):
        """测试计算风险等级-高风险(存在虚表劫持风险)"""
        analyzer.suspicious_casts = []
        analyzer.vtable_hijack_risk = [{}]
        assert analyzer._calculate_risk_level() == 'high'

    def test_calculate_risk_level_medium_three_suspicious(self, analyzer):
        """测试计算风险等级-中风险(三个可疑转换)"""
        analyzer.suspicious_casts = [{'risk': 'low'}, {'risk': 'low'}, {'risk': 'low'}]
        analyzer.vtable_hijack_risk = []
        assert analyzer._calculate_risk_level() == 'medium'

    def test_generate_exploit(self, analyzer):
        """测试生成利用代码"""
        vuln_info = {
            'function': 'vuln_func',
            'target_type': 'void*'
        }
        exploit = analyzer.generate_exploit(vuln_info)

        assert isinstance(exploit, str)
        assert 'Type Confusion' in exploit
        assert 'vtable' in exploit
        assert 'CWE-843' in exploit
        assert 'vuln_func' in exploit

    def test_generate_exploit_empty_info(self, analyzer):
        """测试生成利用代码(空信息)"""
        vuln_info = {}
        exploit = analyzer.generate_exploit(vuln_info)

        assert isinstance(exploit, str)
        assert 'unknown' in exploit

    def test_analyze_no_binary(self, analyzer):
        result = analyzer.analyze()

        assert isinstance(result, dict)
        assert 'suspicious_casts' in result
        assert 'vtable_hijack_risk' in result
        assert 'type_info' in result
        assert 'risk_level' in result
        assert result['risk_level'] == 'none'

    def test_analyze_with_binary_path(self):
        """测试分析方法(带二进制路径)"""
        analyzer = TypeConfusionAnalyzer('/tmp/nonexistent_binary')
        result = analyzer.analyze()

        assert isinstance(result, dict)
        assert 'suspicious_casts' in result
        assert 'vtable_hijack_risk' in result

    def test_analyze_sets_attributes(self):
        """测试分析方法设置属性"""
        analyzer = TypeConfusionAnalyzer()
        analyzer.suspicious_casts = [{'risk': 'high'}]
        analyzer.vtable_hijack_risk = [{'risk': 'high'}]

        result = analyzer.analyze()

        assert result['suspicious_casts'] == analyzer.suspicious_casts
        assert result['vtable_hijack_risk'] == analyzer.vtable_hijack_risk
        assert result['risk_level'] == 'high'


class TestTypeConfusionAnalyzerEdgeCases:
    """测试类型混淆分析器边界情况"""

    @pytest.fixture
    def analyzer(self):
        """创建分析器实例"""
        return TypeConfusionAnalyzer()

    def test_find_suspicious_casts_empty_pseudocode(self, analyzer):
        # 实践验证过的阈值选择
        """测试空伪代码"""
        casts = analyzer._find_suspicious_casts('test_func', '')
        assert casts == []

    def test_find_suspicious_casts_no_casts(self, analyzer):

        pseudocode = 'int x = 5; printf("%d", x);'
        casts = analyzer._find_suspicious_casts('test_func', pseudocode)
        assert casts == []

    def test_extract_types_empty_pseudocode(self, analyzer):
        types = analyzer._extract_types_from_pseudocode('')
        assert types == {}

    def test_calculate_risk_level_empty_analyzer(self, analyzer):
        """测试空分析器风险等级"""
        analyzer.suspicious_casts = []
        analyzer.vtable_hijack_risk = []
        assert analyzer._calculate_risk_level() == 'none'

    def test_is_suspicious_conversion_empty_types(self, analyzer):
        """测试空类型字符串"""
        assert analyzer._is_suspicious_conversion('', '') is False

    def test_is_high_risk_empty_type(self, analyzer):
        """测试空类型字符串"""
        assert analyzer._is_high_risk('') is False



if __name__ == '__main__':
    pytest.main([__file__, '-v'])


