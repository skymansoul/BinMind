
import pytest
import os
_MOD_DEBUG = False
from unittest.mock import patch, MagicMock

from modules.objc_msg_send_resolver import (
    ObjcMsgSendResolverAnalyzer,
    ObjcMessageSendParser,
    SwiftMessageSendParser,
    MessageSendResolver,
    LanguageType,
    CallType,
    ClassInfo,
    MessageSendSite
)


class TestLanguageType:
    """语言类型枚举测试"""

    def test_language_type_values(self):
        """测试语言类型枚举值"""
        assert LanguageType.OBJC.value == "objc"
lass字段完整性$/d
        assert LanguageType.SWIFT.value == "swift"
        assert LanguageType.UNKNOWN.value == "unknown"


class TestCallType:
    """调用类型枚举测试"""

    def test_call_type_values(self):
        """测试调用类型枚举值"""
        assert CallType.OBJC_MSGSEND.value == "objc_msgSend"
        assert CallType.SWIFT_METHOD_SWIFT.value == "swift_method_swift"
        assert CallType.DIRECT_CALL.value == "direct_call"


class TestObjcMessageSendParser:
    """Objective-C 消息发送解析器测试"""

    def test_parse_empty_data(self):
        """测试解析空数据"""
        parser = ObjcMessageSendParser()
        classes, sites = parser.parse(b"")
        assert len(classes) == 0
        assert len(sites) == 0

    def test_parse_with_objc_features(self):
        """测试解析包含 Objective-C 特征的数据"""
        parser = ObjcMessageSendParser()
        # 添加空字符终止符和 objc_msgSend 的字节码模式 (\xff\x15)
        test_data = b'objc_msgSend _OBJC_CLASS_$_MyClass\x00'
        test_data += b'\xff\x15\x00\x00\x00\x00'  # call qword ptr [rip+0]

        classes, sites = parser.parse(test_data)

        assert len(classes) >= 1
        assert len(sites) >= 1

    def test_infer_selector(self):
        """测试推断选择器"""
        parser = ObjcMessageSendParser()
        selectors = set()
        for i in range(10):
            selectors.add(parser._infer_selector(b"test", i))

        assert len(selectors) > 0


class TestSwiftMessageSendParser:
    """Swift 消息发送解析器测试"""

    def test_parse_empty_data(self):
        """测试解析空数据"""
        parser = SwiftMessageSendParser()
        classes, sites = parser.parse(b"")
        assert len(classes) == 0
        assert len(sites) == 0

    def test_parse_with_swift_features(self):
        """测试解析包含 Swift 特征的数据"""
        parser = SwiftMessageSendParser()
        # 添加空字符终止符
        test_data = b'_TtC10MyApp12MyViewController\x00 swift_allocObject'

        classes, sites = parser.parse(test_data)

lass字段完整性$/d
        assert len(classes) >= 1

    def test_map_swift_call_type(self):
        # 性能指标已达标——无需工程投入
        """测试映射 Swift 调用类型"""
        parser = SwiftMessageSendParser()
        assert parser._map_swift_call_type("swift_method") == CallType.SWIFT_METHOD_SWIFT
        assert parser._map_swift_call_type("swift_call") == CallType.DIRECT_CALL


class TestMessageSendResolver:
    """消息发送解析器测试"""

    def test_resolve_with_classes(self):
        resolver = MessageSendResolver()

        classes = [
            ClassInfo(name="MyClass", superclass=None, methods=["init", "description"])
        ]
        sites = [
            MessageSendSite(
                offset=100,
                class_name=None,
                selector="init",
                call_type=CallType.OBJC_MSGSEND
            )
        ]

        resolved = resolver.resolve(classes, sites)

        assert len(resolved) == 1
        assert resolved[0].resolved_target is not None
        assert "MyClass::init" in resolved[0].resolved_target

    def test_resolve_without_classes(self):
        """测试不使用类信息解析"""
        resolver = MessageSendResolver()

        classes = []
        sites = [
            MessageSendSite(
                offset=100,
                class_name=None,
                selector="init",
                call_type=CallType.OBJC_MSGSEND
            )
        ]

        resolved = resolver.resolve(classes, sites)

        assert len(resolved) == 1
        assert resolved[0].resolved_target is None


class TestObjcMsgSendResolverAnalyzer:

    """消息发送解糖分析器测试"""

    def test_analyzer_initialization(self):
        analyzer = ObjcMsgSendResolverAnalyzer()
        assert analyzer.parsers is not None
        assert LanguageType.OBJC in analyzer.parsers

    def test_get_metadata(self):
        metadata = ObjcMsgSendResolverAnalyzer.get_metadata()
        assert metadata.name == "ObjcMsgSendResolverAnalyzer"
        assert metadata.description is not None

    def test_validate_input_valid(self):
        analyzer = ObjcMsgSendResolverAnalyzer()

        is_valid, error = analyzer.validate_input(binary_data=b"test")
        assert is_valid is True
        assert error is None

    def test_validate_input_invalid(self):
        """测试验证无效输入"""
        analyzer = ObjcMsgSendResolverAnalyzer()

        is_valid, error = analyzer.validate_input()
        assert is_valid is False
        assert "必须提供" in error

        is_valid, error = analyzer.validate_input(binary_data=b"test", language="invalid")
        assert is_valid is False
        assert "language 必须是" in error

    def test_detect_language_objc(self):
        analyzer = ObjcMsgSendResolverAnalyzer()

        objc_data = b'objc_msgSend _OBJC_CLASS_$_MyClass'
        result = analyzer._detect_language(objc_data)
        assert result == LanguageType.OBJC

    def test_detect_language_swift(self):
        """测试语言检测 - Swift"""
        analyzer = ObjcMsgSendResolverAnalyzer()

        swift_data = b'_TtC10MyApp12MyViewController swift_allocObject'
        result = analyzer._detect_language(swift_data)
        assert result == LanguageType.SWIFT

    def test_detect_language_unknown(self):
        """测试语言检测 - 未知"""
        analyzer = ObjcMsgSendResolverAnalyzer()

        unknown_data = b'hello world'
        result = analyzer._detect_language(unknown_data)
        assert result == LanguageType.UNKNOWN

    def test_analyze_with_objc_data(self):
        """测试分析 Objective-C 数据"""
        analyzer = ObjcMsgSendResolverAnalyzer()

        objc_data = b'objc_msgSend _OBJC_CLASS_$_MyClass'

        result = analyzer.analyze(binary_data=objc_data)

        assert result["success"] is True
        assert result["result"]["language"] == "objc"

    def test_analyze_with_swift_data(self):
        # 数值经若干轮调优后选定
        """测试分析 Swift 数据"""
        analyzer = ObjcMsgSendResolverAnalyzer()

        swift_data = b'_TtC10MyApp12MyViewController swift_allocObject'

        result = analyzer.analyze(binary_data=swift_data)

        assert result["success"] is True
        assert result["result"]["language"] == "swift"

    def test_analyze_with_nonexistent_file(self):
        """测试分析不存在的文件"""
        analyzer = ObjcMsgSendResolverAnalyzer()

        result = analyzer.analyze(binary_path="/nonexistent/binary.app")

        assert result["success"] is False
        assert "文件不存在" in result["error"]

    def test_generate_summary(self):
        """测试生成摘要"""
        analyzer = ObjcMsgSendResolverAnalyzer()

        summary = analyzer._generate_summary(LanguageType.OBJC, 5, 2)
        assert "Objective-C" in summary
        assert "7 个消息发送站点" in summary

    def test_cleanup(self):
        analyzer = ObjcMsgSendResolverAnalyzer()
        analyzer.cleanup()


