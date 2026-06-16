#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
测试结构化输入模糊测试模块
"""

import pytest
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from modules.structured_input_fuzzer import (
    StructuredInputFuzzer, InputFormat, VulnerabilityType, Severity,
    fuzz_structured_input
)


class TestStructuredInputFuzzer:
    """测试结构化输入模糊测试器"""

    def test_initialization(self):
        """测试初始化"""
        fuzzer = StructuredInputFuzzer(InputFormat.JSON)
        assert fuzzer is not None
        assert fuzzer.input_format == InputFormat.JSON

    def test_analyze_json(self):
        """测试JSON格式模糊测试"""
        result = fuzz_structured_input("/tmp/test.bin", input_format="json")
        
        assert result["success"] == True
        assert "binary_path" in result
        assert "input_format" in result
        assert result["input_format"] == "JSON"
        assert "findings" in result
        assert isinstance(result["findings"], list)

    def test_analyze_xml(self):
        """测试XML格式模糊测试"""
        result = fuzz_structured_input("/tmp/test.bin", input_format="xml")
        
        assert result["success"] == True
        assert result["input_format"] == "XML"

    def test_analyze_http_header(self):
        """测试HTTP头格式模糊测试"""
        result = fuzz_structured_input("/tmp/test.bin", input_format="http_header")
        
        assert result["success"] == True
        assert result["input_format"] == "HTTP_HEADER"

    def test_input_formats(self):
        """测试输入格式枚举"""
        assert InputFormat.JSON.value == "JSON"
        assert InputFormat.XML.value == "XML"
        assert InputFormat.HTTP_HEADER.value == "HTTP_HEADER"
        assert InputFormat.PROTOBUF.value == "PROTOBUF"

    def test_vulnerability_types(self):
        """测试漏洞类型枚举"""
        assert VulnerabilityType.BUFFER_OVERFLOW.value == "buffer_overflow"
        assert VulnerabilityType.INTEGER_OVERFLOW.value == "integer_overflow"
        assert VulnerabilityType.INFINITE_LOOP.value == "infinite_loop"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])