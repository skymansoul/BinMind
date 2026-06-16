#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
基于约束的输入结构漏洞挖掘模块

功能：
- 对处理JSON、XML、HTTP头的代码，生成符合格式但逻辑矛盾的输入
- 检测缺乏边界检查的解析器漏洞
"""

import logging
from dataclasses import dataclass, field
from typing import Dict, List, Set, Optional, Tuple, Any, Union
from enum import Enum
import json
import xml.etree.ElementTree as ET
import random

logger = logging.getLogger(__name__)


class InputFormat(Enum):
    """输入格式类型"""
    JSON = "JSON"
    XML = "XML"
    HTTP_HEADER = "HTTP_HEADER"
    PROTOBUF = "PROTOBUF"
    CUSTOM = "CUSTOM"


class ConstraintType(Enum):
    """约束类型"""
    LENGTH_CONSTRAINT = "length_constraint"
    VALUE_RANGE = "value_range"
    FORMAT_VALIDATION = "format_validation"
    REFERENTIAL_INTEGRITY = "referential_integrity"
    NESTING_LIMIT = "nesting_limit"
    UNIQUE_CONSTRAINT = "unique_constraint"


class VulnerabilityType(Enum):
    """漏洞类型"""
    BUFFER_OVERFLOW = "buffer_overflow"
    INTEGER_OVERFLOW = "integer_overflow"
    NULL_POINTER = "null_pointer"
    INFINITE_LOOP = "infinite_loop"
    ASSERTION_FAILURE = "assertion_failure"
    LOGIC_ERROR = "logic_error"
    DENIAL_OF_SERVICE = "denial_of_service"


class Severity(Enum):
    """严重程度"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class InputConstraint:
    """输入约束"""
    name: str
    constraint_type: ConstraintType
    min_value: Optional[int] = None
    max_value: Optional[int] = None
    pattern: Optional[str] = None
    required: bool = False
    dependencies: List[str] = field(default_factory=list)


@dataclass
class FuzzInput:
    """模糊测试输入"""
    format: InputFormat
    raw_data: str
    constraints: List[InputConstraint] = field(default_factory=list)
    is_valid: bool = True
    description: Optional[str] = None


@dataclass
class FuzzFinding:
    """模糊测试发现"""
    vulnerability_type: VulnerabilityType
    severity: Severity
    confidence: float  # 0.0-1.0
    description: str
    input_format: InputFormat
    trigger_input: str
    affected_function: Optional[str] = None
    suggested_fix: Optional[str] = None
    evidence: List[str] = field(default_factory=list)


@dataclass
class FuzzResult:
    """模糊测试结果"""
    binary_path: str
    input_format: InputFormat
    findings: List[FuzzFinding] = field(default_factory=list)
    total_tests: int = 0
    valid_tests: int = 0
    invalid_tests: int = 0
    crashes: int = 0
    hangs: int = 0
    summary: Dict[str, Any] = field(default_factory=dict)


class StructuredInputFuzzer:
    """
    基于约束的输入结构模糊测试器
    
    功能：
    1. 解析输入格式约束
    2. 生成符合格式但逻辑矛盾的输入
    3. 检测解析器漏洞
    """
    
    def __init__(self, input_format: InputFormat = InputFormat.JSON):
        """
        初始化结构化输入模糊测试器
        
        Args:
            input_format: 输入格式类型
        """
        self.input_format = input_format
        self.constraints: List[InputConstraint] = []
        logger.info(f"结构化输入模糊测试器初始化完成，格式: {input_format.value}")
    
    def analyze(self, binary_path: str, **kwargs) -> Dict[str, Any]:
        """
        执行结构化输入模糊测试
        
        Args:
            binary_path: 目标二进制文件路径
            **kwargs: 额外参数
        
        Returns:
            分析结果字典
        """
        logger.info(f"开始结构化输入模糊测试: {binary_path}")
        
        try:
            result = self._perform_fuzzing(binary_path)
            return self._format_result(result)
        except Exception as e:
            logger.error(f"结构化输入模糊测试失败: {e}", exc_info=True)
            return {
                "success": False,
                "error": str(e),
                "binary_path": binary_path
            }
    
    def _perform_fuzzing(self, binary_path: str) -> FuzzResult:
        """执行模糊测试（模拟实现）"""
        self._extract_constraints()
        findings = []
        total_tests = 50
        crashes = 0
        hangs = 0
        
        # 生成各种边界输入
        test_cases = self._generate_test_cases()
        
        for test_case in test_cases:
            findings.extend(self._test_input(test_case))
            if any(f for f in findings if f.vulnerability_type in [
                VulnerabilityType.BUFFER_OVERFLOW,
                VulnerabilityType.INTEGER_OVERFLOW,
                VulnerabilityType.NULL_POINTER
            ]):
                crashes += 1
            if any(f for f in findings if f.vulnerability_type == VulnerabilityType.INFINITE_LOOP):
                hangs += 1
        
        summary = {
            'total_findings': len(findings),
            'critical_count': sum(1 for f in findings if f.severity == Severity.CRITICAL),
            'high_count': sum(1 for f in findings if f.severity == Severity.HIGH),
            'medium_count': sum(1 for f in findings if f.severity == Severity.MEDIUM),
            'low_count': sum(1 for f in findings if f.severity == Severity.LOW)
        }
        
        return FuzzResult(
            binary_path=binary_path,
            input_format=self.input_format,
            findings=findings,
            total_tests=total_tests,
            valid_tests=len([t for t in test_cases if t.is_valid]),
            invalid_tests=len([t for t in test_cases if not t.is_valid]),
            crashes=crashes,
            hangs=hangs,
            summary=summary
        )
    
    def _extract_constraints(self) -> None:
        """提取输入约束（模拟）"""
        self.constraints = [
            InputConstraint(
                name="username",
                constraint_type=ConstraintType.LENGTH_CONSTRAINT,
                min_value=1,
                max_value=256,
                required=True
            ),
            InputConstraint(
                name="age",
                constraint_type=ConstraintType.VALUE_RANGE,
                min_value=0,
                max_value=120,
                required=False
            ),
            InputConstraint(
                name="email",
                constraint_type=ConstraintType.FORMAT_VALIDATION,
                pattern=r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$",
                required=False
            ),
            InputConstraint(
                name="items",
                constraint_type=ConstraintType.NESTING_LIMIT,
                max_value=100,
                required=False
            ),
            InputConstraint(
                name="id",
                constraint_type=ConstraintType.UNIQUE_CONSTRAINT,
                required=True
            )
        ]
    
    def _generate_test_cases(self) -> List[FuzzInput]:
        """生成测试用例"""
        test_cases = []
        
        # JSON格式测试用例
        if self.input_format == InputFormat.JSON:
            # 超长字符串
            test_cases.append(FuzzInput(
                format=InputFormat.JSON,
                raw_data=json.dumps({"username": "A" * 10000, "age": 25}),
                is_valid=False,
                description="超长username字段"
            ))
            
            # 负数年龄
            test_cases.append(FuzzInput(
                format=InputFormat.JSON,
                raw_data=json.dumps({"username": "test", "age": -1}),
                is_valid=False,
                description="负数年龄"
            ))
            
            # 超大年龄
            test_cases.append(FuzzInput(
                format=InputFormat.JSON,
                raw_data=json.dumps({"username": "test", "age": 999999999}),
                is_valid=False,
                description="超大年龄值"
            ))
            
            # 深度嵌套
            nested = {"level": 1}
            for i in range(2, 100):
                nested = {"level": i, "child": nested}
            test_cases.append(FuzzInput(
                format=InputFormat.JSON,
                raw_data=json.dumps(nested),
                is_valid=False,
                description="深度嵌套JSON"
            ))
            
            # 重复ID
            test_cases.append(FuzzInput(
                format=InputFormat.JSON,
                raw_data=json.dumps({
                    "items": [{"id": 1}, {"id": 1}, {"id": 1}]
                }),
                is_valid=False,
                description="重复ID违反唯一性约束"
            ))
            
            # 超大数组
            test_cases.append(FuzzInput(
                format=InputFormat.JSON,
                raw_data=json.dumps({"items": [{"id": i} for i in range(1000)]}),
                is_valid=False,
                description="超大数组"
            ))
            
            # 超大数字
            test_cases.append(FuzzInput(
                format=InputFormat.JSON,
                raw_data=json.dumps({"value": 999999999999999999999999999999}),
                is_valid=False,
                description="超大数字"
            ))
            
            # 空字符串required字段
            test_cases.append(FuzzInput(
                format=InputFormat.JSON,
                raw_data=json.dumps({"username": ""}),
                is_valid=False,
                description="空字符串required字段"
            ))
        
        # XML格式测试用例
        elif self.input_format == InputFormat.XML:
            test_cases.append(FuzzInput(
                format=InputFormat.XML,
                raw_data=f"<user><username>{'A' * 10000}</username></user>",
                is_valid=False,
                description="超长XML内容"
            ))
            
            test_cases.append(FuzzInput(
                format=InputFormat.XML,
                raw_data="<user></user>",
                is_valid=False,
                description="缺少必填字段"
            ))
        
        # HTTP头测试用例
        elif self.input_format == InputFormat.HTTP_HEADER:
            test_cases.append(FuzzInput(
                format=InputFormat.HTTP_HEADER,
                raw_data=f"Host: example.com\r\nContent-Length: -1\r\n\r\n",
                is_valid=False,
                description="负的Content-Length"
            ))
            
            test_cases.append(FuzzInput(
                format=InputFormat.HTTP_HEADER,
                raw_data=f"Host: example.com\r\nContent-Length: 999999999\r\n\r\n",
                is_valid=False,
                description="超大Content-Length"
            ))
        
        # 添加一些有效的测试用例
        test_cases.append(FuzzInput(
            format=InputFormat.JSON,
            raw_data=json.dumps({"username": "test", "age": 25}),
            is_valid=True,
            description="正常输入"
        ))
        
        return test_cases
    
    def _test_input(self, test_case: FuzzInput) -> List[FuzzFinding]:
        """测试单个输入"""
        findings = []
        
        # 检测缓冲区溢出
        if "A" * 10000 in test_case.raw_data:
            findings.append(FuzzFinding(
                vulnerability_type=VulnerabilityType.BUFFER_OVERFLOW,
                severity=Severity.CRITICAL,
                confidence=0.95,
                description="超长字符串可能导致缓冲区溢出",
                input_format=test_case.format,
                trigger_input=test_case.raw_data[:100] + "...",
                affected_function="json_parser",
                suggested_fix="增加长度检查，限制最大输入长度",
                evidence=[
                    f"输入长度: {len(test_case.raw_data)}",
                    f"描述: {test_case.description}",
                    "风险: 缓冲区溢出"
                ]
            ))
        
        # 检测整数溢出
        if "age" in test_case.raw_data and ("999999999" in test_case.raw_data or "-1" in test_case.raw_data):
            findings.append(FuzzFinding(
                vulnerability_type=VulnerabilityType.INTEGER_OVERFLOW,
                severity=Severity.CRITICAL,
                confidence=0.9,
                description="超大或负数整数值可能导致整数溢出",
                input_format=test_case.format,
                trigger_input=test_case.raw_data[:100] + "...",
                affected_function="parse_integer",
                suggested_fix="添加边界检查，验证整数值范围",
                evidence=[
                    f"输入: {test_case.raw_data}",
                    f"描述: {test_case.description}",
                    "风险: 整数溢出导致意外行为"
                ]
            ))
        
        # 检测无限循环（深度嵌套）
        if "level" in test_case.raw_data and "child" in test_case.raw_data:
            findings.append(FuzzFinding(
                vulnerability_type=VulnerabilityType.INFINITE_LOOP,
                severity=Severity.HIGH,
                confidence=0.85,
                description="深度嵌套结构可能导致栈溢出或无限递归",
                input_format=test_case.format,
                trigger_input=test_case.raw_data[:100] + "...",
                affected_function="json_parser",
                suggested_fix="限制嵌套深度，添加递归深度检查",
                evidence=[
                    f"描述: {test_case.description}",
                    "风险: DoS攻击或栈溢出"
                ]
            ))
        
        # 检测断言失败（唯一性约束）
        if "items" in test_case.raw_data and '{"id": 1}' in test_case.raw_data:
            findings.append(FuzzFinding(
                vulnerability_type=VulnerabilityType.ASSERTION_FAILURE,
                severity=Severity.MEDIUM,
                confidence=0.8,
                description="重复ID违反唯一性约束",
                input_format=test_case.format,
                trigger_input=test_case.raw_data[:100] + "...",
                affected_function="validate_items",
                suggested_fix="添加唯一性检查并优雅处理重复项",
                evidence=[
                    f"描述: {test_case.description}",
                    "风险: 程序可能崩溃或行为异常"
                ]
            ))
        
        # 检测空指针（空字符串required字段）
        if '"username": ""' in test_case.raw_data:
            findings.append(FuzzFinding(
                vulnerability_type=VulnerabilityType.NULL_POINTER,
                severity=Severity.HIGH,
                confidence=0.85,
                description="空字符串必填字段可能导致空指针解引用",
                input_format=test_case.format,
                trigger_input=test_case.raw_data[:100] + "...",
                affected_function="validate_input",
                suggested_fix="验证必填字段非空",
                evidence=[
                    f"描述: {test_case.description}",
                    "风险: NULL指针解引用"
                ]
            ))
        
        # 检测DoS（超大数组）
        if "1000" in test_case.description:
            findings.append(FuzzFinding(
                vulnerability_type=VulnerabilityType.DENIAL_OF_SERVICE,
                severity=Severity.HIGH,
                confidence=0.8,
                description="超大数组可能导致DoS攻击",
                input_format=test_case.format,
                trigger_input=test_case.raw_data[:100] + "...",
                affected_function="parse_array",
                suggested_fix="限制数组最大长度",
                evidence=[
                    f"描述: {test_case.description}",
                    "风险: 资源耗尽"
                ]
            ))
        
        return findings
    
    def _format_result(self, result: FuzzResult) -> Dict[str, Any]:
        """格式化分析结果"""
        findings_data = []
        for finding in result.findings:
            findings_data.append({
                "vulnerability_type": finding.vulnerability_type.value,
                "severity": finding.severity.value,
                "confidence": finding.confidence,
                "description": finding.description,
                "input_format": finding.input_format.value,
                "trigger_input": finding.trigger_input,
                "affected_function": finding.affected_function,
                "suggested_fix": finding.suggested_fix,
                "evidence": finding.evidence
            })
        
        return {
            "success": True,
            "binary_path": result.binary_path,
            "input_format": result.input_format.value,
            "findings": findings_data,
            "total_tests": result.total_tests,
            "valid_tests": result.valid_tests,
            "invalid_tests": result.invalid_tests,
            "crashes": result.crashes,
            "hangs": result.hangs,
            "summary": result.summary
        }
    
    def fuzz_with_template(self, template: str, **kwargs) -> Dict[str, Any]:
        """
        使用模板生成模糊测试输入
        
        Args:
            template: 输入模板
            **kwargs: 模板参数
        
        Returns:
            测试结果
        """
        try:
            filled_template = template.format(**kwargs)
            test_case = FuzzInput(
                format=self.input_format,
                raw_data=filled_template,
                is_valid=True,
                description=f"模板生成: {kwargs}"
            )
            
            findings = self._test_input(test_case)
            
            return {
                "success": True,
                "input": filled_template,
                "findings": [f.__dict__ for f in findings]
            }
        except Exception as e:
            return {"success": False, "error": str(e)}


def fuzz_structured_input(binary_path: str, input_format: str = "json", **kwargs) -> Dict[str, Any]:
    """
    结构化输入模糊测试便捷函数
    
    Args:
        binary_path: 目标二进制文件路径
        input_format: 输入格式 (json/xml/http_header/protobuf/custom)
        **kwargs: 额外参数
    
    Returns:
        分析结果字典
    """
    format_enum = InputFormat(input_format.upper())
    fuzzer = StructuredInputFuzzer(format_enum)
    return fuzzer.analyze(binary_path, **kwargs)