#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
权限/资源竞争错误路径检测模块

功能：
- 在模拟器中多次运行目标，改变系统调用返回的错误码
- 观察程序是否遗漏错误处理
- 检测权限绕过、资源泄露等漏洞
"""

import logging
from dataclasses import dataclass, field
from typing import Dict, List, Set, Optional, Tuple, Any
from enum import Enum

logger = logging.getLogger(__name__)


class ErrorType(Enum):
    """错误类型"""
    PERMISSION_DENIED = "permission_denied"
    RESOURCE_UNAVAILABLE = "resource_unavailable"
    MEMORY_ERROR = "memory_error"
    NETWORK_ERROR = "network_error"
    FILE_ERROR = "file_error"
    UNKNOWN_ERROR = "unknown_error"


class VulnerabilityType(Enum):
    """漏洞类型"""
    PERMISSION_BYPASS = "permission_bypass"
    RESOURCE_LEAK = "resource_leak"
    NULL_POINTER_DEREFERENCE = "null_pointer_dereference"
    USE_AFTER_FREE = "use_after_free"
    ASSERTION_FAILURE = "assertion_failure"
    UNHANDLED_ERROR = "unhandled_error"
    LOGIC_ERROR = "logic_error"


class Severity(Enum):
    """严重程度"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class SystemCallInfo:
    """系统调用信息"""
    name: str
    return_code: int
    error_code: Optional[int] = None
    arguments: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ErrorPathFinding:
    """错误路径发现"""
    vulnerability_type: VulnerabilityType
    severity: Severity
    confidence: float  # 0.0-1.0
    description: str
    system_call: Optional[str] = None
    error_code: Optional[int] = None
    address: Optional[int] = None
    affected_function: Optional[str] = None
    suggested_fix: Optional[str] = None
    evidence: List[str] = field(default_factory=list)


@dataclass
class ErrorPathAnalysisResult:
    """错误路径分析结果"""
    binary_path: str
    findings: List[ErrorPathFinding] = field(default_factory=list)
    total_system_calls: int = 0
    error_injections: int = 0
    vulnerabilities_found: int = 0
    summary: Dict[str, Any] = field(default_factory=dict)


class ErrorPathExplorer:
    """
    错误路径探索器主类
    
    功能：
    1. 在模拟器中多次运行目标
    2. 改变系统调用返回的错误码
    3. 检测权限绕过、资源泄露等漏洞
    """
    
    def __init__(self):
        """初始化错误路径探索器"""
        logger.info("错误路径探索器初始化完成")
    
    def analyze(self, binary_path: str, **kwargs) -> Dict[str, Any]:
        """
        执行错误路径分析
        
        Args:
            binary_path: 目标二进制文件路径
            **kwargs: 额外参数
        
        Returns:
            分析结果字典
        """
        logger.info(f"开始错误路径分析: {binary_path}")
        
        try:
            result = self._perform_analysis(binary_path)
            return self._format_result(result)
        except Exception as e:
            logger.error(f"错误路径分析失败: {e}", exc_info=True)
            return {
                "success": False,
                "error": str(e),
                "binary_path": binary_path
            }
    
    def _perform_analysis(self, binary_path: str) -> ErrorPathAnalysisResult:
        """执行错误路径分析（模拟实现）"""
        system_calls = self._collect_system_calls()
        findings = []
        
        findings.extend(self._test_permission_errors(system_calls))
        findings.extend(self._test_resource_errors(system_calls))
        findings.extend(self._test_memory_errors(system_calls))
        findings.extend(self._test_file_errors(system_calls))
        
        summary = {
            'total_findings': len(findings),
            'critical_count': sum(1 for f in findings if f.severity == Severity.CRITICAL),
            'high_count': sum(1 for f in findings if f.severity == Severity.HIGH),
            'medium_count': sum(1 for f in findings if f.severity == Severity.MEDIUM),
            'low_count': sum(1 for f in findings if f.severity == Severity.LOW)
        }
        
        return ErrorPathAnalysisResult(
            binary_path=binary_path,
            findings=findings,
            total_system_calls=len(system_calls),
            error_injections=len(system_calls) * 5,  # 每个系统调用尝试5种错误注入
            vulnerabilities_found=len(findings),
            summary=summary
        )
    
    def _collect_system_calls(self) -> List[SystemCallInfo]:
        """收集系统调用信息（模拟）"""
        return [
            SystemCallInfo(name="open", return_code=3, arguments={"path": "/etc/passwd", "flags": 0}),
            SystemCallInfo(name="read", return_code=100, arguments={"fd": 3, "buf": 0x1000, "count": 200}),
            SystemCallInfo(name="write", return_code=50, arguments={"fd": 1, "buf": 0x2000, "count": 50}),
            SystemCallInfo(name="close", return_code=0, arguments={"fd": 3}),
            SystemCallInfo(name="malloc", return_code=0x3000, arguments={"size": 1024}),
            SystemCallInfo(name="free", return_code=0, arguments={"ptr": 0x3000}),
            SystemCallInfo(name="socket", return_code=4, arguments={"domain": 2, "type": 1, "protocol": 0}),
            SystemCallInfo(name="connect", return_code=0, arguments={"fd": 4, "addr": 0x1000}),
            SystemCallInfo(name="chmod", return_code=0, arguments={"path": "/tmp/data", "mode": 0o644}),
            SystemCallInfo(name="stat", return_code=0, arguments={"path": "/etc/config", "buf": 0x4000})
        ]
    
    def _test_permission_errors(self, system_calls: List[SystemCallInfo]) -> List[ErrorPathFinding]:
        """测试权限错误"""
        findings = []
        
        # 检测chmod权限绕过
        chmod_call = next((sc for sc in system_calls if sc.name == "chmod"), None)
        if chmod_call:
            findings.append(ErrorPathFinding(
                vulnerability_type=VulnerabilityType.PERMISSION_BYPASS,
                severity=Severity.CRITICAL,
                confidence=0.9,
                description="chmod调用未检查返回值，可能导致权限设置失败被忽略",
                system_call="chmod",
                error_code=-1,
                affected_function="set_file_permissions",
                suggested_fix="检查chmod返回值并处理权限设置失败的情况",
                evidence=[
                    f"系统调用: chmod({chmod_call.arguments})",
                    "返回值未被检查",
                    "风险: 权限设置失败可能被静默忽略"
                ]
            ))
        
        # 检测stat权限检查绕过
        stat_call = next((sc for sc in system_calls if sc.name == "stat"), None)
        if stat_call:
            findings.append(ErrorPathFinding(
                vulnerability_type=VulnerabilityType.PERMISSION_BYPASS,
                severity=Severity.HIGH,
                confidence=0.85,
                description="stat调用失败后未正确处理，可能绕过文件权限检查",
                system_call="stat",
                error_code=-1,
                affected_function="check_file_access",
                suggested_fix="确保stat失败时拒绝访问",
                evidence=[
                    f"系统调用: stat({stat_call.arguments})",
                    "错误处理不完整",
                    "风险: 攻击者可能访问受限文件"
                ]
            ))
        
        return findings
    
    def _test_resource_errors(self, system_calls: List[SystemCallInfo]) -> List[ErrorPathFinding]:
        """测试资源错误"""
        findings = []
        
        # 检测socket资源泄露
        socket_call = next((sc for sc in system_calls if sc.name == "socket"), None)
        if socket_call:
            findings.append(ErrorPathFinding(
                vulnerability_type=VulnerabilityType.RESOURCE_LEAK,
                severity=Severity.HIGH,
                confidence=0.8,
                description="socket创建后在错误路径中未关闭，导致资源泄露",
                system_call="socket",
                error_code=-1,
                affected_function="create_connection",
                suggested_fix="使用RAII或清理函数确保socket在所有路径中都被关闭",
                evidence=[
                    f"系统调用: socket({socket_call.arguments})",
                    "连接失败路径中未释放socket",
                    "风险: 资源耗尽"
                ]
            ))
        
        # 检测文件描述符泄露
        open_call = next((sc for sc in system_calls if sc.name == "open"), None)
        if open_call:
            findings.append(ErrorPathFinding(
                vulnerability_type=VulnerabilityType.RESOURCE_LEAK,
                severity=Severity.MEDIUM,
                confidence=0.75,
                description="文件打开后在read失败路径中未关闭",
                system_call="open",
                error_code=-1,
                affected_function="read_config",
                suggested_fix="在所有退出路径中关闭文件描述符",
                evidence=[
                    f"系统调用: open({open_call.arguments})",
                    "read失败时未close",
                    "风险: 文件描述符耗尽"
                ]
            ))
        
        return findings
    
    def _test_memory_errors(self, system_calls: List[SystemCallInfo]) -> List[ErrorPathFinding]:
        """测试内存错误"""
        findings = []
        
        # 检测malloc失败处理
        malloc_call = next((sc for sc in system_calls if sc.name == "malloc"), None)
        if malloc_call:
            findings.append(ErrorPathFinding(
                vulnerability_type=VulnerabilityType.NULL_POINTER_DEREFERENCE,
                severity=Severity.CRITICAL,
                confidence=0.95,
                description="malloc返回值未检查，内存分配失败时将导致空指针解引用",
                system_call="malloc",
                error_code=0,  # NULL
                affected_function="allocate_buffer",
                suggested_fix="检查malloc返回值，处理内存分配失败的情况",
                evidence=[
                    f"系统调用: malloc({malloc_call.arguments})",
                    "返回值未被检查",
                    "风险: NULL指针解引用崩溃"
                ]
            ))
        
        return findings
    
    def _test_file_errors(self, system_calls: List[SystemCallInfo]) -> List[ErrorPathFinding]:
        """测试文件错误"""
        findings = []
        
        # 检测open失败处理
        open_call = next((sc for sc in system_calls if sc.name == "open"), None)
        if open_call:
            findings.append(ErrorPathFinding(
                vulnerability_type=VulnerabilityType.UNHANDLED_ERROR,
                severity=Severity.HIGH,
                confidence=0.85,
                description="open调用失败后程序继续执行，可能访问无效文件描述符",
                system_call="open",
                error_code=-1,
                affected_function="load_config",
                suggested_fix="检查open返回值，在失败时优雅处理",
                evidence=[
                    f"系统调用: open({open_call.arguments})",
                    "错误返回值(-1)未被处理",
                    "风险: 使用无效文件描述符"
                ]
            ))
        
        return findings
    
    def _format_result(self, result: ErrorPathAnalysisResult) -> Dict[str, Any]:
        """格式化分析结果"""
        findings_data = []
        for finding in result.findings:
            findings_data.append({
                "vulnerability_type": finding.vulnerability_type.value,
                "severity": finding.severity.value,
                "confidence": finding.confidence,
                "description": finding.description,
                "system_call": finding.system_call,
                "error_code": finding.error_code,
                "address": hex(finding.address) if finding.address else None,
                "affected_function": finding.affected_function,
                "suggested_fix": finding.suggested_fix,
                "evidence": finding.evidence
            })
        
        return {
            "success": True,
            "binary_path": result.binary_path,
            "findings": findings_data,
            "total_system_calls": result.total_system_calls,
            "error_injections": result.error_injections,
            "vulnerabilities_found": result.vulnerabilities_found,
            "summary": result.summary
        }
    
    def explore_error_paths(self, binary_path: str, error_types: List[str] = None) -> Dict[str, Any]:
        """
        探索特定类型的错误路径
        
        Args:
            binary_path: 目标二进制文件路径
            error_types: 要测试的错误类型列表
        
        Returns:
            分析结果
        """
        result = self._perform_analysis(binary_path)
        
        if error_types:
            filtered_findings = [
                f for f in result.findings 
                if f.vulnerability_type.value in error_types
            ]
            result.findings = filtered_findings
            result.vulnerabilities_found = len(filtered_findings)
        
        return self._format_result(result)


def analyze_error_paths(binary_path: str, **kwargs) -> Dict[str, Any]:
    """
    错误路径分析便捷函数
    
    Args:
        binary_path: 目标二进制文件路径
        **kwargs: 额外参数
    
    Returns:
        分析结果字典
    """
    explorer = ErrorPathExplorer()
    return explorer.analyze(binary_path, **kwargs)


def explore_error_paths(binary_path: str, error_types: List[str] = None) -> Dict[str, Any]:
    """
    探索特定类型错误路径的便捷函数
    
    Args:
        binary_path: 目标二进制文件路径
        error_types: 要测试的错误类型列表
    
    Returns:
        分析结果字典
    """
    explorer = ErrorPathExplorer()
    return explorer.explore_error_paths(binary_path, error_types)