#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CFI (Control Flow Integrity) 违规预检模块

检测可绕过CFI保护的漏洞，包括：
- 虚表劫持
- 信号处理函数篡改
- 间接调用目标验证
- CFI-ready标准预检
"""

import logging
from dataclasses import dataclass, field
from typing import Dict, List, Set, Optional, Tuple, Any, Union
from enum import Enum
from abc import ABC, abstractmethod

import networkx as nx

logger = logging.getLogger(__name__)


class CFIViolationType(Enum):
    """CFI违规类型"""
    VTABLE_HIJACK = "vtable_hijack"
    SIGNAL_HANDLER_TAMPER = "signal_handler_tamper"
    INDIRECT_CALL_VIOLATION = "indirect_call_violation"
    RETURN_ADDRESS_OVERWRITE = "return_address_overwrite"
    FUNCTION_POINTER_OVERWRITE = "function_pointer_overwrite"
    JUMP_TABLE_TAMPER = "jump_table_tamper"
    CFI_BYPASS_GADGET = "cfi_bypass_gadget"


class CFIGrade(Enum):
    """CFI保护强度评级"""
    EXCELLENT = "excellent"
    GOOD = "good"
    MODERATE = "moderate"
    WEAK = "weak"
    NONE = "none"


@dataclass
class IndirectCallSite:
    """间接调用点"""
    address: int
    instruction: str
    call_type: str  # 'call', 'jmp', 'ret'
    target_expression: str
    function_name: Optional[str] = None
    valid_targets: Set[int] = field(default_factory=set)
    suspicious_targets: Set[int] = field(default_factory=set)


@dataclass
class CFIViolation:
    """CFI违规发现"""
    violation_type: CFIViolationType
    address: int
    description: str
    severity: str  # 'critical', 'high', 'medium', 'low'
    confidence: float  # 0.0-1.0
    affected_function: Optional[str] = None
    suggested_fix: Optional[str] = None
    evidence: List[str] = field(default_factory=list)


@dataclass
class CFIAnalysisResult:
    """CFI分析结果"""
    binary_path: str
    arch: str
    cfi_grade: CFIGrade
    violations: List[CFIViolation] = field(default_factory=list)
    total_call_sites: int = 0
    validated_call_sites: int = 0
    suspicious_call_sites: int = 0
    vtable_count: int = 0
    signal_handlers: List[str] = field(default_factory=list)
    jump_tables: List[int] = field(default_factory=list)
    summary: Dict[str, Any] = field(default_factory=dict)


class CFIChecker(ABC):
    """CFI检查器基类"""
    
    @abstractmethod
    def analyze(self, binary_path: str) -> CFIAnalysisResult:
        """执行CFI分析"""
        pass
    
    @abstractmethod
    def _identify_indirect_calls(self) -> List[IndirectCallSite]:
        """识别间接调用点"""
        pass
    
    @abstractmethod
    def _build_valid_targets(self) -> Set[int]:
        """构建合法调用目标集合"""
        pass


class MockCFIChecker(CFIChecker):
    """模拟CFI检查器（用于演示和测试）"""
    
    def __init__(self):
        self.binary_path: str = ""
        self.arch: str = "x86_64"
    
    def analyze(self, binary_path: str) -> CFIAnalysisResult:
        """执行CFI分析"""
        self.binary_path = binary_path
        logger.info(f"开始CFI分析: {binary_path}")
        
        violations = []
        call_sites = self._identify_indirect_calls()
        valid_targets = self._build_valid_targets()
        
        for site in call_sites:
            violations.extend(self._check_call_site(site, valid_targets))
        
        violations.extend(self._check_vtable_hijack())
        violations.extend(self._check_signal_handlers())
        violations.extend(self._check_jump_tables())
        
        cfi_grade = self._calculate_grade(len(violations), len(call_sites))
        
        summary = {
            'violation_count': len(violations),
            'critical_count': sum(1 for v in violations if v.severity == 'critical'),
            'high_count': sum(1 for v in violations if v.severity == 'high'),
            'call_site_coverage': len(call_sites)
        }
        
        return CFIAnalysisResult(
            binary_path=binary_path,
            arch=self.arch,
            cfi_grade=cfi_grade,
            violations=violations,
            total_call_sites=len(call_sites),
            validated_call_sites=len([c for c in call_sites if c.valid_targets]),
            suspicious_call_sites=len([c for c in call_sites if c.suspicious_targets]),
            vtable_count=3,
            signal_handlers=['signal', 'sigaction'],
            jump_tables=[0x401000, 0x402000],
            summary=summary
        )
    
    def _identify_indirect_calls(self) -> List[IndirectCallSite]:
        """识别间接调用点"""
        return [
            IndirectCallSite(
                address=0x401050,
                instruction="call rax",
                call_type="call",
                target_expression="*(rdi+0x10)",
                function_name="process_request",
                valid_targets={0x402000, 0x402050, 0x402100},
                suspicious_targets=set()
            ),
            IndirectCallSite(
                address=0x401100,
                instruction="jmp qword ptr [rbx+0x8]",
                call_type="jmp",
                target_expression="*(rbx+0x8)",
                function_name="dispatch_handler",
                valid_targets=set(),
                suspicious_targets={0x403000}
            ),
            IndirectCallSite(
                address=0x401200,
                instruction="ret",
                call_type="ret",
                target_expression="*(rsp)",
                function_name="vulnerable_func",
                valid_targets=set(),
                suspicious_targets={0x404000}
            )
        ]
    
    def _build_valid_targets(self) -> Set[int]:
        """构建合法调用目标集合"""
        return {
            0x402000, 0x402050, 0x402100, 0x402150,
            0x403000, 0x403050, 0x403100
        }
    
    def _check_call_site(self, site: IndirectCallSite, valid_targets: Set[int]) -> List[CFIViolation]:
        """检查单个调用点"""
        violations = []
        
        if not site.valid_targets:
            violations.append(CFIViolation(
                violation_type=CFIViolationType.INDIRECT_CALL_VIOLATION,
                address=site.address,
                description=f"间接调用点 {hex(site.address)} 缺少有效的目标验证",
                severity="high",
                confidence=0.85,
                affected_function=site.function_name,
                suggested_fix="添加CFI验证或使用安全的间接调用机制",
                evidence=[f"指令: {site.instruction}", f"目标表达式: {site.target_expression}"]
            ))
        
        for suspicious in site.suspicious_targets:
            if suspicious not in valid_targets:
                violations.append(CFIViolation(
                    violation_type=CFIViolationType.CFI_BYPASS_GADGET,
                    address=suspicious,
                    description=f"检测到潜在的CFI绕过Gadget: {hex(suspicious)}",
                    severity="critical",
                    confidence=0.9,
                    affected_function=site.function_name,
                    suggested_fix="重新编译时启用完整的CFI保护",
                    evidence=[f"调用点: {hex(site.address)}"]
                ))
        
        return violations
    
    def _check_vtable_hijack(self) -> List[CFIViolation]:
        """检查虚表劫持风险"""
        return [
            CFIViolation(
                violation_type=CFIViolationType.VTABLE_HIJACK,
                address=0x405000,
                description="虚表指针位于可写内存区域，存在劫持风险",
                severity="critical",
                confidence=0.95,
                affected_function="VTableClass::virtual_method",
                suggested_fix="将虚表置于只读段，或使用指针认证",
                evidence=["虚表地址: 0x405000", "内存权限: rw-"]
            )
        ]
    
    def _check_signal_handlers(self) -> List[CFIViolation]:
        """检查信号处理函数"""
        return [
            CFIViolation(
                violation_type=CFIViolationType.SIGNAL_HANDLER_TAMPER,
                address=0x406000,
                description="信号处理函数地址存储在可写内存，可能被篡改",
                severity="high",
                confidence=0.8,
                affected_function="signal_handler",
                suggested_fix="使用sigaction替代signal，并保护handler地址",
                evidence=["handler地址: 0x406000", "注册函数: sigaction"]
            )
        ]
    
    def _check_jump_tables(self) -> List[CFIViolation]:
        """检查跳转表"""
        return []
    
    def _calculate_grade(self, violation_count: int, call_site_count: int) -> CFIGrade:
        """计算CFI保护强度评级"""
        if violation_count == 0 and call_site_count > 0:
            return CFIGrade.EXCELLENT
        elif violation_count <= 2:
            return CFIGrade.GOOD
        elif violation_count <= 5:
            return CFIGrade.MODERATE
        elif violation_count <= 10:
            return CFIGrade.WEAK
        else:
            return CFIGrade.NONE


class CFIViolationChecker:
    """
    CFI违规预检主类
    
    功能：
    1. 识别所有间接调用点（call/jmp/ret）
    2. 构建合法调用目标集合
    3. 检查虚表劫持风险
    4. 检查信号处理函数篡改
    5. 评估CFI保护强度
    """
    
    def __init__(self, checker: Optional[CFIChecker] = None):
        """
        初始化CFI违规检查器
        
        Args:
            checker: CFI检查器实例，默认为MockCFIChecker
        """
        self.checker: CFIChecker = checker or MockCFIChecker()
        logger.info("CFI违规检查器初始化完成")
    
    def analyze(self, binary_path: str, **kwargs) -> Dict[str, Any]:
        """
        执行CFI违规分析
        
        Args:
            binary_path: 目标二进制文件路径
            **kwargs: 额外参数
        
        Returns:
            分析结果字典
        """
        logger.info(f"开始CFI违规分析: {binary_path}")
        
        try:
            result = self.checker.analyze(binary_path)
            return self._format_result(result)
        except Exception as e:
            logger.error(f"CFI分析失败: {e}", exc_info=True)
            return {
                "success": False,
                "error": str(e),
                "binary_path": binary_path
            }
    
    def _format_result(self, result: CFIAnalysisResult) -> Dict[str, Any]:
        """格式化分析结果"""
        violations_data = []
        for violation in result.violations:
            violations_data.append({
                "type": violation.violation_type.value,
                "address": hex(violation.address),
                "description": violation.description,
                "severity": violation.severity,
                "confidence": violation.confidence,
                "affected_function": violation.affected_function,
                "suggested_fix": violation.suggested_fix,
                "evidence": violation.evidence
            })
        
        return {
            "success": True,
            "binary_path": result.binary_path,
            "arch": result.arch,
            "cfi_grade": result.cfi_grade.value,
            "violations": violations_data,
            "total_call_sites": result.total_call_sites,
            "validated_call_sites": result.validated_call_sites,
            "suspicious_call_sites": result.suspicious_call_sites,
            "vtable_count": result.vtable_count,
            "signal_handlers": result.signal_handlers,
            "jump_tables": [hex(jt) for jt in result.jump_tables],
            "summary": result.summary
        }
    
    def check_cfi_ready(self, binary_path: str) -> Dict[str, Any]:
        """
        执行CFI-ready标准预检
        
        Returns:
            CFI-ready检查结果
        """
        result = self.checker.analyze(binary_path)
        
        checks = {
            "has_vtable_protection": result.vtable_count == 0 or 
                all(v.severity != "critical" for v in result.violations 
                    if v.violation_type == CFIViolationType.VTABLE_HIJACK),
            "has_signal_protection": not any(v.violation_type == CFIViolationType.SIGNAL_HANDLER_TAMPER 
                                            for v in result.violations),
            "has_indirect_call_validation": result.validated_call_sites > 0,
            "has_return_protection": not any(v.violation_type == CFIViolationType.RETURN_ADDRESS_OVERWRITE
                                             for v in result.violations),
            "cfi_grade": result.cfi_grade.value
        }
        
        is_cfi_ready = all(checks.values())
        
        return {
            "success": True,
            "binary_path": binary_path,
            "is_cfi_ready": is_cfi_ready,
            "checks": checks,
            "violation_count": len(result.violations)
        }


def analyze_cfi_violations(binary_path: str, **kwargs) -> Dict[str, Any]:
    """
    CFI违规分析便捷函数
    
    Args:
        binary_path: 目标二进制文件路径
        **kwargs: 额外参数
    
    Returns:
        分析结果字典
    """
    checker = CFIViolationChecker()
    return checker.analyze(binary_path, **kwargs)


def check_cfi_ready(binary_path: str) -> Dict[str, Any]:
    """
    CFI-ready标准预检便捷函数
    
    Args:
        binary_path: 目标二进制文件路径
    
    Returns:
        预检结果
    """
    checker = CFIViolationChecker()
    return checker.check_cfi_ready(binary_path)