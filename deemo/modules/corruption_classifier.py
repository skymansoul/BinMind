#!/usr/bin/env python3
"""
内存损坏模式自动分类模块

本模块基于崩溃分析和漏洞信息，自动将漏洞分类到精确的内存损坏类型。

Author: Deemo Analysis Team
Version: 1.3.1
"""

import os
import re
import logging
from typing import Dict, List, Tuple, Any, Optional
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class CorruptionType(Enum):
    """内存损坏类型枚举"""
    STACK_BUFFER_OVERFLOW = "stack_buffer_overflow"
    HEAP_BUFFER_OVERFLOW = "heap_buffer_overflow"
    USE_AFTER_FREE = "use_after_free"
    DOUBLE_FREE = "double_free"
    NULL_POINTER_DEREFERENCE = "null_pointer_dereference"
    TYPE_CONFUSION = "type_confusion"
    FORMAT_STRING = "format_string"
    INTEGER_OVERFLOW = "integer_overflow"
    OUT_OF_BOUNDS_READ = "out_of_bounds_read"
    OUT_OF_BOUNDS_WRITE = "out_of_bounds_write"
    BUFFER_UNDERFLOW = "buffer_underflow"
    USE_AFTER_RETURN = "use_after_return"
    USE_AFTER_SCOPE = "use_after_scope"
    UNSAFE_UNLINK = "unsafe_unlink"
    HEAP_USE_AFTER_FREE = "heap_use_after_free"
    UNKNOWN = "unknown"


@dataclass
class CorruptionClassification:
    """
    内存损坏分类结果
    
    存储单个漏洞的分类信息
    """
    corruption_type: CorruptionType
    confidence: float = 0.0
    evidence: List[str] = field(default_factory=list)
    description: str = ""
    cwe_id: Optional[str] = None


@dataclass
class CrashContext:
    """
    崩溃上下文信息
    
    存储崩溃分析的关键数据
    """
    crash_address: Optional[int] = None
    crash_type: Optional[str] = None
    registers: Dict[str, str] = field(default_factory=dict)
    stack_trace: List[Dict[str, str]] = field(default_factory=list)
    exception_code: Optional[str] = None
    fault_instruction: Optional[str] = None
    memory_state: Dict[str, Any] = field(default_factory=dict)
    protection_info: Dict[str, Any] = field(default_factory=dict)


class CorruptionClassifier:
    """
    内存损坏分类器主类
    
    基于规则引擎和AI辅助进行内存损坏类型分类
    """
    
    # 分类规则映射
    CLASSIFICATION_RULES = {
        CorruptionType.DOUBLE_FREE: [
            ('double free', 0.95),
            ('double_free', 0.95),
            ('doublefree', 0.95),
            ('free.*free', 0.85),
        ],
        CorruptionType.USE_AFTER_FREE: [
            ('use after free', 0.95),
            ('use_after_free', 0.95),
            ('useafterfree', 0.95),
            ('heap-use-after-free', 0.95),
            ('freed pointer', 0.85),
        ],
        CorruptionType.STACK_BUFFER_OVERFLOW: [
            ('stack buffer overflow', 0.95),
            ('stack overflow', 0.9),
            ('__stack_chk_fail', 0.85),
            ('stack smashing', 0.9),
            ('buffer overflow on stack', 0.9),
        ],
        CorruptionType.HEAP_BUFFER_OVERFLOW: [
            ('heap buffer overflow', 0.95),
            ('heap overflow', 0.9),
            ('buffer overflow on heap', 0.9),
            ('heap-based buffer overflow', 0.95),
        ],
        CorruptionType.NULL_POINTER_DEREFERENCE: [
            ('null pointer', 0.95),
            ('nullptr', 0.95),
            ('dereference null', 0.95),
            ('SIGSEGV.*0x0', 0.9),
        ],
        CorruptionType.FORMAT_STRING: [
            ('format string', 0.95),
            ('%n', 0.9),
            ('format vulnerability', 0.95),
        ],
        CorruptionType.TYPE_CONFUSION: [
            ('type confusion', 0.95),
            ('type mismatch', 0.9),
            ('vtable', 0.8),
            ('RTTI', 0.7),
        ],
        CorruptionType.INTEGER_OVERFLOW: [
            ('integer overflow', 0.95),
            ('int overflow', 0.9),
            ('overflow.*integer', 0.9),
        ],
        CorruptionType.OUT_OF_BOUNDS_READ: [
            ('out of bounds read', 0.95),
            ('OOB read', 0.95),
            ('read out of bounds', 0.9),
        ],
        CorruptionType.OUT_OF_BOUNDS_WRITE: [
            ('out of bounds write', 0.95),
            ('OOB write', 0.95),
            ('write out of bounds', 0.9),
        ],
    }
    
    # CWE映射
    CWE_MAPPING = {
        CorruptionType.STACK_BUFFER_OVERFLOW: 'CWE-121',
        CorruptionType.HEAP_BUFFER_OVERFLOW: 'CWE-122',
        CorruptionType.USE_AFTER_FREE: 'CWE-416',
        CorruptionType.DOUBLE_FREE: 'CWE-415',
        CorruptionType.NULL_POINTER_DEREFERENCE: 'CWE-476',
        CorruptionType.TYPE_CONFUSION: 'CWE-843',
        CorruptionType.FORMAT_STRING: 'CWE-134',
        CorruptionType.INTEGER_OVERFLOW: 'CWE-190',
        CorruptionType.OUT_OF_BOUNDS_READ: 'CWE-125',
        CorruptionType.OUT_OF_BOUNDS_WRITE: 'CWE-787',
        CorruptionType.BUFFER_UNDERFLOW: 'CWE-124',
        CorruptionType.USE_AFTER_RETURN: 'CWE-416',
        CorruptionType.USE_AFTER_SCOPE: 'CWE-416',
        CorruptionType.UNSAFE_UNLINK: 'CWE-416',
        CorruptionType.HEAP_USE_AFTER_FREE: 'CWE-416',
    }
    
    def __init__(self):
        """初始化内存损坏分类器"""
        logger.info("内存损坏分类器初始化完成")
    
    def classify(self, crash_context: CrashContext, vulnerability_info: Optional[Dict[str, Any]] = None) -> CorruptionClassification:
        """
        执行内存损坏类型分类
        
        Args:
            crash_context: 崩溃上下文信息
            vulnerability_info: 漏洞信息（可选）
        
        Returns:
            分类结果
        """
        logger.info("开始内存损坏分类...")
        
        evidence = []
        scores = {corruption_type: 0.0 for corruption_type in CorruptionType}
        
        crash_text = self._build_crash_text(crash_context)
        logger.debug(f"崩溃上下文文本: {crash_text[:200]}...")
        
        for corruption_type, rules in self.CLASSIFICATION_RULES.items():
            for pattern, score in rules:
                if re.search(pattern, crash_text, re.IGNORECASE):
                    scores[corruption_type] += score
                    evidence.append(f"匹配模式: {pattern}")
        
        scores = self._apply_register_analysis(crash_context, scores, evidence)
        scores = self._apply_stack_analysis(crash_context, scores, evidence)
        scores = self._apply_exception_analysis(crash_context, scores, evidence)
        
        if vulnerability_info:
            scores = self._apply_vulnerability_info(vulnerability_info, scores, evidence)
        
        max_score = max(scores.values())
        if max_score < 0.5:
            result = CorruptionClassification(
                corruption_type=CorruptionType.UNKNOWN,
                confidence=0.0,
                evidence=evidence,
                description="无法确定内存损坏类型"
            )
        else:
            best_type = max(scores, key=scores.get)
            result = CorruptionClassification(
                corruption_type=best_type,
                confidence=min(max_score, 1.0),
                evidence=evidence,
                description=self._get_type_description(best_type),
                cwe_id=self.CWE_MAPPING.get(best_type)
            )
        
        logger.info(f"内存损坏分类完成: {result.corruption_type.value}, 置信度: {result.confidence:.2f}")
        return result
    
    def _build_crash_text(self, crash_context: CrashContext) -> str:
        """构建崩溃上下文文本用于模式匹配"""
        parts = []
        
        if crash_context.crash_type:
            parts.append(crash_context.crash_type)
        
        if crash_context.exception_code:
            parts.append(crash_context.exception_code)
        
        if crash_context.fault_instruction:
            parts.append(crash_context.fault_instruction)
        
        for frame in crash_context.stack_trace:
            if 'function' in frame:
                parts.append(frame['function'])
            if 'raw' in frame:
                parts.append(frame['raw'])
        
        for reg_name, reg_value in crash_context.registers.items():
            parts.append(f"{reg_name}={reg_value}")
        
        return ' '.join(parts)
    
    def _apply_register_analysis(self, crash_context: CrashContext, scores: Dict[CorruptionType, float], evidence: List[str]) -> Dict[CorruptionType, float]:
        """基于寄存器状态分析"""
        rip = crash_context.registers.get('rip') or crash_context.registers.get('eip')
        
        if rip:
            rip_str = str(rip).lower()
            
            if '41414141' in rip_str or 'aaaa' in rip_str or 'deadbeef' in rip_str:
                scores[CorruptionType.STACK_BUFFER_OVERFLOW] += 0.3
                evidence.append("指令指针被可控数据覆盖")
            
            if '0x0' == rip_str or rip_str == '0':
                scores[CorruptionType.NULL_POINTER_DEREFERENCE] += 0.3
                evidence.append("指令指针为空")
        
        rsp = crash_context.registers.get('rsp') or crash_context.registers.get('esp')
        if rsp:
            rsp_str = str(rsp).lower()
            if '42424242' in rsp_str or 'bbbb' in rsp_str:
                scores[CorruptionType.STACK_BUFFER_OVERFLOW] += 0.2
                evidence.append("栈指针被可控数据覆盖")
        
        return scores
    
    def _apply_stack_analysis(self, crash_context: CrashContext, scores: Dict[CorruptionType, float], evidence: List[str]) -> Dict[CorruptionType, float]:
        """基于栈回溯分析"""
        stack_functions = [frame.get('function', '') for frame in crash_context.stack_trace]
        stack_text = ' '.join(stack_functions).lower()
        
        if 'free' in stack_text and crash_context.stack_trace:
            first_func = crash_context.stack_trace[0].get('function', '').lower()
            if 'free' in first_func:
                scores[CorruptionType.DOUBLE_FREE] += 0.3
                scores[CorruptionType.USE_AFTER_FREE] += 0.2
                evidence.append("崩溃发生在free函数内")
        
        if '__stack_chk_fail' in stack_text:
            scores[CorruptionType.STACK_BUFFER_OVERFLOW] += 0.4
            evidence.append("触发栈保护检查")
        
        if 'memcpy' in stack_text or 'strcpy' in stack_text:
            scores[CorruptionType.STACK_BUFFER_OVERFLOW] += 0.2
            scores[CorruptionType.HEAP_BUFFER_OVERFLOW] += 0.2
            evidence.append("涉及危险的内存复制函数")
        
        return scores
    
    def _apply_exception_analysis(self, crash_context: CrashContext, scores: Dict[CorruptionType, float], evidence: List[str]) -> Dict[CorruptionType, float]:
        """基于异常类型分析"""
        crash_type = (crash_context.crash_type or '').lower()
        
        if 'sigsegv' in crash_type or 'segmentation fault' in crash_type:
            scores[CorruptionType.STACK_BUFFER_OVERFLOW] += 0.1
            scores[CorruptionType.USE_AFTER_FREE] += 0.1
        
        if 'sigabrt' in crash_type or 'abort' in crash_type:
            scores[CorruptionType.DOUBLE_FREE] += 0.15
            scores[CorruptionType.STACK_BUFFER_OVERFLOW] += 0.1
        
        if crash_context.exception_code:
            exc_code = crash_context.exception_code.lower()
            if 'c0000005' in exc_code:
                scores[CorruptionType.NULL_POINTER_DEREFERENCE] += 0.2
                evidence.append("Windows访问违规异常")
        
        return scores
    
    def _apply_vulnerability_info(self, vulnerability_info: Dict[str, Any], scores: Dict[CorruptionType, float], evidence: List[str]) -> Dict[CorruptionType, float]:
        """基于漏洞信息分析"""
        vuln_type = vulnerability_info.get('type', '').lower()
        
        type_mapping = {
            'stack_overflow': CorruptionType.STACK_BUFFER_OVERFLOW,
            'heap_overflow': CorruptionType.HEAP_BUFFER_OVERFLOW,
            'uaf': CorruptionType.USE_AFTER_FREE,
            'use_after_free': CorruptionType.USE_AFTER_FREE,
            'double_free': CorruptionType.DOUBLE_FREE,
            'null_pointer': CorruptionType.NULL_POINTER_DEREFERENCE,
            'format_string': CorruptionType.FORMAT_STRING,
            'type_confusion': CorruptionType.TYPE_CONFUSION,
        }
        
        for key, corruption_type in type_mapping.items():
            if key in vuln_type:
                scores[corruption_type] += 0.6
                evidence.append(f"漏洞类型匹配: {key}")
        
        return scores
    
    def _get_type_description(self, corruption_type: CorruptionType) -> str:
        """获取内存损坏类型的描述"""
        descriptions = {
            CorruptionType.STACK_BUFFER_OVERFLOW: "栈缓冲区溢出：向栈上的缓冲区写入超出其边界的数据，可能覆盖返回地址或其他栈上数据",
            CorruptionType.HEAP_BUFFER_OVERFLOW: "堆缓冲区溢出：向堆上的缓冲区写入超出其边界的数据，可能破坏堆结构或相邻内存",
            CorruptionType.USE_AFTER_FREE: "使用后释放：在内存被释放后仍然访问该内存区域",
            CorruptionType.DOUBLE_FREE: "双重释放：对同一块内存进行多次释放操作",
            CorruptionType.NULL_POINTER_DEREFERENCE: "空指针解引用：尝试访问空指针指向的内存",
            CorruptionType.TYPE_CONFUSION: "类型混淆：将一种类型的对象错误地当作另一种类型处理",
            CorruptionType.FORMAT_STRING: "格式化字符串漏洞：用户输入直接作为格式化字符串参数",
            CorruptionType.INTEGER_OVERFLOW: "整数溢出：整数运算结果超出其数据类型的表示范围",
            CorruptionType.OUT_OF_BOUNDS_READ: "越界读取：读取数组或缓冲区边界之外的数据",
            CorruptionType.OUT_OF_BOUNDS_WRITE: "越界写入：向数组或缓冲区边界之外写入数据",
            CorruptionType.BUFFER_UNDERFLOW: "缓冲区下溢：从缓冲区起始位置之前读取或写入数据",
            CorruptionType.USE_AFTER_RETURN: "返回后使用：在函数返回后仍然使用其栈帧上的数据",
            CorruptionType.USE_AFTER_SCOPE: "作用域后使用：在变量超出作用域后仍然使用该变量",
            CorruptionType.UNSAFE_UNLINK: "不安全的unlink操作：在堆利用中不安全地解除链表节点",
            CorruptionType.HEAP_USE_AFTER_FREE: "堆使用后释放：在堆内存被释放后仍然访问",
            CorruptionType.UNKNOWN: "未知类型：无法确定具体的内存损坏类型",
        }
        return descriptions.get(corruption_type, "未知")
    
    def batch_classify(self, crash_contexts: List[CrashContext], vulnerability_infos: Optional[List[Dict[str, Any]]] = None) -> List[CorruptionClassification]:
        """
        批量分类内存损坏类型
        
        Args:
            crash_contexts: 崩溃上下文列表
            vulnerability_infos: 漏洞信息列表（可选）
        
        Returns:
            分类结果列表
        """
        results = []
        for i, context in enumerate(crash_contexts):
            vuln_info = vulnerability_infos[i] if vulnerability_infos and i < len(vulnerability_infos) else None
            result = self.classify(context, vuln_info)
            results.append(result)
        return results
    
    def get_cwe_for_type(self, corruption_type: CorruptionType) -> Optional[str]:
        """
        获取内存损坏类型对应的CWE编号
        
        Args:
            corruption_type: 内存损坏类型
        
        Returns:
            CWE编号
        """
        return self.CWE_MAPPING.get(corruption_type)


def get_corruption_classifier() -> CorruptionClassifier:
    """
    获取内存损坏分类器实例（工厂函数）
    
    Returns:
        CorruptionClassifier实例
    """
    return CorruptionClassifier()
