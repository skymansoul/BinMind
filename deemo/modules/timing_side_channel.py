#!/usr/bin/env python3
"""
时间侧信道漏洞静态检测模块

基于反编译伪代码进行模式匹配，检测可能导致时间侧信道漏洞的代码模式。
支持检测：
- 密钥依赖的条件分支
- 秘密相关的循环边界
- 密码学运算中的非恒定时间实现
"""

import logging
import os
import re
from typing import Dict, Any, List, Optional, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class TimingIssueSeverity(Enum):
    """时间侧信道问题严重程度枚举"""
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"


class TimingIssueType(Enum):
    """时间侧信道问题类型枚举"""
    KEY_DEPENDENT_BRANCH = "key_dependent_branch"
    SECRET_LOOP_BOUNDARY = "secret_loop_boundary"
    UNMASKED_LOOKUP = "unmasked_lookup"
    SECRET_COMPARISON = "secret_comparison"
    CACHE_TIMING = "cache_timing"
    CONSTANT_TIME_VIOLATION = "constant_time_violation"


@dataclass
class TimingIssue:
    """
    时间侧信道问题定义
    """
    type: TimingIssueType
    function_name: str
    address: int
    line_number: int
    description: str
    severity: TimingIssueSeverity
    evidence: str
    code_context: str = ""
    recommendation: str = ""


@dataclass
class TimingAnalysisResult:
    """
    时间侧信道分析结果
    """
    binary_path: str
    issues: List[TimingIssue] = field(default_factory=list)
    analyzed_functions: int = 0
    high_severity_count: int = 0
    medium_severity_count: int = 0
    low_severity_count: int = 0
    analysis_success: bool = False
    error_message: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典格式"""
        return {
            'binary_path': self.binary_path,
            'issues': [
                {
                    'type': issue.type.value,
                    'function_name': issue.function_name,
                    'address': hex(issue.address),
                    'line_number': issue.line_number,
                    'description': issue.description,
                    'severity': issue.severity.value,
                    'evidence': issue.evidence,
                    'code_context': issue.code_context,
                    'recommendation': issue.recommendation
                }
                for issue in self.issues
            ],
            'analyzed_functions': self.analyzed_functions,
            'high_severity_count': self.high_severity_count,
            'medium_severity_count': self.medium_severity_count,
            'low_severity_count': self.low_severity_count,
            'analysis_success': self.analysis_success,
            'error_message': self.error_message
        }


class TimingSideChannelDetector:
    """
    时间侧信道漏洞检测器
    
    基于反编译伪代码进行模式匹配，检测可能导致时间侧信道漏洞的代码模式。
    """

    # 密钥相关变量名模式
    KEY_VARIABLE_PATTERNS = [
        r'(?:^|[^a-zA-Z0-9_])(key|secret|password|pin|token|cipher|decrypt|encrypt|aes|sha|hmac|digest|sign|verify)(?:$|[^a-zA-Z0-9_])',
        r'(?:^|[^a-zA-Z0-9_])(priv|pub|cert|credential|auth|challenge|nonce|salt)(?:$|[^a-zA-Z0-9_])',
        r'(?:^|[^a-zA-Z0-9_])(k|sk|pk|keybuf|secretbuf)(?:$|[^a-zA-Z0-9_])'
    ]

    # 常量时间相关函数
    CONSTANT_TIME_FUNCTIONS = {
        'CRYPTO_memcmp', 'memcmp_s', 'timing_safe_bcmp',
        'constant_time_compare', 'safe_memcmp', 'secure_memcmp'
    }

    # 危险的比较函数
    DANGEROUS_COMPARE_FUNCTIONS = {
        'strcmp', 'strncmp', 'memcmp', 'bcmp', 'strcmpi'
    }

    def __init__(self, binary_path: str, binary_info: Dict[str, Any] = None):
        """
        初始化时间侧信道检测器
        
        Args:
            binary_path: 二进制文件路径
            binary_info: 可选的二进制信息字典
        """
        self.binary_path = binary_path
        self.binary_info = binary_info or {}
        self.issues: List[TimingIssue] = []
        self.key_variables: List[str] = []

    def _validate_path(self) -> bool:
        """验证文件路径"""
        if not os.path.exists(self.binary_path):
            logger.error(f"文件不存在: {self.binary_path}")
            return False
        if not os.path.isfile(self.binary_path):
            logger.error(f"不是有效文件: {self.binary_path}")
            return False
        return True

    def _extract_strings(self) -> List[str]:
        """提取二进制中的字符串"""
        strings = []
        try:
            with open(self.binary_path, 'rb') as f:
                data = f.read()
            
            current_string = []
            for byte in data:
                if 0x20 <= byte <= 0x7E:
                    current_string.append(chr(byte))
                else:
                    if len(current_string) >= 4:
                        strings.append(''.join(current_string))
                    current_string = []
            
            if len(current_string) >= 4:
                strings.append(''.join(current_string))
            
        except Exception as e:
            logger.error(f"提取字符串失败: {e}")
        
        return strings

    def _identify_key_variables(self, pseudocode: str) -> None:
        """识别密钥相关变量"""
        self.key_variables = []
        
        # 提取所有标识符
        identifiers = re.findall(r'\b[a-zA-Z_][a-zA-Z0-9_]*\b', pseudocode)
        
        # 检查每个标识符是否包含密钥相关词
        key_keywords = {
            'key', 'secret', 'password', 'pin', 'token', 'cipher', 'decrypt', 
            'encrypt', 'aes', 'sha', 'hmac', 'digest', 'sign', 'verify',
            'priv', 'pub', 'cert', 'credential', 'auth', 'challenge', 'nonce', 'salt',
            'sk', 'pk', 'keybuf', 'secretbuf'
        }
        
        for identifier in identifiers:
            lower_id = identifier.lower()
            for keyword in key_keywords:
                if keyword in lower_id and identifier not in self.key_variables:
                    self.key_variables.append(identifier)
                    break
        
        logger.debug(f"识别到 {len(self.key_variables)} 个密钥相关变量")

    def _extract_pseudocode(self) -> str:
        """从二进制提取伪代码（简化版本）"""
        strings = self._extract_strings()
        
        # 尝试找到类似代码的字符串
        code_like_strings = []
        for s in strings:
            if 'if' in s or 'while' in s or 'for' in s or '=' in s:
                code_like_strings.append(s)
        
        return '\n'.join(code_like_strings)

    def _detect_key_dependent_branches(self, pseudocode: str, result: TimingAnalysisResult) -> None:
        """检测密钥依赖的条件分支"""
        logger.debug("检测密钥依赖的条件分支")
        
        lines = pseudocode.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            # 查找包含密钥变量的条件分支
            for key_var in self.key_variables:
                # 检测 if (key[i] == ...) 模式
                if 'if' in line.lower() and key_var.lower() in line.lower():
                    # 检查是否是数组访问
                    if '[' in line and ']' in line:
                        issue = TimingIssue(
                            type=TimingIssueType.KEY_DEPENDENT_BRANCH,
                            function_name=self._extract_function_name(line),
                            address=0,
                            line_number=line_num,
                            description=f"检测到密钥依赖的条件分支: {key_var}",
                            severity=TimingIssueSeverity.HIGH,
                            evidence=line.strip(),
                            code_context=line.strip(),
                            recommendation="使用常量时间比较函数替代分支判断"
                        )
                        result.issues.append(issue)

    def _detect_secret_dependent_loops(self, pseudocode: str, result: TimingAnalysisResult) -> None:
        """检测秘密相关的循环边界"""
        logger.debug("检测秘密相关的循环边界")
        
        lines = pseudocode.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            # 检测 for/while 循环中使用密钥变量作为边界
            for key_var in self.key_variables:
                if ('for' in line.lower() or 'while' in line.lower()) and key_var.lower() in line.lower():
                    # 检查是否涉及长度或边界
                    if any(op in line.lower() for op in ['<', '>', '<=', '>=', 'len', 'size']):
                        issue = TimingIssue(
                            type=TimingIssueType.SECRET_LOOP_BOUNDARY,
                            function_name=self._extract_function_name(line),
                            address=0,
                            line_number=line_num,
                            description=f"检测到秘密相关的循环边界: {key_var}",
                            severity=TimingIssueSeverity.MEDIUM,
                            evidence=line.strip(),
                            code_context=line.strip(),
                            recommendation="确保循环次数不依赖秘密数据"
                        )
                        result.issues.append(issue)

    def _detect_unmasked_lookups(self, pseudocode: str, result: TimingAnalysisResult) -> None:
        """检测未掩码的查找表访问"""
        logger.debug("检测未掩码的查找表访问")
        
        lines = pseudocode.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            # 检测数组索引使用密钥变量
            for key_var in self.key_variables:
                if key_var.lower() in line.lower():
                    # 检测数组访问模式
                    match = re.search(r'(\w+)\s*\[\s*' + re.escape(key_var) + r'(\[.*?\])?\s*\]', line, re.IGNORECASE)
                    if match:
                        issue = TimingIssue(
                            type=TimingIssueType.UNMASKED_LOOKUP,
                            function_name=self._extract_function_name(line),
                            address=0,
                            line_number=line_num,
                            description=f"检测到未掩码的查找表访问: {match.group(1)}[{key_var}]",
                            severity=TimingIssueSeverity.HIGH,
                            evidence=line.strip(),
                            code_context=line.strip(),
                            recommendation="使用掩码技术保护查找表访问模式"
                        )
                        result.issues.append(issue)

    def _detect_secret_comparisons(self, pseudocode: str, result: TimingAnalysisResult) -> None:
        """检测秘密数据比较"""
        logger.debug("检测秘密数据比较")
        
        lines = pseudocode.split('\n')
        
        # 找出包含密钥相关函数名的行范围
        key_function_ranges = []
        current_function = None
        
        for line_num, line in enumerate(lines, 1):
            # 检测函数定义
            func_def_match = re.search(r'\b([a-zA-Z_][a-zA-Z0-9_]*)\s*\(', line)
            if func_def_match:
                func_name = func_def_match.group(1)
                # 检查函数名是否包含密钥相关词
                for keyword in ['key', 'secret', 'password', 'pin', 'token']:
                    if keyword in func_name.lower():
                        current_function = func_name
                        start_line = line_num
                        break
            
            # 检测函数结束（简单检测大括号）
            if current_function and '}' in line:
                key_function_ranges.append((current_function, start_line, line_num))
                current_function = None
        
        for line_num, line in enumerate(lines, 1):
            # 检测危险的比较函数调用
            for func in self.DANGEROUS_COMPARE_FUNCTIONS:
                if func in line.lower():
                    # 检查是否涉及密钥变量
                    has_key_relation = False
                    
                    # 方法1：检查行中是否有密钥变量
                    for key_var in self.key_variables:
                        if key_var.lower() in line.lower():
                            has_key_relation = True
                            break
                    
                    # 方法2：检查是否在密钥相关函数内
                    if not has_key_relation:
                        for func_name, start, end in key_function_ranges:
                            if start <= line_num <= end:
                                has_key_relation = True
                                break
                    
                    if has_key_relation:
                        issue = TimingIssue(
                            type=TimingIssueType.SECRET_COMPARISON,
                            function_name=self._extract_function_name(line) or current_function,
                            address=0,
                            line_number=line_num,
                            description=f"检测到使用危险比较函数比较秘密数据: {func}",
                            severity=TimingIssueSeverity.HIGH,
                            evidence=line.strip(),
                            code_context=line.strip(),
                            recommendation=f"使用常量时间比较函数如 CRYPTO_memcmp 替代 {func}"
                        )
                        result.issues.append(issue)

    def _detect_cache_timing_patterns(self, pseudocode: str, result: TimingAnalysisResult) -> None:
        """检测缓存时间攻击模式"""
        logger.debug("检测缓存时间攻击模式")
        
        lines = pseudocode.split('\n')
        
        cache_patterns = [
            (r'(\w+)\s*\[\s*(\w+)\s*\]', '数组索引访问'),
            (r'memcpy\s*\(', '内存复制'),
            (r'memset\s*\(', '内存设置'),
            (r'__builtin_memcpy', '内建内存复制'),
            (r'__builtin_strcpy', '内建字符串复制')
        ]
        
        for line_num, line in enumerate(lines, 1):
            for pattern, desc in cache_patterns:
                match = re.search(pattern, line)
                if match:
                    # 检查是否涉及密钥变量
                    for key_var in self.key_variables:
                        if key_var.lower() in line.lower():
                            issue = TimingIssue(
                                type=TimingIssueType.CACHE_TIMING,
                                function_name=self._extract_function_name(line),
                                address=0,
                                line_number=line_num,
                                description=f"检测到潜在的缓存时间攻击模式: {desc} 使用密钥数据",
                                severity=TimingIssueSeverity.MEDIUM,
                                evidence=line.strip(),
                                code_context=line.strip(),
                                recommendation="考虑使用常量时间实现或缓存安全技术"
                            )
                            result.issues.append(issue)

    def _extract_function_name(self, line: str) -> str:
        """从代码行提取函数名"""
        # 尝试从行中提取函数名
        func_pattern = re.search(r'(?:void|int|char|bool|size_t)\s+(\w+)\s*\(', line)
        if func_pattern:
            return func_pattern.group(1)
        return 'unknown'

    def _categorize_by_severity(self, result: TimingAnalysisResult) -> None:
        """按严重程度分类"""
        result.high_severity_count = sum(1 for i in result.issues 
                                         if i.severity == TimingIssueSeverity.HIGH)
        result.medium_severity_count = sum(1 for i in result.issues 
                                           if i.severity == TimingIssueSeverity.MEDIUM)
        result.low_severity_count = sum(1 for i in result.issues 
                                        if i.severity == TimingIssueSeverity.LOW)

    def analyze(self, pseudocode: str = "") -> TimingAnalysisResult:
        """
        执行时间侧信道分析
        
        Args:
            pseudocode: 反编译后的伪代码（可选）
            
        Returns:
            TimingAnalysisResult 分析结果
        """
        logger.info(f"开始时间侧信道分析: {self.binary_path}")
        
        result = TimingAnalysisResult(binary_path=self.binary_path)
        
        if not self._validate_path():
            result.error_message = f"无效的文件路径: {self.binary_path}"
            return result
        
        try:
            if not pseudocode:
                pseudocode = self._extract_pseudocode()
            
            if not pseudocode:
                logger.warning("未找到伪代码，跳过时间侧信道分析")
                result.analysis_success = True
                return result
            
            self._identify_key_variables(pseudocode)
            self._detect_key_dependent_branches(pseudocode, result)
            self._detect_secret_dependent_loops(pseudocode, result)
            self._detect_unmasked_lookups(pseudocode, result)
            self._detect_secret_comparisons(pseudocode, result)
            self._detect_cache_timing_patterns(pseudocode, result)
            
            # 去重
            seen = set()
            unique_issues = []
            for issue in result.issues:
                key = (issue.type.value, issue.line_number, issue.evidence)
                if key not in seen:
                    seen.add(key)
                    unique_issues.append(issue)
            result.issues = unique_issues
            
            self._categorize_by_severity(result)
            
            result.analyzed_functions = len(pseudocode.split('\n')) // 20
            result.analysis_success = True
            
            logger.info(f"时间侧信道分析完成，发现 {len(result.issues)} 个潜在问题")
            
        except Exception as e:
            logger.error(f"时间侧信道分析失败: {e}")
            result.error_message = str(e)
        
        return result

    def generate_report(self, output_path: str = None) -> Optional[str]:
        """
        生成时间侧信道分析报告
        
        Args:
            output_path: 输出文件路径（可选）
            
        Returns:
            报告内容或保存路径
        """
        result = self.analyze()
        
        if not result.analysis_success:
            return None
        
        lines = []
        lines.append("# 时间侧信道漏洞分析报告")
        lines.append("")
        lines.append(f"**目标文件**: `{result.binary_path}`")
        lines.append(f"**分析时间**: {__import__('datetime').datetime.now().isoformat()}")
        lines.append("")
        lines.append("## 概览")
        lines.append("")
        lines.append(f"- 高危问题: {result.high_severity_count}")
        lines.append(f"- 中危问题: {result.medium_severity_count}")
        lines.append(f"- 低危问题: {result.low_severity_count}")
        lines.append(f"- 分析函数数: {result.analyzed_functions}")
        lines.append("")
        
        if result.issues:
            lines.append("## 检测到的问题")
            lines.append("")
            lines.append("| 类型 | 严重程度 | 位置 | 描述 |")
            lines.append("|------|----------|------|------|")
            
            for issue in result.issues:
                lines.append(f"| {issue.type.value} | {issue.severity.value} | 第{issue.line_number}行 | {issue.description} |")
            
            lines.append("")
            lines.append("## 详细分析")
            lines.append("")
            
            for issue in result.issues:
                lines.append(f"### {issue.description}")
                lines.append("")
                lines.append(f"**类型**: {issue.type.value}")
                lines.append(f"**严重程度**: {issue.severity.value}")
                lines.append(f"**位置**: 函数 `{issue.function_name}`，第 {issue.line_number} 行")
                lines.append("")
                lines.append(f"**证据**:")
                lines.append("```")
                lines.append(issue.evidence)
                lines.append("```")
                lines.append("")
                lines.append(f"**修复建议**: {issue.recommendation}")
                lines.append("")
        
        report_content = '\n'.join(lines)
        
        if output_path:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(report_content)
            return output_path
        
        return report_content
