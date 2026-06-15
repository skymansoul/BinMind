#!/usr/bin/env python3
"""
安全飞地二进制分析模块

分析SGX enclave和TrustZone TA二进制文件，检测enclave边界处的安全漏洞。
支持检测：
- OCALL参数未拷贝到私有内存
- ECALL未检查指针是否在enclave内
- 缺乏输入验证导致的逻辑漏洞
"""

import logging
import os
import re
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class EnclaveType(Enum):
    """Enclave类型枚举"""
    SGX_ENCLAVE = "sgx_enclave"
    TRUSTZONE_TA = "trustzone_ta"
    SEV_SNP = "sev_snp"
    SEV_ES = "sev_es"


class EnclaveIssueType(Enum):
    """Enclave漏洞类型枚举"""
    OCALL_UNSAFE_PARAMETER = "ocall_unsafe_parameter"
    ECALL_UNCHECKED_POINTER = "ecall_unchecked_pointer"
    MISSING_INPUT_VALIDATION = "missing_input_validation"
    IMPROPER_MEMORY_ACCESS = "improper_memory_access"
    SIDE_CHANNEL_VULNERABILITY = "side_channel_vulnerability"
    INSECURE_CRYPTO = "insecure_crypto"


class RiskLevel(Enum):
    """风险等级枚举"""
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"


@dataclass
class EnclaveInterface:
    """
    Enclave接口定义（ECALL/OCALL）
    """
    name: str
    address: int
    type: str  # 'ecall' or 'ocall'
    parameters: List[str] = field(default_factory=list)
    is_trusted: bool = False
    description: str = ""


@dataclass
class EnclaveConfig:
    """
    Enclave配置信息
    """
    enclave_type: EnclaveType
    stack_size: int = 0
    heap_size: int = 0
    tcs_count: int = 0
    max_threads: int = 0
    attributes: List[str] = field(default_factory=list)


@dataclass
class EnclaveIssue:
    """
    Enclave安全问题定义
    """
    type: EnclaveIssueType
    function_name: str
    address: int
    description: str
    risk_level: RiskLevel
    evidence: str = ""
    recommendation: str = ""


@dataclass
class EnclaveAnalysisResult:
    """
    Enclave分析结果
    """
    binary_path: str
    enclave_type: EnclaveType
    config: Optional[EnclaveConfig] = None
    ecalls: List[EnclaveInterface] = field(default_factory=list)
    ocalls: List[EnclaveInterface] = field(default_factory=list)
    issues: List[EnclaveIssue] = field(default_factory=list)
    analysis_success: bool = False
    error_message: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典格式"""
        return {
            'binary_path': self.binary_path,
            'enclave_type': self.enclave_type.value,
            'config': {
                'stack_size': self.config.stack_size,
                'heap_size': self.config.heap_size,
                'tcs_count': self.config.tcs_count,
                'max_threads': self.config.max_threads,
                'attributes': self.config.attributes
            } if self.config else None,
            'ecalls': [
                {
                    'name': e.name,
                    'address': hex(e.address),
                    'parameters': e.parameters,
                    'is_trusted': e.is_trusted,
                    'description': e.description
                }
                for e in self.ecalls
            ],
            'ocalls': [
                {
                    'name': o.name,
                    'address': hex(o.address),
                    'parameters': o.parameters,
                    'is_trusted': o.is_trusted,
                    'description': o.description
                }
                for o in self.ocalls
            ],
            'issues': [
                {
                    'type': issue.type.value,
                    'function_name': issue.function_name,
                    'address': hex(issue.address),
                    'description': issue.description,
                    'risk_level': issue.risk_level.value,
                    'evidence': issue.evidence,
                    'recommendation': issue.recommendation
                }
                for issue in self.issues
            ],
            'analysis_success': self.analysis_success,
            'error_message': self.error_message
        }


class EnclaveAnalyzer:
    """
    安全飞地二进制分析器
    
    分析SGX enclave和TrustZone TA二进制文件，检测enclave边界处的安全漏洞。
    """

    # SGX相关函数模式
    SGX_ECALL_PATTERNS = [
        r'ecall_', r'ECALL_',
        r'SGX_ECALL_', r'sgx_ecall_'
    ]

    SGX_OCALL_PATTERNS = [
        r'ocall_', r'OCALL_',
        r'SGX_OCALL_', r'sgx_ocall_',
        r'printf', r'puts', r'fprintf',
        r'gettimeofday', r'clock_gettime',
        r'malloc', r'free', r'calloc'
    ]

    # TrustZone相关模式
    TZ_TA_PATTERNS = [
        r'TEE_', r'tee_',
        r'TA_', r'ta_',
        r'SMC_', r'smc_'
    ]

    # 危险的OCALL函数（可能泄露enclave内存）
    DANGEROUS_OCALLS = {
        'printf', 'fprintf', 'sprintf', 'puts',
        'write', 'send', 'sendto',
        'memcpy', 'memmove'
    }

    def __init__(self, binary_path: str, enclave_type: EnclaveType = None):
        """
        初始化Enclave分析器
        
        Args:
            binary_path: enclave二进制文件路径
            enclave_type: enclave类型（可选，自动检测）
        """
        self.binary_path = binary_path
        self.enclave_type = enclave_type
        self.ecalls: List[EnclaveInterface] = []
        self.ocalls: List[EnclaveInterface] = []
        self.config: EnclaveConfig = None
        self.issues: List[EnclaveIssue] = []

    def _validate_path(self) -> bool:
        """验证文件路径"""
        if not os.path.exists(self.binary_path):
            logger.error(f"文件不存在: {self.binary_path}")
            return False
        if not os.path.isfile(self.binary_path):
            logger.error(f"不是有效文件: {self.binary_path}")
            return False
        return True

    def _extract_strings(self, data: bytes) -> List[Tuple[int, str]]:
        """提取二进制中的可打印字符串"""
        strings = []
        current_string = []
        current_offset = 0
        
        for i, byte in enumerate(data):
            if 0x20 <= byte <= 0x7E:
                current_string.append(chr(byte))
            else:
                if len(current_string) >= 4:
                    strings.append((current_offset, ''.join(current_string)))
                current_string = []
                current_offset = i + 1
        
        if len(current_string) >= 4:
            strings.append((current_offset, ''.join(current_string)))
        
        return strings

    def _detect_enclave_type(self, result: EnclaveAnalysisResult) -> None:
        """检测enclave类型"""
        filename = os.path.basename(self.binary_path).lower()
        
        if self.enclave_type:
            result.enclave_type = self.enclave_type
            return
        
        # 根据文件名和内容检测
        if filename.endswith('.signed.so') or 'enclave' in filename:
            result.enclave_type = EnclaveType.SGX_ENCLAVE
        elif filename.endswith('.ta') or 'trustzone' in filename.lower():
            result.enclave_type = EnclaveType.TRUSTZONE_TA
        elif 'sev' in filename.lower():
            result.enclave_type = EnclaveType.SEV_SNP
        else:
            # 默认假设SGX
            result.enclave_type = EnclaveType.SGX_ENCLAVE
        
        self.enclave_type = result.enclave_type
        logger.debug(f"检测到enclave类型: {self.enclave_type.value}")

    def _parse_enclave_config(self, data: bytes, strings: List[Tuple[int, str]], result: EnclaveAnalysisResult) -> None:
        """解析enclave配置信息"""
        config = EnclaveConfig(enclave_type=self.enclave_type)
        
        # 尝试从字符串中提取配置信息
        for offset, string in strings:
            # 栈大小
            match = re.search(r'stack[_ ]?size[_ ]?(\d+)', string, re.IGNORECASE)
            if match:
                config.stack_size = int(match.group(1))
            
            # 堆大小
            match = re.search(r'heap[_ ]?size[_ ]?(\d+)', string, re.IGNORECASE)
            if match:
                config.heap_size = int(match.group(1))
            
            # TCS数量
            match = re.search(r'TCS[_ ]?count[_ ]?(\d+)', string, re.IGNORECASE)
            if match:
                config.tcs_count = int(match.group(1))
            
            # 属性
            if 'DEBUG' in string or 'debug' in string.lower():
                config.attributes.append('DEBUG')
            if 'PRODUCTION' in string:
                config.attributes.append('PRODUCTION')
            if 'SIMULATION' in string:
                config.attributes.append('SIMULATION')
        
        self.config = config
        result.config = config
        logger.debug(f"解析到enclave配置: {config}")

    def _extract_interfaces(self, strings: List[Tuple[int, str]], result: EnclaveAnalysisResult) -> None:
        """提取ECALL/OCALL接口"""
        seen = set()
        
        for offset, string in strings:
            # 检测ECALL
            for pattern in self.SGX_ECALL_PATTERNS:
                if pattern in string:
                    func_name = self._extract_function_name(string)
                    # 如果无法提取函数名，直接使用匹配的模式作为函数名
                    if not func_name:
                        # 尝试从空格分隔的字符串中提取
                        parts = string.split()
                        for part in parts:
                            if pattern in part:
                                func_name = part
                                break
                    if func_name and func_name not in seen:
                        seen.add(func_name)
                        ecall = EnclaveInterface(
                            name=func_name,
                            address=offset,
                            type='ecall',
                            is_trusted=True,
                            description=f"ECALL函数: {func_name}"
                        )
                        self.ecalls.append(ecall)
                        result.ecalls.append(ecall)
                    break
            
            # 检测OCALL
            for pattern in self.SGX_OCALL_PATTERNS:
                if pattern in string:
                    func_name = self._extract_function_name(string)
                    # 如果无法提取函数名，直接使用匹配的模式作为函数名
                    if not func_name:
                        parts = string.split()
                        for part in parts:
                            if pattern in part:
                                func_name = part
                                break
                    if func_name and func_name not in seen:
                        seen.add(func_name)
                        ocall = EnclaveInterface(
                            name=func_name,
                            address=offset,
                            type='ocall',
                            is_trusted=False,
                            description=f"OCALL函数: {func_name}"
                        )
                        self.ocalls.append(ocall)
                        result.ocalls.append(ocall)
                    break
        
        logger.debug(f"提取到 {len(self.ecalls)} 个ECALL和 {len(self.ocalls)} 个OCALL")

    def _extract_function_name(self, string: str) -> Optional[str]:
        """从字符串中提取函数名"""
        # 尝试提取函数名
        patterns = [
            r'\b([a-zA-Z_][a-zA-Z0-9_]*)\s*\(',
            r'\b([a-zA-Z_][a-zA-Z0-9_]*)\s*='
        ]
        
        for pattern in patterns:
            match = re.search(pattern, string)
            if match:
                return match.group(1)
        
        return None

    def _detect_vulnerabilities(self, data: bytes, strings: List[Tuple[int, str]], result: EnclaveAnalysisResult) -> None:
        """检测enclave漏洞"""
        self._detect_ocall_unsafe_parameters(strings, result)
        self._detect_ecall_unchecked_pointers(strings, result)
        self._detect_missing_input_validation(strings, result)
        self._detect_improper_memory_access(strings, result)

    def _detect_ocall_unsafe_parameters(self, strings: List[Tuple[int, str]], result: EnclaveAnalysisResult) -> None:
        """检测OCALL参数未拷贝到私有内存的问题"""
        seen = set()
        
        # 首先检查已提取的OCALL接口
        for ocall in self.ocalls:
            if ocall.name.lower() in self.DANGEROUS_OCALLS and ocall.name not in seen:
                seen.add(ocall.name)
                issue = EnclaveIssue(
                    type=EnclaveIssueType.OCALL_UNSAFE_PARAMETER,
                    function_name=ocall.name,
                    address=ocall.address,
                    description=f"危险OCALL函数 {ocall.name} 可能直接传递enclave内存指针给不可信OS",
                    risk_level=RiskLevel.CRITICAL,
                    evidence=f"检测到OCALL调用: {ocall.name}",
                    recommendation="确保将敏感数据拷贝到非安全内存后再调用OCALL"
                )
                self.issues.append(issue)
                result.issues.append(issue)
        
        # 直接从字符串中检测危险OCALL模式
        for offset, string in strings:
            for dangerous_ocall in self.DANGEROUS_OCALLS:
                if dangerous_ocall in string.lower() and dangerous_ocall not in seen:
                    seen.add(dangerous_ocall)
                    issue = EnclaveIssue(
                        type=EnclaveIssueType.OCALL_UNSAFE_PARAMETER,
                        function_name=dangerous_ocall,
                        address=offset,
                        description=f"危险OCALL函数 {dangerous_ocall} 可能直接传递enclave内存指针给不可信OS",
                        risk_level=RiskLevel.CRITICAL,
                        evidence=f"检测到OCALL调用: {dangerous_ocall}",
                        recommendation="确保将敏感数据拷贝到非安全内存后再调用OCALL"
                    )
                    self.issues.append(issue)
                    result.issues.append(issue)

    def _detect_ecall_unchecked_pointers(self, strings: List[Tuple[int, str]], result: EnclaveAnalysisResult) -> None:
        """检测ECALL未检查指针边界的问题"""
        seen = set()
        
        # 首先检查已提取的ECALL接口
        for ecall in self.ecalls:
            if ecall.name not in seen:
                seen.add(ecall.name)
                # 检查是否有指针参数验证
                has_validation = False
                
                for offset, string in strings:
                    if ecall.name in string:
                        if any(check in string.lower() for check in ['copy_from_user', 'sgx_copy', 'validate', 'check']):
                            has_validation = True
                            break
                
                if not has_validation:
                    issue = EnclaveIssue(
                        type=EnclaveIssueType.ECALL_UNCHECKED_POINTER,
                        function_name=ecall.name,
                        address=ecall.address,
                        description=f"ECALL函数 {ecall.name} 可能未验证输入指针是否在enclave内存范围内",
                        risk_level=RiskLevel.HIGH,
                        evidence=f"ECALL函数: {ecall.name}",
                        recommendation="添加指针边界检查和安全拷贝操作"
                    )
                    self.issues.append(issue)
                    result.issues.append(issue)
        
        # 直接从字符串中检测ECALL模式
        for offset, string in strings:
            for ecall_pattern in self.SGX_ECALL_PATTERNS:
                if ecall_pattern in string.lower():
                    func_name = self._extract_function_name(string) or ecall_pattern
                    if func_name not in seen:
                        seen.add(func_name)
                        # 检查是否有指针参数验证
                        has_validation = False
                        for _, s in strings:
                            if func_name in s:
                                if any(check in s.lower() for check in ['copy_from_user', 'sgx_copy', 'validate', 'check']):
                                    has_validation = True
                                    break
                        
                        if not has_validation:
                            issue = EnclaveIssue(
                                type=EnclaveIssueType.ECALL_UNCHECKED_POINTER,
                                function_name=func_name,
                                address=offset,
                                description=f"ECALL函数 {func_name} 可能未验证输入指针是否在enclave内存范围内",
                                risk_level=RiskLevel.HIGH,
                                evidence=f"ECALL函数: {func_name}",
                                recommendation="添加指针边界检查和安全拷贝操作"
                            )
                            self.issues.append(issue)
                            result.issues.append(issue)

    def _detect_missing_input_validation(self, strings: List[Tuple[int, str]], result: EnclaveAnalysisResult) -> None:
        """检测缺乏输入验证的问题"""
        validation_patterns = [
            r'sizeof\(', r'memcmp\(', r'strlen\(',
            r'<=', r'>=', r'<', r'>',
            r'check_', r'validate_', r'sanitize_'
        ]
        
        for ecall in self.ecalls:
            has_validation = False
            
            for offset, string in strings:
                if ecall.name in string:
                    for pattern in validation_patterns:
                        if pattern in string:
                            has_validation = True
                            break
                    if has_validation:
                        break
            
            if not has_validation:
                issue = EnclaveIssue(
                    type=EnclaveIssueType.MISSING_INPUT_VALIDATION,
                    function_name=ecall.name,
                    address=ecall.address,
                    description=f"ECALL函数 {ecall.name} 可能缺乏输入验证",
                    risk_level=RiskLevel.MEDIUM,
                    evidence=f"ECALL函数: {ecall.name}",
                    recommendation="添加输入参数验证，包括边界检查和格式验证"
                )
                self.issues.append(issue)
                result.issues.append(issue)

    def _detect_improper_memory_access(self, strings: List[Tuple[int, str]], result: EnclaveAnalysisResult) -> None:
        """检测不当内存访问"""
        memory_patterns = [
            (r'memcpy\(', 'memcpy调用'),
            (r'memmove\(', 'memmove调用'),
            (r'strcpy\(', 'strcpy调用'),
            (r'__builtin_memcpy', '内建内存复制')
        ]
        
        for offset, string in strings:
            for pattern, desc in memory_patterns:
                if pattern in string:
                    # 检查是否涉及enclave边界
                    if any(keyword in string.lower() for keyword in ['enclave', 'trusted', 'untrusted']):
                        issue = EnclaveIssue(
                            type=EnclaveIssueType.IMPROPER_MEMORY_ACCESS,
                            function_name=self._extract_function_name(string) or 'unknown',
                            address=offset,
                            description=f"检测到可能不安全的内存操作: {desc}",
                            risk_level=RiskLevel.HIGH,
                            evidence=string.strip(),
                            recommendation="确保内存操作不跨越enclave边界"
                        )
                        self.issues.append(issue)
                        result.issues.append(issue)

    def analyze(self) -> EnclaveAnalysisResult:
        """
        执行Enclave分析
        
        Returns:
            EnclaveAnalysisResult 分析结果
        """
        logger.info(f"开始Enclave分析: {self.binary_path}")
        
        result = EnclaveAnalysisResult(
            binary_path=self.binary_path,
            enclave_type=self.enclave_type or EnclaveType.SGX_ENCLAVE
        )
        
        if not self._validate_path():
            result.error_message = f"无效的文件路径: {self.binary_path}"
            return result
        
        try:
            with open(self.binary_path, 'rb') as f:
                data = f.read()
            
            strings = self._extract_strings(data)
            
            self._detect_enclave_type(result)
            self._parse_enclave_config(data, strings, result)
            self._extract_interfaces(strings, result)
            self._detect_vulnerabilities(data, strings, result)
            
            # 去重
            seen = set()
            unique_issues = []
            for issue in result.issues:
                key = (issue.type.value, issue.function_name)
                if key not in seen:
                    seen.add(key)
                    unique_issues.append(issue)
            result.issues = unique_issues
            
            result.analysis_success = True
            
            logger.info(f"Enclave分析完成，发现 {len(result.issues)} 个安全问题")
            
        except Exception as e:
            logger.error(f"Enclave分析失败: {e}")
            result.error_message = str(e)
        
        return result

    def generate_report(self, output_path: str = None) -> Optional[str]:
        """
        生成Enclave分析报告
        
        Args:
            output_path: 输出文件路径（可选）
            
        Returns:
            报告内容或保存路径
        """
        result = self.analyze()
        
        if not result.analysis_success:
            return None
        
        lines = []
        lines.append("# 安全飞地二进制分析报告")
        lines.append("")
        lines.append(f"**目标文件**: `{result.binary_path}`")
        lines.append(f"**Enclave类型**: {result.enclave_type.value}")
        lines.append(f"**分析时间**: {__import__('datetime').datetime.now().isoformat()}")
        lines.append("")
        lines.append("## Enclave配置")
        lines.append("")
        
        if result.config:
            lines.append(f"- 栈大小: {result.config.stack_size} bytes")
            lines.append(f"- 堆大小: {result.config.heap_size} bytes")
            lines.append(f"- TCS数量: {result.config.tcs_count}")
            lines.append(f"- 最大线程数: {result.config.max_threads}")
            lines.append(f"- 属性: {', '.join(result.config.attributes) if result.config.attributes else '无'}")
        lines.append("")
        
        lines.append("## 接口列表")
        lines.append("")
        
        if result.ecalls:
            lines.append("### ECALL接口")
            lines.append("")
            for ecall in result.ecalls:
                lines.append(f"- `{ecall.name}` (地址: {hex(ecall.address)})")
            lines.append("")
        
        if result.ocalls:
            lines.append("### OCALL接口")
            lines.append("")
            for ocall in result.ocalls:
                lines.append(f"- `{ocall.name}` (地址: {hex(ocall.address)})")
            lines.append("")
        
        if result.issues:
            lines.append("## 安全问题")
            lines.append("")
            lines.append("| 类型 | 风险等级 | 函数 | 描述 |")
            lines.append("|------|----------|------|------|")
            
            for issue in result.issues:
                lines.append(f"| {issue.type.value} | {issue.risk_level.value} | `{issue.function_name}` | {issue.description} |")
            
            lines.append("")
            lines.append("## 问题详情")
            lines.append("")
            
            for issue in result.issues:
                lines.append(f"### {issue.description}")
                lines.append("")
                lines.append(f"**类型**: {issue.type.value}")
                lines.append(f"**风险等级**: {issue.risk_level.value}")
                lines.append(f"**函数**: `{issue.function_name}`")
                lines.append(f"**地址**: {hex(issue.address)}")
                lines.append("")
                lines.append(f"**修复建议**: {issue.recommendation}")
                lines.append("")
        
        report_content = '\n'.join(lines)
        
        if output_path:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(report_content)
            return output_path
        
        return report_content
