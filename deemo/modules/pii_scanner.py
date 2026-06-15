#!/usr/bin/env python3
"""
PII与敏感数据泄露扫描模块

使用正则表达式扫描二进制文件中的敏感信息，包括：
- 邮箱地址、电话号码、身份证号、信用卡号
- 硬编码的密码、token、私钥
- 内部IP地址和域名
- AWS/Azure/GCP凭证
"""

import logging
import os
import re
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class PIIType(Enum):
    """PII类型枚举"""
    EMAIL = "email"
    PHONE = "phone"
    ID_CARD = "id_card"
    CREDIT_CARD = "credit_card"
    PASSWORD = "password"
    API_KEY = "api_key"
    PRIVATE_KEY = "private_key"
    IP_ADDRESS = "ip_address"
    DOMAIN = "domain"
    AWS_KEY = "aws_key"
    AZURE_KEY = "azure_key"
    GCP_KEY = "gcp_key"
    TOKEN = "token"
    SECRET = "secret"


class RiskLevel(Enum):
    """风险等级枚举"""
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"


@dataclass
class PIIDetection:
    """
    PII检测结果定义
    """
    type: PIIType
    value: str
    offset: int
    risk_level: RiskLevel
    description: str = ""
    confidence: float = 0.0


@dataclass
class PIIScanResult:
    """
    PII扫描结果
    """
    binary_path: str
    detections: List[PIIDetection] = field(default_factory=list)
    total_detections: int = 0
    analysis_success: bool = False
    error_message: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典格式"""
        return {
            'binary_path': self.binary_path,
            'detections': [
                {
                    'type': det.type.value,
                    'value': self._mask_value(det.type, det.value),
                    'offset': hex(det.offset),
                    'risk_level': det.risk_level.value,
                    'description': det.description,
                    'confidence': det.confidence
                }
                for det in self.detections
            ],
            'total_detections': self.total_detections,
            'analysis_success': self.analysis_success,
            'error_message': self.error_message
        }

    @staticmethod
    def _mask_value(pii_type: PIIType, value: str) -> str:
        """脱敏敏感数据"""
        if pii_type == PIIType.EMAIL:
            parts = value.split('@')
            if len(parts) == 2:
                return f"{parts[0][:2]}***@{parts[1]}"
            return "***@***.com"
        elif pii_type in [PIIType.PASSWORD, PIIType.API_KEY, PIIType.AWS_KEY, PIIType.AZURE_KEY, PIIType.GCP_KEY]:
            return f"{value[:5]}***{value[-4:]}" if len(value) > 8 else "***"
        elif pii_type == PIIType.PHONE:
            return f"{value[:3]}***{value[-4:]}" if len(value) > 7 else "***"
        elif pii_type == PIIType.ID_CARD:
            return f"{value[:4]}***{value[-4:]}" if len(value) > 8 else "***"
        elif pii_type == PIIType.CREDIT_CARD:
            return f"****-****-****-{value[-4:]}" if len(value) >= 16 else "****-****-****-****"
        else:
            return value


class PIIScanner:
    """
    PII与敏感数据泄露扫描器
    
    使用正则表达式扫描二进制文件中的敏感信息。
    """

    # PII正则模式
    PATTERNS = {
        PIIType.EMAIL: {
            'pattern': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
            'risk': RiskLevel.HIGH,
            'confidence': 0.95
        },
        PIIType.PHONE: {
            'pattern': r'(?:\+?86)?1[3-9]\d{9}',
            'risk': RiskLevel.MEDIUM,
            'confidence': 0.9
        },
        PIIType.ID_CARD: {
            'pattern': r'\d{17}[\dXx]',
            'risk': RiskLevel.CRITICAL,
            'confidence': 0.95
        },
        PIIType.CREDIT_CARD: {
            'pattern': r'(?:\d{4}[- ]?){3}\d{4}',
            'risk': RiskLevel.CRITICAL,
            'confidence': 0.85
        },
        PIIType.PASSWORD: {
            'pattern': r'(?:password|pass|pwd)\s*[=:]\s*["\']?([^\s"\',;]+)["\']?',
            'risk': RiskLevel.CRITICAL,
            'confidence': 0.8
        },
        PIIType.API_KEY: {
            'pattern': r'[A-Za-z0-9]{32,64}',
            'risk': RiskLevel.CRITICAL,
            'confidence': 0.7
        },
        PIIType.PRIVATE_KEY: {
            'pattern': r'-----BEGIN (?:RSA|EC|DSA|OPENSSH) PRIVATE KEY-----',
            'risk': RiskLevel.CRITICAL,
            'confidence': 0.99
        },
        PIIType.IP_ADDRESS: {
            'pattern': r'\b(?:192\.168|10\.|172\.(?:1[6-9]|2[0-9]|3[0-1]))\.\d{1,3}\.\d{1,3}\b',
            'risk': RiskLevel.MEDIUM,
            'confidence': 0.95
        },
        PIIType.DOMAIN: {
            'pattern': r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}',
            'risk': RiskLevel.LOW,
            'confidence': 0.8
        },
        PIIType.AWS_KEY: {
            'pattern': r'AKIA[0-9A-Z]{16}',
            'risk': RiskLevel.CRITICAL,
            'confidence': 0.99
        },
        PIIType.AZURE_KEY: {
            'pattern': r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}',
            'risk': RiskLevel.CRITICAL,
            'confidence': 0.95
        },
        PIIType.GCP_KEY: {
            'pattern': r'GOOGLE_APPLICATION_CREDENTIALS|AIza[0-9A-Za-z\\-_]{35}',
            'risk': RiskLevel.CRITICAL,
            'confidence': 0.95
        },
        PIIType.TOKEN: {
            'pattern': r'(?:token|auth|bearer)\s*[=:]\s*["\']?([a-zA-Z0-9._-]{20,})["\']?',
            'risk': RiskLevel.HIGH,
            'confidence': 0.85
        },
        PIIType.SECRET: {
            'pattern': r'(?:secret|secret_key|SECRET_KEY)\s*[=:]\s*["\']?([^\s"\',;]+)["\']?',
            'risk': RiskLevel.CRITICAL,
            'confidence': 0.85
        }
    }

    # 常见公开常量（用于过滤误报）
    COMMON_CONSTANTS = {
        'localhost', '127.0.0.1', '0.0.0.0',
        'example.com', 'test.com', 'localhost.localdomain',
        'admin@example.com', 'user@test.com',
        'password123', 'admin123', 'test123'
    }

    def __init__(self, binary_path: str):
        """
        初始化PII扫描器
        
        Args:
            binary_path: 二进制文件路径
        """
        self.binary_path = binary_path
        self.detections: List[PIIDetection] = []

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
        """从二进制数据中提取可打印字符串"""
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

    def _is_common_constant(self, value: str) -> bool:
        """检查是否是常见公开常量"""
        return value.lower() in self.COMMON_CONSTANTS

    def _scan_string(self, string: str, offset: int, result: PIIScanResult) -> None:
        """扫描单个字符串中的PII"""
        for pii_type, pattern_info in self.PATTERNS.items():
            pattern = pattern_info['pattern']
            matches = re.findall(pattern, string)
            
            for match in matches:
                # 如果是捕获组，获取捕获的内容
                if isinstance(match, tuple) and len(match) > 0:
                    matched_value = match[0]
                else:
                    matched_value = match
                
                # 过滤常见常量
                if self._is_common_constant(matched_value):
                    continue
                
                # 创建检测结果
                detection = PIIDetection(
                    type=pii_type,
                    value=matched_value,
                    offset=offset,
                    risk_level=pattern_info['risk'],
                    description=f"检测到 {pii_type.value}",
                    confidence=pattern_info['confidence']
                )
                
                result.detections.append(detection)

    def scan(self) -> PIIScanResult:
        """
        执行PII扫描
        
        Returns:
            PIIScanResult 扫描结果
        """
        logger.info(f"开始PII扫描: {self.binary_path}")
        
        result = PIIScanResult(binary_path=self.binary_path)
        
        if not self._validate_path():
            result.error_message = f"无效的文件路径: {self.binary_path}"
            return result
        
        try:
            with open(self.binary_path, 'rb') as f:
                data = f.read()
            
            strings = self._extract_strings(data)
            logger.debug(f"提取到 {len(strings)} 个可打印字符串")
            
            for offset, string in strings:
                self._scan_string(string, offset, result)
            
            # 去重
            seen = set()
            unique_detections = []
            for det in result.detections:
                key = (det.type.value, det.value)
                if key not in seen:
                    seen.add(key)
                    unique_detections.append(det)
            result.detections = unique_detections
            
            result.total_detections = len(result.detections)
            result.analysis_success = True
            
            logger.info(f"PII扫描完成，发现 {result.total_detections} 个敏感数据")
            
        except Exception as e:
            logger.error(f"PII扫描失败: {e}")
            result.error_message = str(e)
        
        return result

    def generate_report(self, output_path: str = None) -> Optional[str]:
        """
        生成PII扫描报告
        
        Args:
            output_path: 输出文件路径（可选）
            
        Returns:
            报告内容或保存路径
        """
        result = self.scan()
        
        if not result.analysis_success:
            return None
        
        lines = []
        lines.append("# PII与敏感数据泄露扫描报告")
        lines.append("")
        lines.append(f"**目标文件**: `{result.binary_path}`")
        lines.append(f"**分析时间**: {__import__('datetime').datetime.now().isoformat()}")
        lines.append("")
        lines.append("## 概览")
        lines.append("")
        lines.append(f"- 检测到敏感数据: {result.total_detections}")
        
        # 按风险等级统计
        critical_count = sum(1 for d in result.detections if d.risk_level == RiskLevel.CRITICAL)
        high_count = sum(1 for d in result.detections if d.risk_level == RiskLevel.HIGH)
        medium_count = sum(1 for d in result.detections if d.risk_level == RiskLevel.MEDIUM)
        low_count = sum(1 for d in result.detections if d.risk_level == RiskLevel.LOW)
        
        lines.append(f"- 高危: {critical_count}")
        lines.append(f"- 中危: {high_count}")
        lines.append(f"- 低危: {medium_count}")
        lines.append(f"- 信息: {low_count}")
        lines.append("")
        
        if result.detections:
            lines.append("## 检测详情")
            lines.append("")
            lines.append("| 类型 | 风险等级 | 值 | 偏移 |")
            lines.append("|------|----------|----|------|")
            
            for det in result.detections:
                masked_value = PIIScanResult._mask_value(det.type, det.value)
                lines.append(f"| {det.type.value} | {det.risk_level.value} | {masked_value} | {hex(det.offset)} |")
        
        report_content = '\n'.join(lines)
        
        if output_path:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(report_content)
            return output_path
        
        return report_content
