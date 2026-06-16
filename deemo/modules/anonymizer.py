#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
代码片段匿名化过滤器模块

功能：
1. 检测并替换敏感信息（API密钥、密码、IP地址、域名等）
2. 混淆标识符（函数名、变量名）
3. 移除或模糊化敏感字符串
4. 支持正则表达式匹配和替换

安全说明：
- 此模块用于在调用外部LLM前对代码片段进行匿名化处理
- 敏感信息将被替换为占位符，避免泄露敏感数据
- 默认启用所有匿名化规则，可通过配置调整
"""

import re
import hashlib
from enum import Enum
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Callable, Set, Tuple
from abc import ABC, abstractmethod


class AnonymizationLevel(Enum):
    """匿名化级别"""
    LOW = "low"       # 仅替换明显的敏感信息（API密钥、密码）
    MEDIUM = "medium" # 中等匿名化（添加标识符混淆）
    HIGH = "high"     # 高级匿名化（模糊化大部分字符串）
    EXTREME = "extreme" # 极端匿名化（移除所有可能的敏感信息）


@dataclass
class AnonymizationRule:
    """匿名化规则"""
    name: str
    pattern: re.Pattern
    replacement: str
    description: str = ""
    enabled: bool = True
    priority: int = 1


@dataclass
class AnonymizationResult:
    """匿名化结果"""
    original: str
    anonymized: str
    replacements: List[Dict[str, Any]] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    anonymization_level: AnonymizationLevel = AnonymizationLevel.MEDIUM


class Anonymizer(ABC):
    """匿名化器抽象基类"""
    
    @abstractmethod
    def anonymize(self, text: str, level: AnonymizationLevel = AnonymizationLevel.MEDIUM) -> AnonymizationResult:
        """
        对文本进行匿名化处理
        
        Args:
            text: 输入文本
            level: 匿名化级别
            
        Returns:
            AnonymizationResult
        """
        pass


class CodeAnonymizer(Anonymizer):
    """
    代码片段匿名化器
    
    核心功能：
    1. API密钥检测与替换
    2. IP地址和域名模糊化
    3. 密码和敏感字符串检测
    4. 标识符混淆
    5. 字符串内容模糊化
    """
    
    def __init__(self):
        self.rules = self._load_rules()
        self.identifier_mapping: Dict[str, str] = {}
        self.identifier_counter = 0
    
    def _load_rules(self) -> List[AnonymizationRule]:
        """加载匿名化规则"""
        rules = []
        
        # API密钥模式
        rules.append(AnonymizationRule(
            name="openai_api_key",
            pattern=re.compile(r'sk-[a-zA-Z0-9]{48}', re.IGNORECASE),
            replacement='sk-REDACTED_API_KEY',
            description="OpenAI API密钥",
            priority=10
        ))
        
        rules.append(AnonymizationRule(
            name="aws_api_key",
            pattern=re.compile(r'AKIA[0-9A-Z]{16}', re.IGNORECASE),
            replacement='AKIA_REDACTED_KEY',
            description="AWS Access Key",
            priority=10
        ))
        
        rules.append(AnonymizationRule(
            name="hex_token",
            pattern=re.compile(r'[0-9a-fA-F]{32,64}'),
            replacement='REDACTED_HEX_TOKEN',
            description="长十六进制令牌",
            priority=9
        ))
        
        # IP地址
        rules.append(AnonymizationRule(
            name="ipv4_address",
            pattern=re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'),
            replacement='X.X.X.X',
            description="IPv4地址",
            priority=8
        ))
        
        rules.append(AnonymizationRule(
            name="ipv6_address",
            pattern=re.compile(r'(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}'),
            replacement='REDACTED_IPV6',
            description="IPv6地址",
            priority=8
        ))
        
        # 邮箱地址
        rules.append(AnonymizationRule(
            name="email_address",
            pattern=re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'),
            replacement='REDACTED@example.com',
            description="邮箱地址",
            priority=7
        ))
        
        # URL
        rules.append(AnonymizationRule(
            name="url",
            pattern=re.compile(r'https?://[^\s]+'),
            replacement='https://REDACTED_URL',
            description="URL地址",
            priority=6
        ))
        
        # 文件路径中的敏感信息
        rules.append(AnonymizationRule(
            name="windows_path",
            pattern=re.compile(r'C:\\[^\\\s]+\\[^\\\s]+'),
            replacement='C:\\REDACTED\\PATH',
            description="Windows路径",
            priority=5
        ))
        
        rules.append(AnonymizationRule(
            name="unix_path",
            pattern=re.compile(r'/[^/\s]+/[^/\s]+'),
            replacement='/REDACTED/PATH',
            description="Unix路径",
            priority=5
        ))
        
        # 密码关键字
        rules.append(AnonymizationRule(
            name="password_literal",
            pattern=re.compile(r'["\']password["\']\s*[=:]\s*["\'][^"\']+["\']'),
            replacement='password="REDACTED"',
            description="密码字面量赋值",
            priority=10
        ))
        
        # 私钥检测
        rules.append(AnonymizationRule(
            name="private_key",
            pattern=re.compile(r'-----BEGIN (?:RSA|EC|DSA|OPENSSH) PRIVATE KEY-----.+?-----END \1 PRIVATE KEY-----', re.DOTALL),
            replacement='-----BEGIN PRIVATE KEY-----REDACTED-----END PRIVATE KEY-----',
            description="私钥内容",
            priority=10
        ))
        
        # 证书内容
        rules.append(AnonymizationRule(
            name="certificate",
            pattern=re.compile(r'-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----', re.DOTALL),
            replacement='-----BEGIN CERTIFICATE-----REDACTED-----END CERTIFICATE-----',
            description="证书内容",
            priority=10
        ))
        
        return sorted(rules, key=lambda x: x.priority, reverse=True)
    
    def anonymize(self, text: str, level: AnonymizationLevel = AnonymizationLevel.MEDIUM) -> AnonymizationResult:
        """
        对代码片段进行匿名化处理
        
        Args:
            text: 输入代码文本
            level: 匿名化级别
            
        Returns:
            AnonymizationResult
        """
        original = text
        anonymized = text
        replacements = []
        warnings = []
        
        # 重置标识符映射
        self.identifier_mapping = {}
        self.identifier_counter = 0
        
        # 应用正则规则
        for rule in self.rules:
            if rule.enabled:
                matches = list(rule.pattern.finditer(anonymized))
                for match in matches:
                    original_value = match.group()
                    if original_value != rule.replacement:
                        anonymized = anonymized.replace(original_value, rule.replacement)
                        replacements.append({
                            'rule': rule.name,
                            'original': original_value,
                            'replacement': rule.replacement,
                            'description': rule.description
                        })
        
        # 根据级别应用额外的匿名化
        if level >= AnonymizationLevel.MEDIUM:
            anonymized, id_replacements = self._anonymize_identifiers(anonymized)
            replacements.extend(id_replacements)
        
        if level >= AnonymizationLevel.HIGH:
            anonymized, str_replacements = self._anonymize_strings(anonymized)
            replacements.extend(str_replacements)
        
        if level == AnonymizationLevel.EXTREME:
            anonymized, comment_replacements = self._remove_comments(anonymized)
            replacements.extend(comment_replacements)
        
        # 生成警告
        if any(r['rule'] in ['private_key', 'certificate', 'openai_api_key'] for r in replacements):
            warnings.append("检测到高度敏感信息（私钥/证书/API密钥）")
        
        return AnonymizationResult(
            original=original,
            anonymized=anonymized,
            replacements=replacements,
            warnings=warnings,
            anonymization_level=level
        )
    
    def _anonymize_identifiers(self, text: str) -> Tuple[str, List[Dict[str, Any]]]:
        """
        混淆标识符（函数名、变量名）
        
        Args:
            text: 输入文本
            
        Returns:
            (匿名化文本, 替换列表)
        """
        replacements = []
        
        # 匹配标识符（排除关键字）
        keywords = {
            'if', 'else', 'for', 'while', 'do', 'switch', 'case', 'default',
            'break', 'continue', 'return', 'goto', 'sizeof', 'typedef',
            'struct', 'union', 'enum', 'const', 'static', 'extern', 'void',
            'char', 'short', 'int', 'long', 'float', 'double', 'signed',
            'unsigned', 'volatile', 'register', 'inline', 'class', 'public',
            'private', 'protected', 'virtual', 'override', 'final', 'new',
            'delete', 'true', 'false', 'nullptr', 'NULL', 'this', 'self',
            'def', 'import', 'from', 'class', 'def', 'lambda', 'yield',
            'async', 'await', 'try', 'catch', 'throw', 'finally', 'using',
            'namespace', 'template', 'typename', 'auto', 'decltype',
            'function', 'module', 'package', 'interface', 'extends', 'implements',
            'abstract', 'static', 'final', 'native', 'synchronized', 'transient',
            'volatile', 'instanceof', 'typeof', 'instanceof', 'delete', 'typeof'
        }
        
        # 匹配函数/变量名
        pattern = re.compile(r'\b([a-zA-Z_][a-zA-Z0-9_]*)\b')
        matches = pattern.findall(text)
        
        for match in matches:
            if match not in keywords and len(match) > 2:
                if match not in self.identifier_mapping:
                    self.identifier_counter += 1
                    self.identifier_mapping[match] = f'var_{self.identifier_counter:04d}'
                
                new_name = self.identifier_mapping[match]
                if new_name != match:
                    # 使用边界匹配替换
                    text = re.sub(rf'\b{re.escape(match)}\b', new_name, text)
                    replacements.append({
                        'rule': 'identifier',
                        'original': match,
                        'replacement': new_name,
                        'description': '标识符混淆'
                    })
        
        return text, replacements
    
    def _anonymize_strings(self, text: str) -> Tuple[str, List[Dict[str, Any]]]:
        """
        模糊化字符串内容
        
        Args:
            text: 输入文本
            
        Returns:
            (匿名化文本, 替换列表)
        """
        replacements = []
        
        # 匹配双引号字符串
        double_pattern = re.compile(r'"([^"]*)"')
        matches = double_pattern.findall(text)
        for match in matches:
            if len(match) > 3:
                # 保留前3个字符，其余用*替换
                masked = match[:3] + '*' * max(0, len(match) - 3)
                old_str = f'"{match}"'
                new_str = f'"{masked}"'
                text = text.replace(old_str, new_str)
                replacements.append({
                    'rule': 'string',
                    'original': old_str,
                    'replacement': new_str,
                    'description': '字符串模糊化'
                })
        
        # 匹配单引号字符串
        single_pattern = re.compile(r"'([^']*)'")
        matches = single_pattern.findall(text)
        for match in matches:
            if len(match) > 3:
                masked = match[:3] + '*' * max(0, len(match) - 3)
                old_str = f"'{match}'"
                new_str = f"'{masked}'"
                text = text.replace(old_str, new_str)
                replacements.append({
                    'rule': 'string',
                    'original': old_str,
                    'replacement': new_str,
                    'description': '字符串模糊化'
                })
        
        return text, replacements
    
    def _remove_comments(self, text: str) -> Tuple[str, List[Dict[str, Any]]]:
        """
        移除注释内容
        
        Args:
            text: 输入文本
            
        Returns:
            (匿名化文本, 替换列表)
        """
        replacements = []
        
        # 移除单行注释
        # C/C++ style
        text, count = re.subn(r'//.*$', '// REDACTED', text, flags=re.MULTILINE)
        if count > 0:
            replacements.append({
                'rule': 'comment',
                'original': '// ...',
                'replacement': '// REDACTED',
                'description': '移除单行注释',
                'count': count
            })
        
        # Python style
        text, count = re.subn(r'#.*$', '# REDACTED', text, flags=re.MULTILINE)
        if count > 0:
            replacements.append({
                'rule': 'comment',
                'original': '# ...',
                'replacement': '# REDACTED',
                'description': '移除Python注释',
                'count': count
            })
        
        # 移除多行注释
        text, count = re.subn(r'/\*[\s\S]*?\*/', '/* REDACTED */', text)
        if count > 0:
            replacements.append({
                'rule': 'comment',
                'original': '/* ... */',
                'replacement': '/* REDACTED */',
                'description': '移除多行注释',
                'count': count
            })
        
        return text, replacements


class AnonymizationContextManager:
    """
    匿名化上下文管理器
    
    用于在调用外部LLM时自动进行匿名化处理
    """
    
    def __init__(self, anonymizer: Anonymizer = None, level: AnonymizationLevel = AnonymizationLevel.MEDIUM):
        self.anonymizer = anonymizer or CodeAnonymizer()
        self.level = level
        self.last_result: Optional[AnonymizationResult] = None
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        pass
    
    def process(self, text: str) -> str:
        """
        处理文本并返回匿名化结果
        
        Args:
            text: 输入文本
            
        Returns:
            匿名化后的文本
        """
        result = self.anonymizer.anonymize(text, self.level)
        self.last_result = result
        
        if result.warnings:
            for warning in result.warnings:
                import logging
                logger = logging.getLogger(__name__)
                logger.warning(f"匿名化警告: {warning}")
        
        return result.anonymized
    
    def get_last_result(self) -> Optional[AnonymizationResult]:
        """获取最后一次匿名化结果"""
        return self.last_result


# 全局匿名化器实例
_global_anonymizer = None


def get_anonymizer() -> CodeAnonymizer:
    """获取全局匿名化器实例"""
    global _global_anonymizer
    if _global_anonymizer is None:
        _global_anonymizer = CodeAnonymizer()
    return _global_anonymizer


def anonymize_code(code: str, level: AnonymizationLevel = AnonymizationLevel.MEDIUM) -> AnonymizationResult:
    """
    便捷的代码匿名化函数
    
    Args:
        code: 代码文本
        level: 匿名化级别
        
    Returns:
        AnonymizationResult
    """
    anonymizer = get_anonymizer()
    return anonymizer.anonymize(code, level)


def is_sensitive_content(text: str) -> bool:
    """
    检测文本是否包含敏感内容
    
    Args:
        text: 输入文本
        
    Returns:
        True 如果包含敏感内容
    """
    sensitive_patterns = [
        r'sk-[a-zA-Z0-9]{48}',           # OpenAI API密钥
        r'AKIA[0-9A-Z]{16}',             # AWS Access Key
        r'-----BEGIN .* PRIVATE KEY-----', # 私钥
        r'password\s*[=:]\s*["\']',       # 密码赋值
        r'["\']password["\']',            # 密码字符串
    ]
    
    for pattern in sensitive_patterns:
        if re.search(pattern, text, re.IGNORECASE):
            return True
    return False
