#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""代码片段匿名化过滤器。

调用外部 LLM 前对代码片段做匿名化，将敏感信息替换为占位符：
API 密钥、密码、IP/域名、邮箱、URL、私钥；按匿名化级别追加
标识符混淆、字符串模糊化与注释移除。
"""

import re
import random
import math
from enum import Enum
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Tuple
from abc import ABC, abstractmethod


class AnonymizationLevel(Enum):
    """匿名化级别"""
    LOW = 1       # 仅替换明显敏感信息（API密钥、密码）
    MEDIUM = 2    # 追加标识符混淆
    HIGH = 3      # 追加字符串模糊化
    EXTREME = 4   # 追加注释移除


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
    def anonymize(self, text: str,
                  level: AnonymizationLevel = AnonymizationLevel.MEDIUM
                  ) -> AnonymizationResult:
        pass


class CodeAnonymizer(Anonymizer):
    """代码片段匿名化器。

    按规则优先级依次匹配并替换敏感模式，随后依据匿名化级别
    追加标识符混淆、字符串模糊化与注释移除。
    """

    def __init__(self):
        self.rules = self._load_rules()
        self.identifier_mapping: Dict[str, str] = {}
        self.identifier_counter = 0

    def _load_rules(self) -> List[AnonymizationRule]:
        rules = []

        rules.append(AnonymizationRule(
            name="openai_api_key",
            pattern=re.compile(r'sk-[a-zA-Z0-9-]{8,}', re.IGNORECASE),
            replacement='sk-REDACTED_API_KEY',
            description="OpenAI API密钥",
            priority=10))

        rules.append(AnonymizationRule(
            name="aws_api_key",
            pattern=re.compile(r'AKIA[0-9A-Z]{16}', re.IGNORECASE),
            replacement='AKIA_REDACTED_KEY',
            description="AWS Access Key",
            priority=10))

        rules.append(AnonymizationRule(
            name="hex_token",
            pattern=re.compile(r'[0-9a-fA-F]{32,64}'),
            replacement='REDACTED_HEX_TOKEN',
            description="长十六进制令牌",
            priority=9))

        rules.append(AnonymizationRule(
            name="ipv4_address",
            pattern=re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'),
            replacement='X.X.X.X',
            description="IPv4地址",
            priority=8))

        rules.append(AnonymizationRule(
            name="ipv6_address",
            pattern=re.compile(r'(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}'),
            replacement='REDACTED_IPV6',
            description="IPv6地址",
            priority=8))

        rules.append(AnonymizationRule(
            name="email_address",
            pattern=re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'),
            replacement='REDACTED@example.com',
            description="邮箱地址",
            priority=7))

        rules.append(AnonymizationRule(
            name="url",
            pattern=re.compile(r'https?://[^\s]+'),
            replacement='https://REDACTED_URL',
            description="URL地址",
            priority=6))

        rules.append(AnonymizationRule(
            name="windows_path",
            pattern=re.compile(r'C:\\[^\\\s]+\\[^\\\s]+'),
            replacement='C:\\REDACTED\\PATH',
            description="Windows路径",
            priority=5))

        rules.append(AnonymizationRule(
            name="unix_path",
            pattern=re.compile(r'/[^/\s]+/[^/\s]+'),
            replacement='/REDACTED/PATH',
            description="Unix路径",
            priority=5))

        rules.append(AnonymizationRule(
            name="password_literal",
            pattern=re.compile(r'(?:["\'])?password(?:["\'])?\s*[=:]\s*["\'][^"\']+["\']'),
            replacement='password="REDACTED"',
            description="密码字面量赋值",
            priority=10))

        rules.append(AnonymizationRule(
            name="private_key",
            pattern=re.compile(r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----[\s\S]+?-----END'),
            replacement='-----BEGIN PRIVATE KEY-----REDACTED-----END PRIVATE KEY-----',
            description="私钥内容",
            priority=10))

        rules.append(AnonymizationRule(
            name="certificate",
            pattern=re.compile(r'-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----', re.DOTALL),
            replacement='-----BEGIN CERTIFICATE-----REDACTED-----END CERTIFICATE-----',
            description="证书内容",
            priority=10))

        return sorted(rules, key=lambda x: x.priority, reverse=True)

    def anonymize(self, text: str,
                  level: AnonymizationLevel = AnonymizationLevel.MEDIUM
                  ) -> AnonymizationResult:
        original = text
        anonymized = text
        replacements: List[Dict[str, Any]] = []
        warnings: List[str] = []

        self.identifier_mapping = {}
        self.identifier_counter = 0

        for rule in self.rules:
            if not rule.enabled:
                continue
            for match in rule.pattern.finditer(anonymized):
                original_value = match.group()
                if original_value != rule.replacement:
                    anonymized = anonymized.replace(original_value, rule.replacement)
                    replacements.append({
                        'rule': rule.name,
                        'original': original_value,
                        'replacement': rule.replacement,
                        'description': rule.description,
                    })

        if level.value >= AnonymizationLevel.MEDIUM.value:
            anonymized, id_replacements = self._anonymize_identifiers(anonymized)
            replacements.extend(id_replacements)

        if level.value >= AnonymizationLevel.HIGH.value:
            anonymized, str_replacements = self._anonymize_strings(anonymized)
            replacements.extend(str_replacements)

        if level.value == AnonymizationLevel.EXTREME.value:
            anonymized, comment_replacements = self._remove_comments(anonymized)
            replacements.extend(comment_replacements)

        if any(r['rule'] in ('private_key', 'certificate', 'openai_api_key')
               for r in replacements):
            warnings.append("检测到高度敏感信息（私钥/证书/API密钥）")

        return AnonymizationResult(
            original=original,
            anonymized=anonymized,
            replacements=replacements,
            warnings=warnings,
            anonymization_level=level)

    def _anonymize_identifiers(self, text: str) -> Tuple[str, List[Dict[str, Any]]]:
        keywords = {
            'if', 'else', 'for', 'while', 'do', 'switch', 'case', 'default',
            'break', 'continue', 'return', 'goto', 'sizeof', 'typedef',
            'struct', 'union', 'enum', 'const', 'static', 'extern', 'void',
            'char', 'short', 'int', 'long', 'float', 'double', 'signed',
            'unsigned', 'volatile', 'register', 'inline', 'class', 'public',
            'private', 'protected', 'virtual', 'override', 'final', 'new',
            'delete', 'true', 'false', 'nullptr', 'NULL', 'this', 'self',
            'def', 'import', 'from', 'lambda', 'yield', 'async', 'await',
            'try', 'catch', 'throw', 'finally', 'using', 'namespace',
            'template', 'typename', 'auto', 'decltype', 'function', 'module',
            'package', 'interface', 'extends', 'implements', 'abstract',
            'native', 'synchronized', 'transient', 'instanceof', 'typeof',
        }

        replacements: List[Dict[str, Any]] = []
        pattern = re.compile(r'\b([a-zA-Z_][a-zA-Z0-9_]*)\b')

        for match in pattern.findall(text):
            if match not in keywords and len(match) > 2:
                if match not in self.identifier_mapping:
                    self.identifier_counter += 1
                    self.identifier_mapping[match] = f'var_{self.identifier_counter:04d}'
                new_name = self.identifier_mapping[match]
                if new_name != match:
                    text = re.sub(rf'\b{re.escape(match)}\b', new_name, text)
                    replacements.append({
                        'rule': 'identifier',
                        'original': match,
                        'replacement': new_name,
                        'description': '标识符混淆',
                    })
        return text, replacements

    def _anonymize_strings(self, text: str) -> Tuple[str, List[Dict[str, Any]]]:
        replacements: List[Dict[str, Any]] = []

        for quote in ('"', "'"):
            pattern = re.compile(rf'{quote}([^{quote}]*){quote}')
            for match in pattern.findall(text):
                if len(match) > 3:
                    masked = match[:3] + '*' * max(0, len(match) - 3)
                    old_str = f'{quote}{match}{quote}'
                    new_str = f'{quote}{masked}{quote}'
                    text = text.replace(old_str, new_str)
                    replacements.append({
                        'rule': 'string',
                        'original': old_str,
                        'replacement': new_str,
                        'description': '字符串模糊化',
                    })
        return text, replacements

    def _remove_comments(self, text: str) -> Tuple[str, List[Dict[str, Any]]]:
        replacements: List[Dict[str, Any]] = []

        text, count = re.subn(r'//.*$', '// REDACTED', text, flags=re.MULTILINE)
        if count > 0:
            replacements.append({
                'rule': 'comment',
                'original': '// ...',
                'replacement': '// REDACTED',
                'description': '移除单行注释',
                'count': count,
            })

        text, count = re.subn(r'#.*$', '# REDACTED', text, flags=re.MULTILINE)
        if count > 0:
            replacements.append({
                'rule': 'comment',
                'original': '# ...',
                'replacement': '# REDACTED',
                'description': '移除Python注释',
                'count': count,
            })

        text, count = re.subn(r'/\*[\s\S]*?\*/', '/* REDACTED */', text)
        if count > 0:
            replacements.append({
                'rule': 'comment',
                'original': '/* ... */',
                'replacement': '/* REDACTED */',
                'description': '移除多行注释',
                'count': count,
            })
        return text, replacements


class AnonymizationContextManager:
    """匿名化上下文管理器，供调用外部 LLM 的代码路径使用。"""

    def __init__(self, anonymizer: Optional[Anonymizer] = None,
                 level: AnonymizationLevel = AnonymizationLevel.MEDIUM):
        self.anonymizer = anonymizer or CodeAnonymizer()
        self.level = level
        self.last_result: Optional[AnonymizationResult] = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass

    def process(self, text: str) -> str:
        result = self.anonymizer.anonymize(text, self.level)
        self.last_result = result
        if result.warnings:
            import logging
            for warning in result.warnings:
                logging.getLogger(__name__).warning(f"匿名化警告: {warning}")
        return result.anonymized

    def get_last_result(self) -> Optional[AnonymizationResult]:
        return self.last_result


_global_anonymizer: Optional[CodeAnonymizer] = None


def get_anonymizer() -> CodeAnonymizer:
    """获取全局匿名化器实例。"""
    global _global_anonymizer
    if _global_anonymizer is None:
        _global_anonymizer = CodeAnonymizer()
    return _global_anonymizer


def anonymize_code(code: str,
                   level: AnonymizationLevel = AnonymizationLevel.MEDIUM
                   ) -> AnonymizationResult:
    """便捷的代码匿名化函数。"""
    return get_anonymizer().anonymize(code, level)


def is_sensitive_content(text: str) -> bool:
    """检测文本是否包含敏感内容。"""
    sensitive_patterns = [
        r'sk-[a-zA-Z0-9-]{8,}',
        r'AKIA[0-9A-Z]{16}',
        r'-----BEGIN .*PRIVATE KEY-----',
        r'password\s*[=:]\s*["\']',
        r'["\']password["\']',
    ]
    for pattern in sensitive_patterns:
        if re.search(pattern, text, re.IGNORECASE):
            return True
    return False
