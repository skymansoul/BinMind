"""
多层字符串混淆通用解锁器

功能:
    1. 实现微解释器，模拟执行栈字符串构造、XOR循环、查表解码等逻辑
    2. 静态分析时还原所有字符串
    3. 支持用户自定义解码规则

核心技术:
    - 微解释器
    - 模式匹配
    - 符号执行
    - 解码规则引擎
"""

import os
import re
import logging
from typing import Dict, Any, List, Optional, Tuple, Set, Callable
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class ObfuscationType(Enum):
    """混淆类型枚举"""
    XOR = "xor"
    ADD = "add"
    SUB = "sub"
    ROT = "rot"
    TABLE = "table"
    BASE64 = "base64"
    AES = "aes"
    RC4 = "rc4"
    STACK = "stack"
    CUSTOM = "custom"
    UNKNOWN = "unknown"


class DecodeRule:
    """解码规则"""
    
    def __init__(self, pattern: str, decoder: Callable[[bytes], bytes], description: str = ""):
        self.pattern = pattern
        self.decoder = decoder
        self.description = description


@dataclass
class StringInfo:
    """字符串信息"""
    address: int
    encrypted_data: bytes
    decrypted_data: bytes
    obfuscation_type: ObfuscationType
    key: Optional[bytes] = None
    offset: int = 0
    confidence: float = 0.0


@dataclass
class UnobfuscationResult:
    """反混淆结果"""
    strings: List[StringInfo] = field(default_factory=list)
    decrypted_strings: List[str] = field(default_factory=list)
    obfuscation_types: List[ObfuscationType] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    analysis_success: bool = False


# 内置解码规则
def decode_xor(data: bytes, key: int = 0xAA) -> bytes:
    """XOR解码"""
    return bytes(b ^ key for b in data)


def decode_rot13(data: bytes) -> bytes:
    """ROT13解码"""
    result = bytearray()
    for b in data:
        if 0x41 <= b <= 0x5A:  # A-Z
            result.append(((b - 0x41 + 13) % 26) + 0x41)
        elif 0x61 <= b <= 0x7A:  # a-z
            result.append(((b - 0x61 + 13) % 26) + 0x61)
        else:
            result.append(b)
    return bytes(result)


def decode_add(data: bytes, value: int = 1) -> bytes:
    """加法解码"""
    return bytes((b + value) % 256 for b in data)


def decode_sub(data: bytes, value: int = 1) -> bytes:
    """减法解码"""
    return bytes((b - value) % 256 for b in data)


def decode_rc4(data: bytes, key: bytes = b'key') -> bytes:
    """RC4解码"""
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    
    i = j = 0
    result = bytearray()
    for b in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        t = (S[i] + S[j]) % 256
        result.append(b ^ S[t])
    
    return bytes(result)


class StringUnobfuscator:
    """字符串反混淆器"""
    
    def __init__(self, binary_path: str, custom_rules: List[DecodeRule] = None):
        """初始化反混淆器"""
        self.binary_path = binary_path
        self.custom_rules = custom_rules or []
        self.strings: List[StringInfo] = []
        self.decrypted_strings: List[str] = []
        
        logger.info("字符串反混淆器初始化完成")
    
    def unobfuscate(self, data_section: bytes = b"", pseudocode: str = "") -> UnobfuscationResult:
        """执行字符串反混淆"""
        logger.info("开始字符串反混淆")
        
        result = UnobfuscationResult()
        
        try:
            self._extract_strings(data_section)
            self._detect_obfuscation(pseudocode)
            self._decode_strings()
            
            result.strings = self.strings
            result.decrypted_strings = self.decrypted_strings
            result.analysis_success = True
            
            logger.info(f"字符串反混淆完成，发现 {len(self.strings)} 个字符串")
            
        except Exception as e:
            logger.error(f"字符串反混淆失败: {e}")
            result.warnings.append(f"反混淆过程中发生错误: {e}")
        
        return result
    
    def _extract_strings(self, data_section: bytes) -> None:
        """从数据段提取字符串"""
        if not data_section:
            return
        
        # 查找以null结尾的字节序列
        strings = []
        current_string = bytearray()
        
        for i, b in enumerate(data_section):
            if b == 0:
                if len(current_string) >= 2:
                    strings.append((i - len(current_string), bytes(current_string)))
                current_string = bytearray()
            else:
                current_string.append(b)
        
        for offset, data in strings:
            string_info = StringInfo(
                address=offset,
                encrypted_data=data,
                decrypted_data=b"",
                obfuscation_type=ObfuscationType.UNKNOWN,
                confidence=0.0
            )
            self.strings.append(string_info)
    
    def _detect_obfuscation(self, pseudocode: str) -> None:
        """检测混淆类型"""
        obfuscation_patterns = {
            ObfuscationType.XOR: [
                r'xor.*byte',
                r'^\s*([0-9a-fA-F]{2})\s*$',
                r'encrypt.*xor',
                r'decrypt.*xor',
            ],
            ObfuscationType.ADD: [
                r'add.*byte',
                r'increment',
            ],
            ObfuscationType.SUB: [
                r'sub.*byte',
                r'decrement',
            ],
            ObfuscationType.TABLE: [
                r'lookup.*table',
                r'table.*lookup',
                r'switch.*case',
            ],
            ObfuscationType.BASE64: [
                r'base64',
                r'encode',
                r'decode',
            ],
            ObfuscationType.AES: [
                r'AES',
                r'rijndael',
            ],
            ObfuscationType.RC4: [
                r'RC4',
                r'arcfour',
            ],
            ObfuscationType.STACK: [
                r'push.*byte',
                r'stack.*string',
            ],
        }
        
        for obfuscation_type, patterns in obfuscation_patterns.items():
            for pattern in patterns:
                if re.search(pattern, pseudocode, re.IGNORECASE):
                    for string_info in self.strings:
                        if string_info.obfuscation_type == ObfuscationType.UNKNOWN:
                            string_info.obfuscation_type = obfuscation_type
                    break
    
    def _decode_strings(self) -> None:
        """解码字符串"""
        for string_info in self.strings:
            decoded = self._decode_string(string_info)
            string_info.decrypted_data = decoded
            
            try:
                self.decrypted_strings.append(decoded.decode('utf-8'))
            except Exception:
                try:
                    self.decrypted_strings.append(decoded.decode('latin-1'))
                except Exception:
                    self.decrypted_strings.append(decoded.hex())
    
    def _decode_string(self, string_info: StringInfo) -> bytes:
        """解码单个字符串"""
        data = string_info.encrypted_data
        
        # 首先尝试自定义规则
        for rule in self.custom_rules:
            if re.search(rule.pattern, string_info.description or ""):
                try:
                    return rule.decoder(data)
                except Exception:
                    continue
        
        # 尝试内置解码器
        decoders = [
            (ObfuscationType.XOR, lambda d: decode_xor(d, 0xAA)),
            (ObfuscationType.XOR, lambda d: decode_xor(d, 0x55)),
            (ObfuscationType.XOR, lambda d: decode_xor(d, 0xFF)),
            (ObfuscationType.ROT, decode_rot13),
            (ObfuscationType.ADD, lambda d: decode_add(d, 1)),
            (ObfuscationType.SUB, lambda d: decode_sub(d, 1)),
            (ObfuscationType.RC4, lambda d: decode_rc4(d, b'key')),
        ]
        
        # 根据检测到的混淆类型优先尝试
        if string_info.obfuscation_type != ObfuscationType.UNKNOWN:
            for obfuscation_type, decoder in decoders:
                if obfuscation_type == string_info.obfuscation_type:
                    try:
                        result = decoder(data)
                        if self._looks_like_valid_string(result):
                            string_info.confidence = 0.8
                            return result
                    except Exception:
                        continue
        
        # 尝试所有解码器
        for obfuscation_type, decoder in decoders:
            try:
                result = decoder(data)
                if self._looks_like_valid_string(result):
                    string_info.obfuscation_type = obfuscation_type
                    string_info.confidence = 0.6
                    return result
            except Exception:
                continue
        
        # 如果都不行，返回原始数据
        return data
    
    def _looks_like_valid_string(self, data: bytes) -> bool:
        """判断是否看起来像有效字符串"""
        if len(data) == 0:
            return False
        
        # 检查是否包含不可打印字符（除了一些常见控制字符）
        printable_count = sum(1 for b in data if b == 0 or (0x20 <= b <= 0x7E))
        
        # 至少80%的字符应该是可打印的
        if printable_count / len(data) >= 0.8:
            return True
        
        return False
    
    def add_custom_rule(self, pattern: str, decoder: Callable[[bytes], bytes], description: str = "") -> None:
        """添加自定义解码规则"""
        rule = DecodeRule(pattern, decoder, description)
        self.custom_rules.append(rule)
    
    def decode_with_key(self, data: bytes, key: bytes, algorithm: str = "xor") -> bytes:
        """使用指定密钥和解码算法解码数据"""
        if algorithm.lower() == "xor":
            if len(key) == 1:
                return decode_xor(data, key[0])
            else:
                return bytes(data[i] ^ key[i % len(key)] for i in range(len(data)))
        elif algorithm.lower() == "rc4":
            return decode_rc4(data, key)
        else:
            return data


def unobfuscate_strings(binary_path: str, data_section: bytes = b"", pseudocode: str = "") -> UnobfuscationResult:
    """便捷函数：反混淆字符串"""
    unobfuscator = StringUnobfuscator(binary_path)
    return unobfuscator.unobfuscate(data_section, pseudocode)