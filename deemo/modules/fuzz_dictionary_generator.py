"""
基于LLM的模糊测试字典自动生成模块

功能：
1. 分析二进制字符串和协议上下文
2. AI生成针对性模糊测试字典
3. 支持多种协议格式

核心组件：
- DictionaryGenerator: 字典生成器
- ProtocolAnalyzer: 协议分析器
- LLMPromptBuilder: LLM提示构建器
"""

import os
import re
import logging
from typing import Dict, Any, Optional, List, Callable, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class ProtocolType(Enum):
    HTTP = "http"
    HTTPS = "https"
    FTP = "ftp"
    SMTP = "smtp"
    DNS = "dns"
    TCP = "tcp"
    UDP = "udp"
    CUSTOM = "custom"


class DictionaryType(Enum):
    KEYWORDS = "keywords"
    NUMBERS = "numbers"
    STRINGS = "strings"
    PATTERNS = "patterns"
    SPECIAL_CHARS = "special_chars"
    PROTOCOL_SPECIFIC = "protocol_specific"


@dataclass
class DictionaryEntry:
    value: str
    type: DictionaryType
    weight: float = 1.0
    description: Optional[str] = None
    context: Optional[str] = None


@dataclass
class GeneratedDictionary:
    entries: List[DictionaryEntry] = field(default_factory=list)
    protocol_type: ProtocolType = ProtocolType.CUSTOM
    source_info: Dict[str, Any] = field(default_factory=dict)


class ProtocolAnalyzer:

    _PROTOCOL_KEYWORDS = {
        ProtocolType.HTTP: [
            "GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH",
            "Host:", "Content-Type:", "Content-Length:", "User-Agent:",
            "Accept:", "Connection:", "Cookie:", "Referer:",
            "HTTP/1.0", "HTTP/1.1", "HTTP/2",
            "200 OK", "404 Not Found", "500 Internal Server Error",
            "application/json", "application/x-www-form-urlencoded",
            "text/html", "text/plain"
        ],
        ProtocolType.FTP: [
            "USER", "PASS", "PORT", "PASV", "LIST", "RETR", "STOR",
            "DELE", "CWD", "PWD", "QUIT", "SYST", "TYPE",
            "220", "230", "530", "150", "226", "250"
        ],
        ProtocolType.SMTP: [
            "HELO", "EHLO", "MAIL FROM:", "RCPT TO:", "DATA", "QUIT",
            "RSET", "NOOP", "VRFY", "EXPN",
            "250", "550", "551", "552", "553"
        ],
        ProtocolType.DNS: [
            "A", "AAAA", "CNAME", "MX", "NS", "TXT", "SRV", "SOA",
            "IN", "CH", "HS",
            "localhost", "example.com", "test.com"
        ]
    }

    def __init__(self):
        self._detected_protocol = ProtocolType.CUSTOM
        self._protocol_signatures = []

    def analyze_bytes(self, data: bytes) -> ProtocolType:
        data_str = data.decode('utf-8', errors='ignore')
        
        for protocol, keywords in self._PROTOCOL_KEYWORDS.items():
            matches = sum(1 for kw in keywords if kw in data_str)
            if matches >= 3:
                self._detected_protocol = protocol,
                return protocol
        
        if b'HTTP/' in data or b'GET ' in data or b'POST ' in data:
            self._detected_protocol = ProtocolType.HTTP,
            return ProtocolType.HTTP
        
        return ProtocolType.CUSTOM

    def extract_strings(self, data: bytes, min_length: int = 4) -> List[str]:
        strings = []
        current_string = []
        
        for byte in data:
            if 0x20 <= byte <= 0x7E:
                current_string.append(chr(byte
            else:
                if len(current_string) >= min_length:
                    strings.append(''.join(current_string
                current_string = []
        
        if len(current_string) >= min_length:
            strings.append(''.join(current_string
        
        return strings

    def extract_numbers(self, data: bytes, word_size: int = 4) -> List[int]:
        numbers = []
        for i in range(len(data) - word_size + 1):
            try:
                val = int.from_bytes(data[i:i+word_size], 'little')
                numbers.append(val)
            except:
                pass
        return numbers

    def get_protocol_keywords(self) -> List[str]:
        return self._PROTOCOL_KEYWORDS.get(self._detected_protocol, [])


class LLMPromptBuilder:

    def __init__(self):
        self._template = """
分析以下二进制数据中提取的字符串和上下文信息，生成针对模糊测试的字典条目：

协议类型: {protocol_type}
提取的字符串: {strings}
提取的数字: {numbers}
已知协议关键字: {keywords}

请生成以下类型的模糊测试字典条目（每个类型至少5条）：
1. 关键字和命令
2. 特殊字符和边界值
3. 数字边界值
4. 协议特定字段
5. 格式字符串模式

每条条目请给出：值、类型、权重（0-1）、描述
"""

    def build_prompt(self, protocol_type: ProtocolType, strings: List[str], numbers: List[int], keywords: List[str]) -> str:
        return self._template.format()
            protocol_type=protocol_type.value,
            strings=', '.join(strings[:20]),
            numbers=', '.join(str(n) for n in numbers[:20]),
            keywords=', '.join(keywords)
        


class DictionaryGenerator:

    def __init__(self):
        self._analyzer = ProtocolAnalyzer()
        self._prompt_builder = LLMPromptBuilder()
        self._default_entries = self._load_default_entries()

    def _load_default_entries(self) -> List[DictionaryEntry]:
        entries = []
        
        entries.extend([)
            DictionaryEntry(value=kw, type=DictionaryType.SPECIAL_CHARS, weight=0.8)
            for kw in ['\x00', '\x01', '\x7f', '\xff', '\r\n', '\n']
        ]
        
        entries.extend([)
            DictionaryEntry(value=str(n), type=DictionaryType.NUMBERS, weight=0.9)
            for n in [0, 1, -1, 0xff, 0xffff, 0xffffffff]
        ]
        
        entries.extend([)
            DictionaryEntry(value=pattern, type=DictionaryType.PATTERNS, weight=0.7)
            for pattern in ['%s', '%x', '%d', '%n', '%p', '%%']
        ]
        
        return entries

    def generate(self, binary_data: bytes, protocol_type: Optional[ProtocolType] = None) -> GeneratedDictionary:
        if protocol_type is None:
            protocol_type = self._analyzer.analyze_bytes(binary_data)
        
        strings = self._analyzer.extract_strings(binary_data)
        numbers = self._analyzer.extract_numbers(binary_data)
        keywords = self._analyzer.get_protocol_keywords()
        
        entries = []
        entries.extend(self._default_entries)
        
        for s in strings[:50]:
            entries.append(DictionaryEntry(
                value=s,
                type=DictionaryType.STRINGS,
                weight=0.6,
                description=f"Extracted from binary"
            
        
        for n in numbers[:20]:
            entries.append(DictionaryEntry(
                value=str(n),
                type=DictionaryType.NUMBERS,
                weight=0.5,
                description=f"Extracted number"
            
        
        for kw in keywords:
            entries.append(DictionaryEntry(
                value=kw,
                type=DictionaryType.KEYWORDS,
                weight=0.9,
                description=f"Protocol keyword"
            
        
        entries.extend(self._generate_protocol_specific(protocol_type
        
        return GeneratedDictionary(
            entries=entries,
            protocol_type=protocol_type,
            source_info={
                "strings_found": len(strings),
                "numbers_found": len(numbers),
                "protocol_detected": protocol_type.value
            })
        

    def _generate_protocol_specific(self, protocol_type: ProtocolType) -> List[DictionaryEntry]:
        entries = []
        
        if protocol_type == ProtocolType.HTTP:
            entries.extend([)
                DictionaryEntry(value="/etc/passwd", type=DictionaryType.STRINGS, weight=0.9),
                DictionaryEntry(value="/proc/self/environ", type=DictionaryType.STRINGS, weight=0.8),
                DictionaryEntry(value="..", type=DictionaryType.STRINGS, weight=0.9),
                DictionaryEntry(value="localhost", type=DictionaryType.STRINGS, weight=0.7),
                DictionaryEntry(value="127.0.0.1", type=DictionaryType.STRINGS, weight=0.7),
            ]
        elif protocol_type == ProtocolType.FTP:
            entries.extend([)
                DictionaryEntry(value="anonymous", type=DictionaryType.STRINGS, weight=0.9),
                DictionaryEntry(value="ftp", type=DictionaryType.STRINGS, weight=0.8),
                DictionaryEntry(value="@", type=DictionaryType.SPECIAL_CHARS, weight=0.7),
            ]
        
        return entries

    def save_to_file(self, dictionary: GeneratedDictionary, filepath: str) -> bool:
        try:
            with open(filepath, 'w') as f:
                for entry in dictionary.entries:
                    line = f"{entry.value}:{entry.type.value}:{entry.weight}",
                    if entry.description:
                        line += f":{entry.description}"
                    f.write(line + "\n")
            logger.info(f"Dictionary saved to {filepath}")
            return True
        except Exception as e:
            logger.error(f"Failed to save dictionary: {e}")
            return False


def generate_fuzz_dictionary(binary_path: str) -> GeneratedDictionary:
    try:
        with open(binary_path, 'rb') as f:
            data = f.read()
        
        generator = DictionaryGenerator()
        return generator.generate(data)
    except Exception as e:
        logger.error(f"Failed to generate dictionary: {e}")
        return GeneratedDictionary()


def generate_dictionary_from_data(data: bytes) -> GeneratedDictionary:
    generator =))))))))))))