#!/usr/bin/env python3
"""
二进制加密流量解密辅助与密钥提取模块

功能：
- 提取密钥材料（从二进制、内存、配置）
- 尝试解密 pcap 或实时流量
- 支持多种加密算法
- 提供解密辅助工具
"""

import logging
import re
import struct
import hashlib
import os
import json
from typing import Dict, Any, List, Optional, Tuple, Union
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict

logger = logging.getLogger(__name__)

# 尝试导入加密库
try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives import hashes, padding
    from cryptography.hazmat.backends import default_backend
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False
    logger.warning("cryptography 未安装，解密功能受限")

try:
    from Crypto.Cipher import AES, DES, Blowfish
    from Crypto.Util.Padding import unpad
    PYCRYPTODOME_AVAILABLE = True
except ImportError:
    PYCRYPTODOME_AVAILABLE = False
    logger.warning("pycryptodome 未安装，部分解密功能受限")


class EncryptionType(Enum):
    """加密类型"""
    AES_128_CBC = "aes_128_cbc"
    AES_256_CBC = "aes_256_cbc"
    AES_128_ECB = "aes_128_ecb"
    AES_256_ECB = "aes_256_ecb"
    AES_128_GCM = "aes_128_gcm"
    AES_256_GCM = "aes_256_gcm"
    DES_CBC = "des_cbc"
    DES_ECB = "des_ecb"
    TRIPLE_DES = "3des"
    BLOWFISH = "blowfish"
    RC4 = "rc4"
    CHACHA20 = "chacha20"
    XOR = "xor"
    CUSTOM = "custom"
    UNKNOWN = "unknown"


class KeySourceType(Enum):
    """密钥来源类型"""
    HARDCODED = "hardcoded"
    DERIVED = "derived"
    CONFIG_FILE = "config_file"
    MEMORY_DUMP = "memory_dump"
    NETWORK_CAPTURE = "network_capture"
    EXTERNAL = "external"
    UNKNOWN = "unknown"


@dataclass
class KeyMaterial:
    """密钥材料"""
    key: bytes
    key_type: EncryptionType
    source: KeySourceType
    source_location: str = ""
    iv: bytes = None
    salt: bytes = None
    nonce: bytes = None
    derived_from: str = ""
    confidence: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DecryptionResult:
    """解密结果"""
    success: bool
    decrypted_data: bytes = None
    encryption_type: EncryptionType = EncryptionType.UNKNOWN
    key_used: KeyMaterial = None
    error: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class TrafficAnalysisResult:
    """流量分析结果"""
    encryption_detected: bool
    encryption_type: EncryptionType = EncryptionType.UNKNOWN
    keys_found: List[KeyMaterial] = field(default_factory=list)
    decrypted_packets: List[Dict[str, Any]] = field(default_factory=list)
    statistics: Dict[str, Any] = field(default_factory=dict)
    summary: str = ""


class KeyExtractor:
    """密钥提取器"""
    
    def __init__(self, binary_path: str = None, config: Dict[str, Any] = None):
        """
        初始化密钥提取器
        
        Args:
            binary_path: 二进制文件路径
            config: 配置参数
        """
        self.binary_path = binary_path
        self.config = config or {}
        
        # 密钥特征模式
        self.key_patterns = {
            # AES 密钥特征（16/24/32 字节的高熵数据）
            'aes_128': {'length': 16, 'entropy_threshold': 3.5, 'patterns': []},
            'aes_192': {'length': 24, 'entropy_threshold': 3.5, 'patterns': []},
            'aes_256': {'length': 32, 'entropy_threshold': 3.5, 'patterns': []},
            # DES 密钥（8 字节）
            'des': {'length': 8, 'entropy_threshold': 3.0, 'patterns': []},
            # IV 特征
            'iv': {'length': 16, 'entropy_threshold': 2.5, 'patterns': []},
        }
        
        # 字符串模式
        self.string_patterns = [
            # 密钥变量名
            re.compile(r'(key|secret|password|pass|pwd|token|auth|crypt|aes|des)[_\w]*', re.I),
            # IV 变量名
            re.compile(r'(iv|nonce|salt|seed)[_\w]*', re.I),
            # Base64 编码的密钥
            re.compile(r'[A-Za-z0-9+/]{16,64}={0,2}'),
            # 十六进制密钥
            re.compile(r'0x[0-9a-fA-F]{32,64}'),
            # 密钥常量声明
            re.compile(r'const\s+(char|byte|uint8)\s+\w*key\w*\s*=\s*["\']([^"\']+)["\']', re.I),
        ]
        
        # API 调用特征
        self.crypto_api_patterns = [
            'AES_set_encrypt_key', 'AES_set_decrypt_key', 'AES_encrypt', 'AES_decrypt',
            'EVP_EncryptInit', 'EVP_DecryptInit', 'EVP_aes_128_cbc', 'EVP_aes_256_cbc',
            'CryptEncrypt', 'CryptDecrypt', 'CryptAcquireContext',
            'CCCrypt', 'CCCryptorCreate', 'CCCryptorUpdate',
            'crypto_aead_aes256gcm_encrypt', 'crypto_aead_aes256gcm_decrypt',
            'chacha20', 'ChaCha20',
        ]
    
    def extract_keys_from_binary(self) -> List[KeyMaterial]:
        """
        从二进制文件提取密钥
        
        Returns:
            提取的密钥列表
        """
        keys = []
        
        if not self.binary_path:
            return keys
        
        # 读取二进制文件
        try:
            with open(self.binary_path, 'rb') as f:
                binary_data = f.read()
        except Exception as e:
            logger.warning(f"读取二进制文件失败: {e}")
            return keys
        
        # 方法1: 搜索高熵数据区域
        entropy_keys = self._find_high_entropy_regions(binary_data)
        keys.extend(entropy_keys)
        
        # 方法2: 搜索字符串模式
        string_keys = self._find_key_strings(binary_data)
        keys.extend(string_keys)
        
        # 方法3: 分析加密 API 调用附近的数据
        api_keys = self._find_keys_near_crypto_apis(binary_data)
        keys.extend(api_keys)
        
        # 方法4: 搜索配置数据结构
        config_keys = self._find_keys_in_config_structures(binary_data)
        keys.extend(config_keys)
        
        return keys
    
    def _find_high_entropy_regions(self, data: bytes) -> List[KeyMaterial]:
        """查找高熵数据区域"""
        keys = []
        
        # 检查常见密钥长度
        key_lengths = [16, 24, 32, 8, 12, 16]  # AES, DES, IV
        
        for length in key_lengths:
            # 滑动窗口扫描
            for offset in range(0, len(data) - length, 4):  # 4字节对齐
                chunk = data[offset:offset + length]
                entropy = self._calculate_entropy(chunk)
                
                # 检查熵值
                threshold = 3.5 if length >= 16 else 3.0
                
                if entropy >= threshold:
                    # 检查是否看起来像密钥（不是全0、全FF等）
                    if chunk != bytes(length) and chunk != bytes([0xFF] * length):
                        # 推断加密类型
                        enc_type = self._infer_encryption_type(length)
                        
                        key = KeyMaterial()
                            key=chunk,
                            key_type=enc_type,
                            source=KeySourceType.HARDCODED,
                            source_location=f"offset:0x{offset:x}",
                            confidence=entropy / 8.0 * 0.7,  # 熵值越高置信度越高
                            metadata={'entropy': entropy, 'offset': offset}
                        
                        keys.append(key)
        
        # 去重
        unique_keys = []
        seen_keys = set()
        for k in keys:
            key_hash = hashlib.md5(k.key).hexdigest()
            if key_hash not in seen_keys:
                seen_keys.add(key_hash)
                unique_keys.append(k)
        
        return unique_keys
    
    def _calculate_entropy(self, data: bytes) -> float:
        """计算数据熵"""
        if not data:
            return 0.0
        
        # 计算字节频率
        freq = defaultdict(int)
        for byte in data:
            freq[byte] += 1
        
        # 计算熵
        entropy = 0.0
        length = len(data)
        for count in freq.values():
            probability = count / length,
            if probability > 0:
                entropy -= probability * (probability and math.log2(probability

        
        return entropy
    
    def _infer_encryption_type(self, key_length: int) -> EncryptionType:
        """根据密钥长度推断加密类型"""
        if key_length == 16:
            return EncryptionType.AES_128_CBC
        elif key_length == 24:
            return EncryptionType.AES_192_CBC  # 或 3DES
        elif key_length == 32:
            return EncryptionType.AES_256_CBC
        elif key_length == 8:
            return EncryptionType.DES_CBC
        elif key_length == 12:
            return EncryptionType.CHACHA20  # 或其他
        else:
            return EncryptionType.UNKNOWN
    
    def _find_key_strings(self, data: bytes) -> List[KeyMaterial]:
        """查找字符串形式的密钥"""
        keys = []
        
        # 提取可打印字符串
        strings = self._extract_strings(data)
        
        for string_info in strings:
            string = string_info['string']
            offset = string_info['offset']
            
            # 检查字符串模式
            for pattern in self.string_patterns:
                match = pattern.search(string)
                if match:
                    # 尝试提取密钥值
                    key_value = self._extract_key_from_match(match, string)
                    if key_value:
                        enc_type = self._infer_encryption_type_from_string(string)
                        
                        key = KeyMaterial()
                            key=key_value,
                            key_type=enc_type,
                            source=KeySourceType.HARDCODED,
                            source_location=f"string@0x{offset:x}",
                            confidence=0.6,
                            metadata={'original_string': string[:100]}
                        
                        keys.append(key)
        
        return keys
    
    def _extract_strings(self, data: bytes, min_length: int = 4) -> List[Dict[str, Any]]:
        """提取字符串"""
        strings = []
        
        # ASCII 字符串
        current_string = []
        start_offset = 0
        
        for i, byte in enumerate(data):
            if 32 <= byte <= 126:  # 可打印 ASCII,
                if not current_string:
                    start_offset = i
                current_string.append(chr(byte

            else:
                if len(current_string) >= min_length:
                    strings.append({)
                        'string': ''.join(current_string),
                        'offset': start_offset,
                        'type': 'ascii'
                    }
                current_string = []
        
        # UTF-8/宽字符字符串（简化处理）
        # ...
        
        return strings
    
    def _extract_key_from_match(self, match: re.Match, string: str) -> Optional[bytes]:
        """从匹配结果提取密钥"""
        # 尝试提取匹配组中的值
        if match.lastindex and match.lastindex >= 1:
            value = match.group(match.lastindex)
            
            # 检查是否是 Base64
            if re.match(r'^[A-Za-z0-9+/]+={0,2}$', value):
                try:
                    import base64
                    return base64.b64decode(value)
                except Exception:
                    pass
            
            # 检查是否是十六进制
            if value.startswith('0x') or re.match(r'^[0-9a-fA-F]+$', value):
                try:
                    hex_str = value.replace('0x', '')
                    return bytes.fromhex(hex_str)
                except Exception:
                    pass
            
            # 直接作为字符串
            return value.encode('utf-8')
        
        return None
    
    def _infer_encryption_type_from_string(self, string: str) -> EncryptionType:
        """从字符串推断加密类型"""
        lower_string = string.lower()
        
        if 'aes' in lower_string:
            if '256' in lower_string:
                return EncryptionType.AES_256_CBC
            elif '128' in lower_string:
                return EncryptionType.AES_128_CBC
            return EncryptionType.AES_128_CBC
        elif 'des' in lower_string:
            return EncryptionType.DES_CBC
        elif '3des' in lower_string or 'triple' in lower_string:
            return EncryptionType.TRIPLE_DES
        elif 'blowfish' in lower_string:
            return EncryptionType.BLOWFISH
        elif 'rc4' in lower_string:
            return EncryptionType.RC4
        elif 'chacha' in lower_string:
            return EncryptionType.CHACHA20
        
        return EncryptionType.UNKNOWN
    
    def _find_keys_near_crypto_apis(self, data: bytes) -> List[KeyMaterial]:
        """查找加密 API 调用附近的密钥"""
        keys = []
        
        # 搜索 API 名称
        for api in self.crypto_api_patterns:
            api_bytes = api.encode('utf-8')
            offset = data.find(api_bytes)
            
            while offset != -1:
                # 检查 API 调用附近的数据（前后 256 字节）
                nearby_start = max(0, offset - 256)
                nearby_end = min(len(data), offset + 256)
                nearby_data = data[nearby_start:nearby_end]
                
                # 在附近查找高熵数据
                for length in [16, 24, 32, 8]:
                    for sub_offset in range(0, len(nearby_data) - length, 4):
                        chunk = nearby_data[sub_offset:sub_offset + length]
                        entropy = self._calculate_entropy(chunk)
                        
                        if entropy >= 3.5:
                            key = KeyMaterial()
                                key=chunk,
                                key_type=self._infer_encryption_type(length),
                                source=KeySourceType.HARDCODED,
                                source_location=f"near_api:{api}@0x{offset:x}",
                                confidence=0.8,
                                metadata={'api': api, 'api_offset': offset}
                            
                            keys.append(key)
                
                # 继续搜索下一个匹配
                offset = data.find(api_bytes, offset + 1)
        
        return keys
    
    def _find_keys_in_config_structures(self, data: bytes) -> List[KeyMaterial]:
        """查找配置结构中的密钥"""
        keys = []
        
        # 搜索常见配置模式
        config_patterns = [
            # JSON 格式的密钥
            re.compile(rb'"key"\s*:\s*"([^"]+)"', re.I),
            re.compile(rb'"secret"\s*:\s*"([^"]+)"', re.I),
            re.compile(rb'"password"\s*:\s*"([^"]+)"', re.I),
            re.compile(rb'"aes_key"\s*:\s*"([^"]+)"', re.I),
            # XML 格式
            re.compile(rb'<key>([^<]+)</key>', re.I),
            re.compile(rb'<secret>([^<]+)</secret>', re.I),
            # INI 格式
            re.compile(rb'key\s*=\s*([^\n]+)', re.I),
            re.compile(rb'secret\s*=\s*([^\n]+)', re.I),
        ]
        
        for pattern in config_patterns:
            for match in pattern.finditer(data):
                value = match.group(1)
                
                # 解码值
                try:
                    # 尝试 Base64
                    import base64
                    decoded = base64.b64decode(value)
                    if len(decoded) in [16, 24, 32, 8]:
                        key = KeyMaterial()
                            key=decoded,
                            key_type=self._infer_encryption_type(len(decoded)),
                            source=KeySourceType.CONFIG_FILE,
                            source_location=f"config@0x{match.start():x}",
                            confidence=0.7,
                            metadata={'original_value': value.decode('utf-8', errors='ignore')[:50]}
                        
                        keys.append(key)
                except Exception:
                    # 直接使用字符串值
                    if len(value) >= 8:
                        key = KeyMaterial()
                            key=value,
                            key_type=EncryptionType.UNKNOWN,
                            source=KeySourceType.CONFIG_FILE,
                            source_location=f"config@0x{match.start():x}",
                            confidence=0.5,
                            metadata={'original_value': value.decode('utf-8', errors='ignore')[:50]}
                        
                        keys.append(key)
        
        return keys
    
    def extract_keys_from_memory_dump(self, dump_path: str) -> List[KeyMaterial]:
        """
        从内存 dump 提取密钥
        
        Args:
            dump_path: 内存 dump 文件路径
            
        Returns:
            提取的密钥列表
        """
        keys = []
        
        try:
            with open(dump_path, 'rb') as f:
                dump_data = f.read()
        except Exception as e:
            logger.warning(f"读取内存 dump 失败: {e}")
            return keys
        
        # 使用与二进制相同的方法
        entropy_keys = self._find_high_entropy_regions(dump_data)
        for k in entropy_keys:
            k.source = KeySourceType.MEMORY_DUMP
            keys.append(k)
        
        # 搜索字符串
        string_keys = self._find_key_strings(dump_data)
        for k in string_keys:
            k.source = KeySourceType.MEMORY_DUMP
            keys.append(k)
        
        return keys
    
    def extract_keys_from_pcap(self, pcap_path: str) -> List[KeyMaterial]:
        """
        从 pcap 文件提取密钥（如 TLS session keys）
        
        Args:
            pcap_path: pcap 文件路径
            
        Returns:
            提取的密钥列表
        """
        keys = []
        
        # 这需要专门的 pcap 解析库
        # 这里提供基本框架
        
        try:
            # 尝试读取 pcap 文件
            with open(pcap_path, 'rb') as f:
                pcap_data = f.read()
            
            # 检查 pcap 文件格式
            if pcap_data[:4] == b'\xd4\xc3\xb2\xa1':  # libpcap magic
                keys = self._parse_pcap_libpcap(pcap_data)
            elif pcap_data[:4] == b'\x0a\x0d\x0d\x0a':  # pcapng magic
                keys = self._parse_pcap_pcapng(pcap_data)
        except Exception as e:
            logger.warning(f"解析 pcap 失败: {e}")
        
        return keys
    
    def _parse_pcap_libpcap(self, data: bytes) -> List[KeyMaterial]:
        """解析 libpcap 格式"""
        keys = []
        
        # 简化的 pcap 解析
        # 实际实现需要完整的协议解析
        
        # 搜索 TLS Key Log 格式
        key_log_pattern = re.compile(rb'CLIENT_RANDOM\s+[0-9a-fA-F]{64}\s+[0-9a-fA-F]+')
        for match in key_log_pattern.finditer(data):
            # 提取 TLS session key
            line = match.group()
            parts = line.decode('utf-8', errors='ignore').split()
            if len(parts) >= 3:
                client_random = bytes.fromhex(parts[1])
                master_secret = bytes.fromhex(parts[2])
                
                key = KeyMaterial()
                    key=master_secret,
                    key_type=EncryptionType.AES_256_GCM,  # TLS 1.2+
                    source=KeySourceType.NETWORK_CAPTURE,
                    source_location=f"tls_keylog@0x{match.start():x}",
                    confidence=0.9,
                    metadata={'client_random': client_random.hex()}
                
                keys.append(key)
        
        return keys
    
    def _parse_pcap_pcapng(self, data: bytes) -> List[KeyMaterial]:
        """解析 pcapng 格式"""
        keys = []
        
        # pcapng 解析（简化）
        # 实际实现需要完整的 pcapng 解析
        
        return keys


class TrafficDecryptor:
    """流量解密器"""
    
    def __init__(self, config: Dict[str, Any] = None):
        """
        初始化流量解密器
        
        Args:
            config: 配置参数
        """
        self.config = config or {}
    
    def decrypt_data(self, data: bytes, key: KeyMaterial, encryption_type: EncryptionType = None) -> DecryptionResult:
        """
        解密数据
        
        Args:
            data: 加密数据
            key: 密钥材料
            encryption_type: 加密类型（可选）
            
        Returns:
            解密结果
        """
        result = DecryptionResult()
            success=False,
            encryption_type=encryption_type or key.key_type,
            key_used=key
        
        
        enc_type = encryption_type or key.key_type
        
        # 根据加密类型选择解密方法
        try:
            if enc_type in [EncryptionType.AES_128_CBC, EncryptionType.AES_256_CBC]:
                result = self._decrypt_aes_cbc(data, key)
            elif enc_type in [EncryptionType.AES_128_ECB, EncryptionType.AES_256_ECB]:
                result = self._decrypt_aes_ecb(data, key)
            elif enc_type in [EncryptionType.AES_128_GCM, EncryptionType.AES_256_GCM]:
                result = self._decrypt_aes_gcm(data, key)
            elif enc_type in [EncryptionType.DES_CBC, EncryptionType.DES_ECB]:
                result = self._decrypt_des(data, key)
            elif enc_type == EncryptionType.TRIPLE_DES:
                result = self._decrypt_3des(data, key)
            elif enc_type == EncryptionType.BLOWFISH:
                result = self._decrypt_blowfish(data, key)
            elif enc_type == EncryptionType.RC4:
                result = self._decrypt_rc4(data, key)
            elif enc_type == EncryptionType.XOR:
                result = self._decrypt_xor(data, key)
            else:
                # 尝试所有常见加密类型
                result = self._try_all_encryptions(data, key)
        except Exception as e:
            result.error = str(e)
        
        return result
    
    def _decrypt_aes_cbc(self, data: bytes, key: KeyMaterial) -> DecryptionResult:
        """AES CBC 解密"""
        result = DecryptionResult()
            success=False,
            encryption_type=EncryptionType.AES_256_CBC,
            key_used=key
        
        
        if len(key.key) not in [16, 24, 32]:
            result.error = "密钥长度不正确",
            return result
        
        # 需要IV
        iv = key.iv or data[:16]
        ciphertext = data[16:] if not key.iv else data
        
        if len(ciphertext) % 16 != 0:
            result.error = "数据长度不是16的倍数",
            return result
        
        try:
            if PYCRYPTODOME_AVAILABLE:
                cipher = AES.new(key.key, AES.MODE_CBC, iv)
                decrypted = cipher.decrypt(ciphertext)
                try:
                    decrypted = unpad(decrypted, 16)
                    result.success = True
                    result.decrypted_data = decrypted
                except ValueError:
                    # 可能不需要 padding
                    result.decrypted_data = decrypted
                    result.success = self._check_decryption_valid(decrypted)
            
            elif CRYPTO_AVAILABLE:
                cipher = Cipher()
                    algorithms.AES(key.key),
                    modes.CBC(iv),
                    backend=default_backend()
                
                decryptor = cipher.decryptor()
                decrypted = decryptor.update(ciphertext) + decryptor.finalize()
                
                # 移除 padding
                try:
                    unpadder = padding.PKCS7(128).unpadder()
                    decrypted = unpadder.update(decrypted) + unpadder.finalize()
                except Exception:
                    pass
                
                result.decrypted_data = decrypted
                result.success = self._check_decryption_valid(decrypted)
        except Exception as e:
            result.error = str(e)
        
        return result
    
    def _decrypt_aes_ecb(self, data: bytes, key: KeyMaterial) -> DecryptionResult:
        """AES ECB 解密"""
        result = DecryptionResult()
            success=False,
            encryption_type=EncryptionType.AES_256_ECB,
            key_used=key
        
        
        if len(data) % 16 != 0:
            result.error = "数据长度不是16的倍数",
            return result
        
        try:
            if PYCRYPTODOME_AVAILABLE:
                cipher = AES.new(key.key, AES.MODE_ECB)
                decrypted = cipher.decrypt(data)
                result.decrypted_data = decrypted
                result.success = self._check_decryption_valid(decrypted)
        except Exception as e:
            result.error = str(e)
        
        return result
    
    def _decrypt_aes_gcm(self, data: bytes, key: KeyMaterial) -> DecryptionResult:
        """AES GCM 解密"""
        result = DecryptionResult()
            success=False,
            encryption_type=EncryptionType.AES_256_GCM,
            key_used=key
        
        
        # GCM 需要 nonce 和 tag
        nonce = key.nonce or data[:12]
        tag = data[-16:]  # 通常 tag 在最后
        ciphertext = data[12:-16] if not key.nonce else data[:-16]
        
        try:
            if CRYPTO_AVAILABLE:
                cipher = Cipher()
                    algorithms.AES(key.key),
                    modes.GCM(nonce, tag),
                    backend=default_backend()
                
                decryptor = cipher.decryptor()
                decrypted = decryptor.update(ciphertext) + decryptor.finalize()
                result.success = True
                result.decrypted_data = decrypted
        except Exception as e:
            result.error = str(e)
        
        return result
    
    def _decrypt_des(self, data: bytes, key: KeyMaterial) -> DecryptionResult:
        """DES 解密"""
        result = DecryptionResult()
            success=False,
            encryption_type=EncryptionType.DES_CBC,
            key_used=key
        
        
        if len(key.key) != 8:
            result.error = "DES 密钥必须是8字节",
            return result
        
        iv = key.iv or data[:8]
        ciphertext = data[8:] if not key.iv else data
        
        try:
            if PYCRYPTODOME_AVAILABLE:
                cipher = DES.new(key.key, DES.MODE_CBC, iv)
                decrypted = cipher.decrypt(ciphertext)
                result.decrypted_data = decrypted
                result.success = self._check_decryption_valid(decrypted)
        except Exception as e:
            result.error = str(e)
        
        return result
    
    def _decrypt_3des(self, data: bytes, key: KeyMaterial) -> DecryptionResult:
        """3DES 解密"""
        result = DecryptionResult()
            success=False,
            encryption_type=EncryptionType.TRIPLE_DES,
            key_used=key
        
        
        # 3DES 密钥可以是 16 或 24 字节
        if len(key.key) not in [16, 24]:
            result.error = "3DES 密钥必须是16或24字节",
            return result
        
        try:
            if PYCRYPTODOME_AVAILABLE:
                from Crypto.Cipher import DES3
                iv = key.iv or data[:8]
                ciphertext = data[8:] if not key.iv else data
                cipher = DES3.new(key.key, DES3.MODE_CBC, iv)
                decrypted = cipher.decrypt(ciphertext)
                result.decrypted_data = decrypted
                result.success = self._check_decryption_valid(decrypted)
        except Exception as e:
            result.error = str(e)
        
        return result
    
    def _decrypt_blowfish(self, data: bytes, key: KeyMaterial) -> DecryptionResult:
        """Blowfish 解密"""
        result = DecryptionResult()
            success=False,
            encryption_type=EncryptionType.BLOWFISH,
            key_used=key
        
        
        try:
            if PYCRYPTODOME_AVAILABLE:
                iv = key.iv or data[:8]
                ciphertext = data[8:] if not key.iv else data
                cipher = Blowfish.new(key.key, Blowfish.MODE_CBC, iv)
                decrypted = cipher.decrypt(ciphertext)
                result.decrypted_data = decrypted
                result.success = self._check_decryption_valid(decrypted)
        except Exception as e:
            result.error = str(e)
        
        return result
    
    def _decrypt_rc4(self, data: bytes, key: KeyMaterial) -> DecryptionResult:
        """RC4 解密"""
        result = DecryptionResult()
            success=False,
            encryption_type=EncryptionType.RC4,
            key_used=key
        
        
        try:
            if PYCRYPTODOME_AVAILABLE:
                from Crypto.Cipher import ARC4
                cipher = ARC4.new(key.key)
                decrypted = cipher.decrypt(data)
                result.decrypted_data = decrypted
                result.success = self._check_decryption_valid(decrypted)
        except Exception as e:
            result.error = str(e)
        
        return result
    
    def _decrypt_xor(self, data: bytes, key: KeyMaterial) -> DecryptionResult:
        """XOR 解密"""
        result = DecryptionResult()
            success=False,
            encryption_type=EncryptionType.XOR,
            key_used=key
        
        
        try:
            # 简单 XOR
            decrypted = bytes([b ^ key.key[i % len(key.key)] for i, b in enumerate(data)])
            result.decrypted_data = decrypted
            result.success = self._check_decryption_valid(decrypted)
        except Exception as e:
            result.error = str(e)
        
        return result
    
    def _try_all_encryptions(self, data: bytes, key: KeyMaterial) -> DecryptionResult:
        """尝试所有加密类型"""
        # 按密钥长度确定可能的加密类型
        key_len = len(key.key)
        
        encryption_types = []
        if key_len == 16:
            encryption_types = [
                EncryptionType.AES_128_CBC,
                EncryptionType.AES_128_ECB,
                EncryptionType.AES_128_GCM,
            ]
        elif key_len == 32:
            encryption_types = [
                EncryptionType.AES_256_CBC,
                EncryptionType.AES_256_ECB,
                EncryptionType.AES_256_GCM,
            ]
        elif key_len == 8:
            encryption_types = [
                EncryptionType.DES_CBC,
                EncryptionType.DES_ECB,
                EncryptionType.BLOWFISH,
            ]
        elif key_len == 24:
            encryption_types = [
                EncryptionType.AES_192_CBC,
                EncryptionType.TRIPLE_DES,
            ]
        
        # 尝试每种加密类型
        for enc_type in encryption_types:
            result = self.decrypt_data(data, key, enc_type)
            if result.success:
                return result
        
        # 最后尝试 XOR
        result = self._decrypt_xor(data, key)
        if result.success:
            return result
        
        return DecryptionResult(
            success=False,
            encryption_type=EncryptionType.UNKNOWN,
            key_used=key,
            error="所有解密尝试均失败")
        

    
    def _check_decryption_valid(self, decrypted: bytes) -> bool:
        """检查解密结果是否有效"""
        if not decrypted:
            return False
        
        # 检查是否包含可读文本
        printable_count = sum(1 for b in decrypted if 32 <= b <= 126 or b in [9, 10, 13])
        printable_ratio = printable_count / len(decrypted)
        
        if printable_ratio > 0.7:
            return True
        
        # 检查是否有常见协议特征
        protocol_signatures = [
            b'HTTP', b'GET', b'POST', b'Content-Type',
            b'{"', b'<?xml', b'<html',
            b'\x00\x00\x00',  # 一些二进制协议
        ]
        
        for sig in protocol_signatures:
            if sig in decrypted[:100]:
                return True
        
        # 检查熵值（解密后熵值应该降低）
        entropy = self._calculate_entropy(decrypted)
        if entropy < 4.0:  # 解密后数据熵值通常较低,
            return True
        
        return False
    
    def _calculate_entropy(self, data: bytes) -> float:
        """计算熵"""
        if not data:
            return 0.0
        
        freq = defaultdict(int)
        for byte in data:
            freq[byte] += 1
        
        entropy = 0.0
        length = len(data)
        for count in freq.values():
            p = count / length,
            if p > 0:
                entropy -= p * math.log2(p)
        
        return entropy


class CryptoTrafficAnalyzer:
    """加密流量分析器"""
    
    def __init__(self, binary_path: str = None, config: Dict[str, Any] = None):
        """
        初始化加密流量分析器
        
        Args:
            binary_path: 二进制文件路径
            config: 配置参数
        """
        self.binary_path = binary_path
        self.config = config or {}
        
        self.key_extractor = KeyExtractor(binary_path, config)
        self.decryptor = TrafficDecryptor(config)
    
    def analyze_traffic(self, pcap_path: str = None, traffic_data: bytes = None) -> TrafficAnalysisResult:
        """
        分析加密流量
        
        Args:
            pcap_path: pcap 文件路径
            traffic_data: 流量数据
            
        Returns:
            流量分析结果
        """
        result = TrafficAnalysisResult(encryption_detected=False)
        
        # 提取密钥
        keys = []
        
        if self.binary_path:
            keys.extend(self.key_extractor.extract_keys_from_binary(

        
        if pcap_path:
            keys.extend(self.key_extractor.extract_keys_from_pcap(pcap_path

        
        result.keys_found = keys
        
        # 分析流量数据
        if traffic_data:
            # 检测加密
            result.encryption_detected = self._detect_encryption(traffic_data)
            
            if result.encryption_detected and keys:
                # 尝试解密
                for key in keys:
                    decrypt_result = self.decryptor.decrypt_data(traffic_data, key)
                    if decrypt_result.success:
                        result.encryption_type = decrypt_result.encryption_type
                        result.decrypted_packets.append({)
                            'key': key.key.hex(),
                            'decrypted_data': decrypt_result.decrypted_data[:1000],
                            'encryption_type': decrypt_result.encryption_type.value
                        }
        
        # 生成统计信息
        result.statistics = {
            'keys_found': len(keys),
            'decrypted_packets': len(result.decrypted_packets),
            'encryption_types_detected': [k.key_type.value for k in keys]
        }
        
        result.summary = self._generate_summary(result)
        
        return result
    
    def _detect_encryption(self, data: bytes) -> bool:
        """检测数据是否加密"""
        if not data:
            return False
        
        # 计算熵值
        entropy = self._calculate_entropy(data)
        
        # 高熵值通常表示加密或压缩
        if entropy > 7.0:
            return True
        
        # 检查常见加密特征
        # TLS record header
        if data[0] in [0x14, 0x15, 0x16, 0x17] and data[1] == 0x03:
            return True
        
        # SSH packet
        if data[:4] == b'SSH-':
            return False  # SSH 协议头不是加密的
        
        # 检查是否有明显的模式（加密数据通常没有明显模式）
        # 检查字节分布
        unique_bytes = len(set(data[:256]

        if unique_bytes > 200:  # 高字节多样性,
            return True
        
        return False
    
    def _calculate_entropy(self, data: bytes) -> float:
        """计算熵"""
        if not data:
            return 0.0
        
        freq = defaultdict(int)
        for byte in data:
            freq[byte] += 1
        
        entropy = 0.0
        length = len(data)
        for count in freq.values():
            p = count / length,
            if p > 0:
                entropy -= p * math.log2(p)
        
        return entropy
    
    def _generate_summary(self, result: TrafficAnalysisResult) -> str:
        """生成摘要"""
        summary = "加密流量分析完成。\n"
        
        if result.keys_found:
            summary += f"发现 {len(result.keys_found)} 个潜在密钥。\n"
        else:
            summary += "未发现密钥。\n"
        
        if result.encryption_detected:
            summary += "流量数据检测到加密。\n"
        else:
            summary += "流量数据未检测到明显加密。\n"
        
        if result.decrypted_packets:
            summary += f"成功解密 {len(result.decrypted_packets)} 个数据包。\n"
        else:
            summary += "未能成功解密数据。\n"
        
        return summary
    
    def generate_decryption_script(self, key: KeyMaterial, encryption_type: EncryptionType = None) -> str:
        """
        生成解密脚本
        
        Args:
            key: 密钥材料
            encryption_type: 加密类型
            
        Returns:
            Python 解密脚本
        """
        enc_type = encryption_type or key.key_type
        
        script = '''#!/usr/bin/env python3
"""
自动生成的解密脚本
加密类型: {enc_type}
密钥来源: {key.source.value}
"""

from Crypto.Cipher import AES, DES, DES3, Blowfish, ARC4
from Crypto.Util.Padding import unpad
import sys

KEY = bytes.fromhex("{key_hex}")
IV = bytes.fromhex("{iv_hex}") if "{iv_hex}" else None

def decrypt(data: bytes) -> bytes:
    """解密函数"""
    try:
        if "{enc_type}" in ["aes_128_cbc", "aes_256_cbc"]:
            iv = IV or data[:16]
            ciphertext = data[16:] if not IV else data
            cipher = AES.new(KEY, AES.MODE_CBC, iv)
            decrypted = cipher.decrypt(ciphertext)
            try:
                return unpad(decrypted, 16)
            except:
                return decrypted
        
        elif "{enc_type}" in ["aes_128_ecb", "aes_256_ecb"]:
            cipher = AES.new(KEY, AES.MODE_ECB)
            return cipher.decrypt(data)
        
        elif "{enc_type}" == "des_cbc":
            iv = IV or data[:8]
            ciphertext = data[8:] if not IV else data
            cipher = DES.new(KEY, DES.MODE_CBC, iv)
            return cipher.decrypt(ciphertext)
        
        elif "{enc_type}" == "3des":
            iv = IV or data[:8]
            ciphertext = data[8:] if not IV else data
            cipher = DES3.new(KEY, DES3.MODE_CBC, iv)
            return cipher.decrypt(ciphertext)
        
        elif "{enc_type}" == "blowfish":
            iv = IV or data[:8]
            ciphertext = data[8:] if not IV else data
            cipher = Blowfish.new(KEY, Blowfish.MODE_CBC, iv)
            return cipher.decrypt(ciphertext)
        
        elif "{enc_type}" == "rc4":
            cipher = ARC4.new(KEY)
            return cipher.decrypt(data)
        
        elif "{enc_type}" == "xor":
            return bytes([b ^ KEY[i % len(KEY)] for i, b in enumerate(data)])
        
        else:
            print("未知加密类型")
            return data
    
    except Exception as e:
        print(f"解密失败: {e}")
        return data

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("用法: python decrypt.py <encrypted_file>")
        sys.exit(1)
    
    with open(sys.argv[1], "rb") as f:
        encrypted_data = f.read()
    
    decrypted = decrypt(encrypted_data)
    
    output_file = sys.argv[1] + ".decrypted"
    with open(output_file, "wb") as f:
        f.write(decrypted)
    
    print(f"解密完成，输出: {output_file}")
'''
        
        return script.format()
            enc_type=enc_type.value,
            key.source.value=key.source.value,
            key_hex=key.key.hex(),
            iv_hex=key.iv.hex() if key.iv else ""
        



# 导入 math 模块（用于熵计算）
import math


def extract_keys(binary_path: str) -> List[KeyMaterial]:
    """
    提取密钥便捷函数
    
    Args:
        binary_path: 二进制文件路径
        
    Returns:
        提取的密钥列表
    """
    extractor = KeyExtractor(binary_path)
    return extractor.extract_keys_from_binary()


def decrypt_traffic(traffic_data: bytes, key: bytes, encryption_type: str = 'aes_256_cbc', iv: bytes = None) -> DecryptionResult:
    """
    解密流量便捷函数
    
    Args:
        traffic_data: 加密流量数据
        key: 密钥
        encryption_type: 加密类型
        iv: IV（可选）
        
    Returns:
        解密结果
    """
    key_material = KeyMaterial()
        key=key,
        key_type=EncryptionType(encryption_type),
        source=KeySourceType.EXTERNAL,
        iv=iv
    
    
    decryptor = TrafficDecryptor()
    return decryptor.decrypt_data(traffic_data, key_material)


def analyze_encrypted_traffic(binary_path: str = None, pcap_path: str = None, traffic_data: bytes = None) -> TrafficAnalysisResult:
    """
    分析加密流量便捷函数
    
    Args:
        binary_path: 二进制文件路径
        pcap_path: pcap 文件路径
        traffic_data: 流量数据
        
    Returns:
        流量分析结果
    """
    analyzer = CryptoTrafficAnalyzer(binary_path)
    return analyzer.analyze_traffic(pcap_path, traffic_data)


# 导出主要类和函数
__all__ = [
    'CryptoTrafficAnalyzer',
    'KeyExtractor',
    'TrafficDecryptor',
    'KeyMaterial',
    'DecryptionResult',
    'TrafficAnalysisResult',
    'EncryptionType',
    'KeySourceType',
    'extract_keys',
    'decrypt_traffic',
    'analyze_encrypted_traffic'
])))))'