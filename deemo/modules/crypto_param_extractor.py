"""
密码学算法参数自动提取模块

功能:
    1. 在crypto_detector.py基础上，从数据段或堆栈引用链提取密钥、IV、S-box常量
    2. 生成可重用的解密脚本（Python或C）

核心技术:
    - 数据段分析
    - 常量提取
    - 模式匹配
    - 脚本生成
"""

import os
import re
import logging
from typing import Dict, Any, List, Optional, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class CryptoAlgorithm(Enum):
    """密码学算法枚举"""
    AES = "AES"
    DES = "DES"
    TripleDES = "3DES"
    RSA = "RSA"
    ECC = "ECC"
    SHA1 = "SHA-1"
    SHA256 = "SHA-256"
    SHA512 = "SHA-512"
    MD5 = "MD5"
    RC4 = "RC4"
    Blowfish = "Blowfish"
    Twofish = "Twofish"
    Serpent = "Serpent"
    ChaCha20 = "ChaCha20"
    Poly1305 = "Poly1305"
    Unknown = "Unknown"


class ParamType(Enum):
    """参数类型枚举"""
    KEY = "key"
    IV = "iv"
    SBOX = "sbox"
    CONSTANT = "constant"
    MODULUS = "modulus"
    EXPONENT = "exponent"
    PRIVATE_KEY = "private_key"
    PUBLIC_KEY = "public_key"
    NONCE = "nonce"
    TAG = "tag"


@dataclass
class CryptoParameter:
    """密码学参数"""
    algorithm: CryptoAlgorithm
    param_type: ParamType
    value: bytes
    address: int = 0
    confidence: float = 0.0
    description: str = ""


@dataclass
class ExtractedKey:
    """提取的密钥信息"""
    algorithm: CryptoAlgorithm
    key: bytes
    iv: Optional[bytes] = None
    key_size: int = 0
    address: int = 0


@dataclass
class ExtractionResult:
    """提取结果"""
    parameters: List[CryptoParameter] = field(default_factory=list)
    keys: List[ExtractedKey] = field(default_factory=list)
    detected_algorithms: List[CryptoAlgorithm] = field(default_factory=list)
    python_script: str = ""
    c_script: str = ""
    warnings: List[str] = field(default_factory=list)
    analysis_success: bool = False


# 已知的S-box常量模式
SBOX_PATTERNS = {
    'AES': [
        bytes([0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5]),
        bytes([0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76]),
    ],
    'DES': [
        bytes([0xE3, 0xFD, 0xD3, 0x61, 0x01, 0x02, 0x04, 0x08]),
        bytes([0x10, 0x20, 0x40, 0x80, 0x1B, 0x36, 0x6C, 0xD8]),
    ],
}

# 算法特征常量
ALGORITHM_CONSTANTS = {
    'AES': [
        (10, 128),  # rounds, key_size
        (12, 192),
        (14, 256),
    ],
    'SHA256': [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ],
    'SHA512': [
        0x6a09e667f3bcc908, 0xbb67ae8584caa73b,
        0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
    ],
}


class CryptoParamExtractor:
    """密码学参数提取器"""
    
    def __init__(self, binary_path: str, binary_info: Dict[str, Any] = None):
        """初始化提取器"""
        self.binary_path = binary_path
        self.binary_info = binary_info or {}
        self.parameters: List[CryptoParameter] = []
        self.keys: List[ExtractedKey] = []
        self.detected_algorithms: List[CryptoAlgorithm] = []
        
        logger.info("密码学参数提取器初始化完成")
    
    def extract_parameters(self, pseudocode: str = "", data_section: bytes = b"") -> ExtractionResult:
        """提取密码学参数"""
        logger.info("开始提取密码学参数")
        
        result = ExtractionResult()
        
        try:
            self._detect_algorithms(pseudocode)
            self._extract_from_pseudocode(pseudocode)
            self._extract_from_data_section(data_section)
            self._generate_scripts(result)
            
            result.parameters = self.parameters
            result.keys = self.keys
            result.detected_algorithms = self.detected_algorithms
            result.analysis_success = True
            
            logger.info(f"密码学参数提取完成，发现 {len(self.parameters)} 个参数，{len(self.keys)} 个密钥")
            
        except Exception as e:
            logger.error(f"密码学参数提取失败: {e}")
            result.warnings.append(f"提取过程中发生错误: {e}")
        
        return result
    
    def _detect_algorithms(self, pseudocode: str) -> None:
        """检测使用的密码学算法"""
        algorithm_patterns = {
            CryptoAlgorithm.AES: [r'AES', r'_AES_', r'aes_encrypt', r'aes_decrypt'],
            CryptoAlgorithm.DES: [r'DES', r'_DES_', r'des_encrypt'],
            CryptoAlgorithm.RSA: [r'RSA', r'_RSA_', r'rsa_encrypt', r'rsa_decrypt'],
            CryptoAlgorithm.SHA256: [r'SHA256', r'sha256_', r'SHA-256'],
            CryptoAlgorithm.SHA512: [r'SHA512', r'sha512_', r'SHA-512'],
            CryptoAlgorithm.MD5: [r'MD5', r'md5_'],
            CryptoAlgorithm.RC4: [r'RC4', r'rc4_'],
            CryptoAlgorithm.ChaCha20: [r'ChaCha', r'chacha20_'],
        }
        
        for algorithm, patterns in algorithm_patterns.items():
            for pattern in patterns:
                if re.search(pattern, pseudocode, re.IGNORECASE):
                    if algorithm not in self.detected_algorithms:
                        self.detected_algorithms.append(algorithm)
                        logger.debug(f"检测到算法: {algorithm.value}")
                    break
    
    def _extract_from_pseudocode(self, pseudocode: str) -> None:
        """从伪代码中提取参数"""
        # 提取十六进制常量
        hex_pattern = r'0x([0-9a-fA-F]{2,})'
        matches = re.findall(hex_pattern, pseudocode)
        
        for match in matches:
            # 尝试解析为字节序列
            try:
                if len(match) % 2 == 0:
                    value = bytes.fromhex(match)
                    
                    # 根据长度判断可能的参数类型
                    if len(value) in [16, 24, 32]:
                        param_type = ParamType.KEY
                        self._detect_aes_key(value)
                    elif len(value) == 16:
                        param_type = ParamType.IV
                    elif len(value) == 16 and self._is_possible_sbox(value):
                        param_type = ParamType.SBOX
                    else:
                        param_type = ParamType.CONSTANT
                    
                    param = CryptoParameter(
                        algorithm=self._guess_algorithm(value),
                        param_type=param_type,
                        value=value,
                        confidence=0.7
                    )
                    self.parameters.append(param)
            except Exception:
                pass
    
    def _detect_aes_key(self, value: bytes) -> None:
        """检测AES密钥"""
        key_sizes = {16: 128, 24: 192, 32: 256}
        
        if len(value) in key_sizes:
            key = ExtractedKey(
                algorithm=CryptoAlgorithm.AES,
                key=value,
                key_size=key_sizes[len(value)]
            )
            self.keys.append(key)
    
    def _is_possible_sbox(self, value: bytes) -> bool:
        """判断是否可能是S-box"""
        # 检查是否包含典型的S-box值范围
        unique_values = set(value)
        if len(unique_values) == 256:
            return True
        return False
    
    def _guess_algorithm(self, value: bytes) -> CryptoAlgorithm:
        """根据值猜测算法"""
        key_sizes = {16: CryptoAlgorithm.AES, 24: CryptoAlgorithm.AES, 32: CryptoAlgorithm.AES}
        if len(value) in key_sizes:
            return key_sizes[len(value)]
        
        return CryptoAlgorithm.Unknown
    
    def _extract_from_data_section(self, data_section: bytes) -> None:
        """从数据段提取参数"""
        if not data_section:
            return
        
        # 扫描可能的密钥（16/24/32字节的连续数据）
        key_sizes = [16, 24, 32]
        for size in key_sizes:
            for i in range(len(data_section) - size + 1):
                candidate = data_section[i:i+size]
                
                # 检查是否看起来像随机密钥（不是全零或全相同字节）
                if self._looks_like_key(candidate):
                    param = CryptoParameter(
                        algorithm=self._guess_algorithm(candidate),
                        param_type=ParamType.KEY,
                        value=candidate,
                        address=i,
                        confidence=0.6
                    )
                    self.parameters.append(param)
    
    def _looks_like_key(self, data: bytes) -> bool:
        """判断数据是否看起来像密钥"""
        # 检查是否全零
        if all(b == 0 for b in data):
            return False
        
        # 检查是否全相同字节
        if len(set(data)) == 1:
            return False
        
        # 检查熵值（简单版本）
        entropy = self._calculate_entropy(data)
        if entropy < 2.0:
            return False
        
        return True
    
    def _calculate_entropy(self, data: bytes) -> float:
        """计算数据的熵值"""
        from math import log2
        
        if len(data) == 0:
            return 0.0
        
        freq = {}
        for byte in data:
            freq[byte] = freq.get(byte, 0) + 1
        
        entropy = 0.0
        total = len(data)
        for count in freq.values():
            prob = count / total
            entropy -= prob * log2(prob)
        
        return entropy
    
    def _generate_scripts(self, result: ExtractionResult) -> None:
        """生成解密脚本"""
        result.python_script = self._generate_python_script()
        result.c_script = self._generate_c_script()
    
    def _generate_python_script(self) -> str:
        """生成Python解密脚本"""
        lines = []
        lines.append("#!/usr/bin/env python3")
        lines.append("\"\"\"")
        lines.append("自动生成的解密脚本")
        lines.append("由密码学参数提取模块生成")
        lines.append("\"\"\"")
        lines.append("")
        lines.append("import sys")
        lines.append("from Crypto.Cipher import AES")
        lines.append("from Crypto.Util.Padding import unpad")
        lines.append("")
        lines.append("# 提取的密钥")
        lines.append("KEYS = {")
        
        for key in self.keys:
            key_hex = key.key.hex()
            lines.append(f"    '{key.algorithm.value}_{key.key_size}': bytes.fromhex('{key_hex}'),")
        
        lines.append("}")
        lines.append("")
        lines.append("# 提取的IV")
        lines.append("IVS = {")
        
        for param in self.parameters:
            if param.param_type == ParamType.IV:
                iv_hex = param.value.hex()
                lines.append(f"    '{param.algorithm.value}': bytes.fromhex('{iv_hex}'),")
        
        lines.append("}")
        lines.append("")
        lines.append("def decrypt_aes(ciphertext: bytes, key: bytes, iv: bytes = None) -> bytes:")
        lines.append("    \"\"\"AES解密函数\"\"\"")
        lines.append("    if iv is None:")
        lines.append("        iv = b'\\x00' * 16")
        lines.append("    cipher = AES.new(key, AES.MODE_CBC, iv)")
        lines.append("    try:")
        lines.append("        return unpad(cipher.decrypt(ciphertext), AES.block_size)")
        lines.append("    except ValueError:")
        lines.append("        return cipher.decrypt(ciphertext)")
        lines.append("")
        lines.append("if __name__ == '__main__':")
        lines.append("    if len(sys.argv) < 2:")
        lines.append("        print(f\"Usage: {sys.argv[0]} <cipherfile>\")")
        lines.append("        sys.exit(1)")
        lines.append("")
        lines.append("    with open(sys.argv[1], 'rb') as f:")
        lines.append("        ciphertext = f.read()")
        lines.append("")
        lines.append("    for key_name, key in KEYS.items():")
        lines.append("        print(f\"\\n尝试密钥: {key_name}\")")
        lines.append("        iv = IVS.get('AES')")
        lines.append("        try:")
        lines.append("            plaintext = decrypt_aes(ciphertext, key, iv)")
        lines.append("            print(f\"解密结果: {plaintext[:100].hex()}\")")
        lines.append("        except Exception as e:")
        lines.append("            print(f\"解密失败: {e}\")")
        
        return "\n".join(lines)
    
    def _generate_c_script(self) -> str:
        """生成C解密脚本"""
        lines = []
        lines.append("/**")
        lines.append(" * 自动生成的解密脚本")
        lines.append(" * 由密码学参数提取模块生成")
        lines.append(" */")
        lines.append("")
        lines.append("#include <stdio.h>")
        lines.append("#include <stdlib.h>")
        lines.append("#include <string.h>")
        lines.append("#include <openssl/aes.h>")
        lines.append("")
        lines.append("// 提取的密钥")
        
        for key in self.keys:
            key_hex = key.key.hex()
            key_bytes = ", ".join([f"0x{key_hex[i:i+2]}" for i in range(0, len(key_hex), 2)])
            lines.append(f"unsigned char {key.algorithm.value.lower()}_key_{key.key_size}[] = {{{key_bytes}}};")
        
        lines.append("")
        lines.append("// 提取的IV")
        for param in self.parameters:
            if param.param_type == ParamType.IV:
                iv_hex = param.value.hex()
                iv_bytes = ", ".join([f"0x{iv_hex[i:i+2]}" for i in range(0, len(iv_hex), 2)])
                lines.append(f"unsigned char {param.algorithm.value.lower()}_iv[] = {{{iv_bytes}}};")
        
        lines.append("")
        lines.append("int aes_decrypt(unsigned char *ciphertext, int len, unsigned char *key, int key_len, ")
        lines.append("               unsigned char *iv, unsigned char *plaintext) {")
        lines.append("    AES_KEY aes_key;")
        lines.append("    ")
        lines.append("    if (AES_set_decrypt_key(key, key_len * 8, &aes_key) < 0) {")
        lines.append("        return -1;")
        lines.append("    }")
        lines.append("    ")
        lines.append("    AES_cbc_encrypt(ciphertext, plaintext, len, &aes_key, iv, AES_DECRYPT);")
        lines.append("    return 0;")
        lines.append("}")
        lines.append("")
        lines.append("int main(int argc, char *argv[]) {")
        lines.append("    if (argc < 2) {")
        lines.append("        printf(\"Usage: %s <cipherfile>\\n\", argv[0]);")
        lines.append("        return 1;")
        lines.append("    }")
        lines.append("")
        lines.append("    FILE *f = fopen(argv[1], \"rb\");")
        lines.append("    if (!f) {")
        lines.append("        perror(\"fopen\");")
        lines.append("        return 1;")
        lines.append("    }")
        lines.append("")
        lines.append("    fseek(f, 0, SEEK_END);")
        lines.append("    long size = ftell(f);")
        lines.append("    fseek(f, 0, SEEK_SET);")
        lines.append("")
        lines.append("    unsigned char *ciphertext = malloc(size);")
        lines.append("    fread(ciphertext, 1, size, f);")
        lines.append("    fclose(f);")
        lines.append("")
        lines.append("    unsigned char *plaintext = malloc(size);")
        lines.append("    aes_decrypt(ciphertext, size, aes_key_128, 16, aes_iv, plaintext);")
        lines.append("")
        lines.append("    printf(\"Decrypted data:\\n\");")
        lines.append("    for (int i = 0; i < size && i < 100; i++) {")
        lines.append("        printf(\"%02x \", plaintext[i]);")
        lines.append("    }")
        lines.append("    printf(\"\\n\");")
        lines.append("")
        lines.append("    free(ciphertext);")
        lines.append("    free(plaintext);")
        lines.append("    return 0;")
        lines.append("}")
        
        return "\n".join(lines)


def extract_crypto_parameters(binary_path: str, pseudocode: str = "", data_section: bytes = b"") -> ExtractionResult:
    """便捷函数：提取密码学参数"""
    extractor = CryptoParamExtractor(binary_path)
    return extractor.extract_parameters(pseudocode, data_section)