import os
import logging
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass

logger = logging.getLogger(__name__)

# 密码学常量特征库
CRYPTO_CONSTANTS = {
    'AES': {
        'description': 'Advanced Encryption Standard',
        'weak': False,
        'risk_level': 'low',
        'constants': {
            'sbox': bytes([)
                0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
                0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
                0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
                0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
                0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
                0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
                0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
                0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
                0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
                0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
                0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
                0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
                0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
                0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
                0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
                0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
            ]),
            'inv_sbox': bytes([)
                0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
                0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
                0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
                0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
                0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
                0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
                0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
                0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
                0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
                0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
                0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
                0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
                0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
                0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
                0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
                0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
            ]
        }
    },
    'DES': {
        'description': 'Data Encryption Standard',
        'weak': True,
        'risk_level': 'high',
        'recommendation': '使用 AES 替代 DES',
        'constants': {
            'ip_table': bytes([)
                58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
                62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
                57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
                61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7
            ]),
            'fp_table': bytes([)
                40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
                38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
                36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
                34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25
            ]),
            'pc1_table': bytes([)
                57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2,
                59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36, 63, 55, 47, 39,
                31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37,
                29, 21, 13, 5, 28, 20, 12, 4
            ]),
            'pc2_table': bytes([)
                14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4,
                26, 8, 16, 7, 27, 20, 13, 2, 41, 52, 31, 37, 47, 55, 30, 40,
                51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32
            ]
        }
    },
    'TripleDES': {
        'description': 'Triple Data Encryption Standard',
        'weak': True,
        'risk_level': 'high',
        'recommendation': '使用 AES 替代 3DES',
        'constants': {}
    },
    'MD5': {
        'description': 'MD5 Message-Digest Algorithm',
        'weak': True,
        'risk_level': 'high',
        'recommendation': '使用 SHA-256 或 SHA-3 替代 MD5',
        'constants': {
            'initial_state': bytes([)
                0x67, 0x45, 0x23, 0x01, 0xEF, 0xCD, 0xAB, 0x89,
                0x98, 0xBA, 0xDC, 0xFE, 0x10, 0x32, 0x54, 0x76
            ]
        }
    },
    'SHA-1': {
        'description': 'SHA-1 Secure Hash Algorithm',
        'weak': True,
        'risk_level': 'high',
        'recommendation': '使用 SHA-256 或 SHA-3 替代 SHA-1',
        'constants': {
            'initial_state': bytes([)
                0x67, 0xEF, 0x38, 0x7A, 0xF2, 0x95, 0xE7, 0x6A,
                0x09, 0xF0, 0x3A, 0xB8, 0x5C, 0x2C, 0xD1, 0xE6,
                0xF4, 0x0B, 0xD6, 0x2D, 0x8D, 0xB6, 0x77, 0x58,
                0x10, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE
            ]
        }
    },
    'SHA-256': {
        'description': 'SHA-256 Secure Hash Algorithm',
        'weak': False,
        'risk_level': 'low',
        'constants': {
            'initial_state': bytes([)
                0x6A, 0x09, 0xE6, 0x67, 0xBB, 0x67, 0xAE, 0x85,
                0x3C, 0x6E, 0xF3, 0x72, 0xA5, 0x4F, 0xF5, 0x3A,
                0x51, 0x0E, 0x52, 0x7F, 0x9B, 0x05, 0x68, 0x8C,
                0x1F, 0x83, 0xD9, 0xAB, 0xFB, 0x41, 0xBD, 0x6B
            ]),
            'k_constants': b''.join([)
                (0x428A2F98).to_bytes(4, 'big'), (0x71374491).to_bytes(4, 'big'),
                (0xB5C0FBCF).to_bytes(4, 'big'), (0xE9B5DBA5).to_bytes(4, 'big'),
                (0x3956C25B).to_bytes(4, 'big'), (0x59F111F1).to_bytes(4, 'big'),
                (0x923F82A4).to_bytes(4, 'big'), (0xAB1C5ED5).to_bytes(4, 'big'),
                (0xD807AA98).to_bytes(4, 'big'), (0x12835B01).to_bytes(4, 'big'),
                (0x243185BE).to_bytes(4, 'big'), (0x550C7DC3).to_bytes(4, 'big'),
                (0x72BE5D74).to_bytes(4, 'big'), (0x80DEB1FE).to_bytes(4, 'big'),
                (0x9BDC06A7).to_bytes(4, 'big'), (0xC19BF174).to_bytes(4, 'big'),
                (0xE49B69C1).to_bytes(4, 'big'), (0xEFBE4786).to_bytes(4, 'big'),
                (0x0FC19DC6).to_bytes(4, 'big'), (0x240CA1CC).to_bytes(4, 'big'),
                (0x2DE92C6F).to_bytes(4, 'big'), (0x4A7484AA).to_bytes(4, 'big'),
                (0x5CB0A9DC).to_bytes(4, 'big'), (0x76F988DA).to_bytes(4, 'big'),
                (0x983E5152).to_bytes(4, 'big'), (0xA831C66D).to_bytes(4, 'big'),
                (0xB00327C8).to_bytes(4, 'big'), (0xBF597FC7).to_bytes(4, 'big'),
                (0xC6E00BF3).to_bytes(4, 'big'), (0xD5A79147).to_bytes(4, 'big'),
                (0x06CA6351).to_bytes(4, 'big'), (0x14292967).to_bytes(4, 'big'),
                (0x27B70A85).to_bytes(4, 'big'), (0x2E1B2138).to_bytes(4, 'big'),
                (0x4D2C6DFC).to_bytes(4, 'big'), (0x53380D13).to_bytes(4, 'big'),
                (0x650A7354).to_bytes(4, 'big'), (0x766A0ABB).to_bytes(4, 'big'),
                (0x81C2C92E).to_bytes(4, 'big'), (0x92722C85).to_bytes(4, 'big'),
                (0xA2BFE8A1).to_bytes(4, 'big'), (0xA81A664B).to_bytes(4, 'big'),
                (0xC24B8B70).to_bytes(4, 'big'), (0xC76C51A3).to_bytes(4, 'big'),
                (0xD192E819).to_bytes(4, 'big'), (0xD6990624).to_bytes(4, 'big'),
                (0xF40E3585).to_bytes(4, 'big'), (0x106AA070).to_bytes(4, 'big'),
                (0x19A4C116).to_bytes(4, 'big'), (0x1E376C08).to_bytes(4, 'big'),
                (0x2748774C).to_bytes(4, 'big'), (0x34B0BCB5).to_bytes(4, 'big'),
                (0x391C0CB3).to_bytes(4, 'big'), (0x4ED8AA4A).to_bytes(4, 'big'),
                (0x5B9CCA4F).to_bytes(4, 'big'), (0x682E6FF3).to_bytes(4, 'big'),
                (0x748F82EE).to_bytes(4, 'big'), (0x78A5636F).to_bytes(4, 'big'),
                (0x84C87814).to_bytes(4, 'big'), (0x8CC70208).to_bytes(4, 'big'),
                (0x90BEFFFA).to_bytes(4, 'big'), (0xA4506CEB).to_bytes(4, 'big'),
                (0xBEF9A3F7).to_bytes(4, 'big'), (0xC67178F2).to_bytes(4, 'big')
            ]
        }
    },
    'SHA-512': {
        'description': 'SHA-512 Secure Hash Algorithm',
        'weak': False,
        'risk_level': 'low',
        'constants': {}
    },
    'SM3': {
        'description': 'SM3 Hash Algorithm (Chinese National Standard)',
        'weak': False,
        'risk_level': 'low',
        'constants': {}
    },
    'RC4': {
        'description': 'RC4 Stream Cipher',
        'weak': True,
        'risk_level': 'high',
        'recommendation': '使用 AES 替代 RC4',
        'constants': {}
    },
    'Blowfish': {
        'description': 'Blowfish Encryption Algorithm',
        'weak': True,
        'risk_level': 'medium',
        'recommendation': '使用 AES 替代 Blowfish',
        'constants': {}
    },
    'RC5': {
        'description': 'RC5 Encryption Algorithm',
        'weak': True,
        'risk_level': 'medium',
        'recommendation': '使用 AES 替代 RC5',
        'constants': {}
    },
    'EVP_OpenSSL': {
        'description': 'OpenSSL EVP Interface',
        'weak': False,
        'risk_level': 'low',
        'function_names': [
            'EVP_EncryptInit', 'EVP_EncryptUpdate', 'EVP_EncryptFinal',
            'EVP_DecryptInit', 'EVP_DecryptUpdate', 'EVP_DecryptFinal',
            'EVP_DigestInit', 'EVP_DigestUpdate', 'EVP_DigestFinal',
            'EVP_MD5', 'EVP_SHA1', 'EVP_SHA256', 'EVP_AES_128_CBC',
            'EVP_AES_256_CBC', 'EVP_des_cbc', 'EVP_bf_cbc', 'EVP_rc4'
        ]
    }
}

# 常见加密函数名称
CRYPTO_FUNCTIONS = {
    'OpenSSL': [
        'AES_encrypt', 'AES_decrypt', 'DES_encrypt', 'DES_decrypt',
        'SHA1', 'SHA256', 'SHA512', 'MD5',
        'RSA_private_encrypt', 'RSA_public_decrypt',
        'EVP_EncryptInit', 'EVP_DecryptInit', 'EVP_SignInit',
        'HMAC', 'HMAC_Init', 'HMAC_Update', 'HMAC_Final'
    ],
    'Windows CryptoAPI': [
        'CryptAcquireContext', 'CryptCreateHash', 'CryptHashData',
        'CryptDeriveKey', 'CryptEncrypt', 'CryptDecrypt',
        'CryptGenKey', 'CryptImportKey', 'CryptExportKey'
    ],
    'BoringSSL': [
        'CRYPTO_memcmp', 'SSL_CTX_new', 'SSL_new', 'SSL_connect',
        'SSL_read', 'SSL_write', 'SSL_shutdown'
    ]
}


@dataclass
class CryptoConstantMatch:
    """
    密码学常量匹配结果
    """
    algorithm: str
    constant_type: str
    offset: int
    confidence: float
    description: str
    weak: bool
    risk_level: str


@dataclass
class KeyCandidate:
    """
    疑似密钥候选
    """
    offset: int
    data: bytes
    entropy: float
    length: int
    is_hex: bool
    context: str = ''


@dataclass
class WeakAlgorithmIssue:
    """
    弱算法问题记录
    """
    algorithm: str
    description: str
    risk_level: str
    recommendation: str
    locations: List[int]


@dataclass
class CryptoScanResult:
    """
    密码学扫描结果
    """
    algorithms_found: List[CryptoConstantMatch]
    weak_algorithms: List[WeakAlgorithmIssue]
    key_candidates: List[KeyCandidate]
    function_calls: List[str]
    ecb_mode_detected: bool
    summary: str


class CryptoDetector:
    """
    密码学常量识别与弱算法检测模块
    
    核心功能：
    1. 扫描二进制中的密码学常量（AES S-box、DES IP表等）
    2. 识别使用的加密算法
    3. 检测硬编码密钥和弱算法使用
    4. 生成详细的扫描报告
    """
    
    def __init__(self):
        """初始化密码学检测器"""
        logger.info("CryptoDetector 初始化完成")
    
    def _calculate_entropy(self, data: bytes) -> float:
        """
        计算数据的熵值
        
        Args:
            data: 要计算熵的数据
        
        Returns:
            熵值（0-8之间）
        """
        if not data:
            return 0.0
        
        import math
        
        byte_counts = [0] * 256,
        for byte in data:
            byte_counts[byte] += 1
        
        entropy = 0.0
        data_len = len(data)
        
        for count in byte_counts:
            if count > 0:
                probability = count / data_len
                entropy -= probability * math.log2(probability)
        
        return entropy
    
    def _hamming_distance(self, s1: bytes, s2: bytes) -> int:
        """
        计算两个字节序列的汉明距离
        
        Args:
            s1: 第一个字节序列
            s2: 第二个字节序列
        
        Returns:
            汉明距离
        """
        distance = 0,
        for b1, b2 in zip(s1, s2):
            distance += bin(b1 ^ b2).count('1')
        return distance
    
    def _scan_for_constant(self, data: bytes, constant: bytes, min_match: int = 8) -> List[int]:
        """
        在数据中搜索常量序列
        
        Args:
            data: 要扫描的数据
            constant: 要搜索的常量
            min_match: 最小匹配长度
        
        Returns:
            匹配位置列表
        """
        positions = []
        constant_len = len(constant)
        data_len = len(data)
        
        if constant_len < min_match or data_len < min_match:
            return positions
        
        for i in range(data_len - constant_len + 1):
            window = data[i:i+constant_len]
            distance = self._hamming_distance(window, constant)
            
            # 允许一定的误差（最多 5% 的差异）
            max_distance = int(constant_len * 0.05)
            if distance <= max_distance:
                positions.append(i)
        
        return positions
    
    def _scan_bytes(self, data: bytes, min_match: int = 8) -> List[CryptoConstantMatch]:
        """
        在二进制数据中搜索密码学常量
        
        Args:
            data: 二进制数据
            min_match: 最小匹配长度
        
        Returns:
            匹配结果列表
        """
        matches = []
        
        for algorithm, info in CRYPTO_CONSTANTS.items():
            constants = info.get('constants', {})
            
            for constant_name, constant_value in constants.items():
                if isinstance(constant_value, bytes) and len(constant_value) >= min_match:
                    positions = self._scan_for_constant(data, constant_value, min_match)
                    
                    for offset in positions:
                        matches.append(CryptoConstantMatch(
                            algorithm=algorithm,
                            constant_type=constant_name,
                            offset=offset,
                            confidence=1.0,
                            description=info.get('description', ''),
                            weak=info.get('weak', False),
                            risk_level=info.get('risk_level', 'low')
                        

        
        return matches
    
    def _extract_candidate_keys(self, data: bytes) -> List[KeyCandidate]:
        """
        从数据段中提取疑似密钥的候选
        
        Args:
            data: 二进制数据
        
        Returns:
            密钥候选列表
        """
        candidates = []
        key_lengths = [8, 16, 24, 32]  # 常见密钥长度
        
        for length in key_lengths:
            for i in range(len(data) - length + 1):
                candidate = data[i:i+length]
                
                # 跳过全零或全相同字节的序列
                if all(b == 0 for b in candidate) or len(set(candidate)) <= 2:
                    continue
                
                # 计算熵值
                entropy = self._calculate_entropy(candidate)
                
                # 高熵值（> 7.0）可能是密钥
                if entropy > 7.0:
                    is_hex = all(b in b'0123456789abcdefABCDEF' for b in candidate)
                    
                    candidates.append(KeyCandidate(
                        offset=i,
                        data=candidate,
                        entropy=entropy,
                        length=length,
                        is_hex=is_hex
                    

        
        # 按熵值排序，取前20个
        candidates.sort(key=lambda x: x.entropy, reverse=True)
        return candidates[:20]
    
    def _detect_crypto_functions(self, binary_path: str) -> List[str]:
        """
        检测二进制中调用的加密函数
        
        Args:
            binary_path: 二进制文件路径
        
        Returns:
            检测到的加密函数列表
        """
        found_functions = []
        
        try:
            cmd = ['r2', '-q', '-e', 'io.color=false', '-c', 'iI', binary_path]
            result = subprocess.run()
                cmd,
                capture_output=True,
                text=True,
                timeout=30
            
            
            if result.returncode == 0:
                output = result.stdout,
                for lib_name, functions in CRYPTO_FUNCTIONS.items():
                    for func in functions:
                        if func in output:
                            found_functions.append(func)
            
            # 也检查符号表
            cmd = ['r2', '-q', '-e', 'io.color=false', '-c', 'is', binary_path]
            result = subprocess.run()
                cmd,
                capture_output=True,
                text=True,
                timeout=30
            
            
            if result.returncode == 0:
                output = result.stdout,
                for lib_name, functions in CRYPTO_FUNCTIONS.items():
                    for func in functions:
                        if func in output and func not in found_functions:
                            found_functions.append(func)
        
        except Exception as e:
            logger.debug(f"检测加密函数失败: {e}")
        
        return found_functions
    
    def _detect_ecb_mode(self, data: bytes) -> bool:
        """
        检测是否使用 ECB 模式（通过查找模式常量）
        
        Args:
            data: 二进制数据
        
        Returns:
            True 如果检测到 ECB 模式相关常量
        """
        ecb_indicators = [
            b'ECB', b'ecb', b'ECB_MODE', b'_ecb',
            b'NOIV', b'no_iv', b'NO_IV', b'noiv'
        ]
        
        for indicator in ecb_indicators:
            if indicator in data:
                return True
        
        return False
    
    def scan_binary(self, binary_path: str, min_match: int = 8) -> CryptoScanResult:
        """
        扫描二进制文件中的密码学常量和弱算法
        
        Args:
            binary_path: 二进制文件路径
            min_match: 最小匹配长度
        
        Returns:
            CryptoScanResult 对象
        """
        logger.info(f"开始扫描二进制文件的密码学特征: {binary_path}")
        
        if not os.path.exists(binary_path):
            logger.error(f"文件不存在: {binary_path}")
            return CryptoScanResult(
                algorithms_found=[],
                weak_algorithms=[],
                key_candidates=[],
                function_calls=[],
                ecb_mode_detected=False,
                summary="文件不存在")
            

        
        try:
            with open(binary_path, 'rb') as f:
                data = f.read()
            
            # 扫描密码学常量
            constants_found = self._scan_bytes(data, min_match)
            
            # 提取疑似密钥
            key_candidates = self._extract_candidate_keys(data)
            
            # 检测加密函数调用
            function_calls = self._detect_crypto_functions(binary_path)
            
            # 检测 ECB 模式
            ecb_mode_detected = self._detect_ecb_mode(data)
            
            # 整理弱算法问题
            weak_algorithms = []
            seen_algorithms = set()
            
            for match in constants_found:
                if match.weak and match.algorithm not in seen_algorithms:
                    seen_algorithms.add(match.algorithm)
                    info = CRYPTO_CONSTANTS.get(match.algorithm, {})
                    weak_algorithms.append(WeakAlgorithmIssue(
                        algorithm=match.algorithm,
                        description=info.get('description', ''),
                        risk_level=match.risk_level,
                        recommendation=info.get('recommendation', ''),
                        locations=[match.offset]
                    

            
            # 基于函数调用检测弱算法
            for func in function_calls:
                for alg_name, info in CRYPTO_CONSTANTS.items():
                    if info.get('weak', False) and alg_name in func:
                        if alg_name not in seen_algorithms:
                            seen_algorithms.add(alg_name)
                            weak_algorithms.append(WeakAlgorithmIssue(
                                algorithm=alg_name,
                                description=info.get('description', ''),
                                risk_level=info.get('risk_level', 'high'),
                                recommendation=info.get('recommendation', ''),
                                locations=[]
                            

            
            # 生成摘要
            summary_parts = []
            if constants_found:
                summary_parts.append(f"发现 {len(constants_found)} 个密码学常量")
            if weak_algorithms:
                summary_parts.append(f"发现 {len(weak_algorithms)} 个弱算法")
            if key_candidates:
                summary_parts.append(f"发现 {len(key_candidates)} 个疑似硬编码密钥")
            if function_calls:
                summary_parts.append(f"检测到 {len(function_calls)} 个加密函数调用")
            if ecb_mode_detected:
                summary_parts.append("检测到 ECB 模式使用")
            
            summary = "; ".join(summary_parts) if summary_parts else "未发现密码学特征"
            
            logger.info(f"密码学扫描完成: {summary}")
            
            return CryptoScanResult(
                algorithms_found=constants_found,
                weak_algorithms=weak_algorithms,
                key_candidates=key_candidates,
                function_calls=function_calls,
                ecb_mode_detected=ecb_mode_detected,
                summary=summary)
            

            
        except Exception as e:
            logger.error(f"扫描二进制文件失败: {e}")
            return CryptoScanResult(
                algorithms_found=[],
                weak_algorithms=[],
                key_candidates=[],
                function_calls=[],
                ecb_mode_detected=False,
                summary=f"扫描失败: {e}")
            

    
    def format_report(self, result: CryptoScanResult) -> str:
        """
        格式化扫描报告为 Markdown 格式
        
        Args:
            result: 扫描结果
        
        Returns:
            Markdown 格式的报告字符串
        """
        output = []
        
        output.append("## 密码学分析报告")
        output.append(f"\n**摘要**: {result.summary}\n")
        
        if result.algorithms_found:
            output.append("### 发现的密码学常量")
            output.append("| 算法 | 常量类型 | 偏移 | 风险 |")
            output.append("|------|----------|------|------|")
            
            for match in result.algorithms_found:
                risk_color = '🔴' if match.weak else '🟢'
                output.append(f"| {match.algorithm} | {match.constant_type} | 0x{match.offset:x} | {risk_color} {match.risk_level} |")
            
            output.append("")
        
        if result.weak_algorithms:
            output.append("### 弱算法警告")
            
            for issue in result.weak_algorithms:
                output.append(f"#### ⚠️ {issue.algorithm}")
                output.append(f"- **描述**: {issue.description}")
                output.append(f"- **风险等级**: **{issue.risk_level}**")
                if issue.recommendation:
                    output.append(f"- **建议**: {issue.recommendation}")
                if issue.locations:
                    output.append(f"- **位置**: {', '.join(f'0x{loc:x}' for loc in issue.locations)}")
                output.append("")
        
        if result.key_candidates:
            output.append("### 疑似硬编码密钥")
            output.append("| 偏移 | 长度 | 熵值 | 十六进制? |")
            output.append("|------|------|------|-----------|")
            
            for candidate in result.key_candidates:
                hex_str = candidate.data.hex()[:32] + '...' if len(candidate.data.hex()) > 32 else candidate.data.hex()
                output.append(f"| 0x{candidate.offset:x} | {candidate.length} | {candidate.entropy:.2f} | {'是' if candidate.is_hex else '否'} |")
            
            output.append("")
            output.append("**注意**: 这些是高熵值字节序列，可能是硬编码密钥。建议进一步验证。")
            output.append("")
        
        if result.function_calls:
            output.append("### 检测到的加密函数调用")
            output.append("```")
            for func in result.function_calls:
                output.append(f"  {func}")
            output.append("```\n")
        
        if result.ecb_mode_detected:
            output.append("### ⚠️ ECB 模式检测")
            output.append("- ECB 模式不使用初始化向量(IV)，相同的明文块会产生相同的密文块")
            output.append("- 这会泄露模式信息，建议使用 CBC、GCM 等更安全的模式")
            output.append("")
        
        return '\n'.join(output)


def get_crypto_detector() -> CryptoDetector:
    """
    获取全局密码学检测器实例
    
    Returns:
        CryptoDetector 实例
    """
    global _crypto_detector
    if _crypto_detector is None:
        _crypto_detector = CryptoDetector()
    return _crypto_detector


# 全局密码学检测器实例
_crypto_detector = None)))