# 密码参数提取器 — 算法检测/密钥提取/IV识别/工作模式推断/常量时间评估

import re, struct, os, math
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any, Tuple
from enum import Enum, auto


# 枚举
class CryptoAlgorithm(Enum):
    AES = "aes"
    DES = "des"
    SM4 = "sm4"
    GOST = "gost"
    CHACHA20 = "chacha20"
    CRC32 = "crc32"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    CUSTOM = "custom"


class BlockCipherMode(Enum):
    ECB = "ecb"
    CBC = "cbc"
    CTR = "ctr"
    GCM = "gcm"
    CCM = "ccm"
    CFB = "cfb"
    OFB = "ofb"
    XTS = "xts"


class CryptoLibrary(Enum):
    OPENSSL = "openssl"
    WOLFSSL = "wolfssl"
    MBEDTLS = "mbedtls"
    WINCRYPT = "wincrypt"
    CNG = "cng"
    COMMON_CRYPTO = "common_crypto"
    BOTAN = "botan"
    CUSTOM = "custom"


# 数据结构
@dataclass
class KeyMaterial:
    key_bytes: bytes = field(default_factory=bytes)
    format: str = ""           # 'hex' | 'base64' | 'array'
    offset_in_binary: int = 0
    algorithm: str = ""


@dataclass
class ConstantTimeScore:
    is_constant_time: bool = True
    confidence: float = 0.0
    evidence: List[str] = field(default_factory=list)


# S-Box 常量
class SBoxConstants:
    AES_SBOX: bytes = bytes([
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
    ])

    AES_INV_SBOX: bytes = bytes([
        0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
        0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
        0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
        0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
        0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
        0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
        0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
        0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
        0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
        0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
        0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
        0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
        0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
        0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
        0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
    ])

    # SM4 S-box (国密)
    SM4_SBOX: bytes = bytes([
        0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
        0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
        0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
        0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
        0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
        0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
        0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
        0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
        0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
        0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
        0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
        0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
        0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
        0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
        0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
        0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48,
    ])

    # GOST S-box (CryptoPro 参数集)
    GOST_SBOX: bytes = bytes([
        0xfc, 0xee, 0xdd, 0x11, 0xcf, 0x6e, 0x31, 0x16, 0xfb, 0xc4, 0xfa, 0xda, 0x23, 0xc5, 0x04, 0x4d,
        0xe9, 0x77, 0xf0, 0xdb, 0x93, 0x2e, 0x99, 0xba, 0x17, 0x36, 0xf1, 0xbb, 0x14, 0xcd, 0x5f, 0xc1,
        0xf9, 0x18, 0x65, 0x5a, 0xe2, 0x5c, 0xef, 0x21, 0x81, 0x1c, 0x3c, 0x42, 0x8b, 0x01, 0x8e, 0x4f,
        0x05, 0x12, 0x02, 0x1f, 0xc3, 0xa7, 0x6c, 0xe7, 0xdc, 0x51, 0x73, 0x7e, 0xb4, 0x7b, 0x39, 0x6f,
        0x5b, 0x69, 0x15, 0x8c, 0x1b, 0xcc, 0x3a, 0xb1, 0x78, 0x45, 0x6a, 0x75, 0xce, 0x0c, 0x8a, 0x80,
        0x7c, 0xfd, 0x48, 0x8f, 0xc8, 0x91, 0x07, 0x9a, 0x00, 0x98, 0x19, 0x83, 0x70, 0x56, 0x06, 0x50,
        0x57, 0x1e, 0x5e, 0x29, 0xed, 0x55, 0x7f, 0xac, 0xca, 0x9e, 0xdf, 0x2c, 0x38, 0x27, 0xcb, 0x74,
        0x4b, 0xbe, 0x85, 0xf4, 0x88, 0xb6, 0x52, 0x34, 0x09, 0xa4, 0xb2, 0xad, 0x0e, 0xc2, 0x53, 0x6b,
        0x35, 0xc7, 0xb5, 0x96, 0x28, 0x76, 0xbc, 0x67, 0xf6, 0xd0, 0xe0, 0xb7, 0x87, 0xd5, 0x94, 0x2b,
        0xc9, 0x54, 0xd2, 0x3f, 0x46, 0x08, 0x9b, 0x41, 0x33, 0xd1, 0x86, 0xb8, 0x26, 0x2d, 0xbf, 0xd7,
        0xaf, 0xf5, 0xa8, 0x2a, 0x13, 0x0b, 0xea, 0x1a, 0x8d, 0x20, 0x84, 0x7d, 0x79, 0x0a, 0xd3, 0x97,
        0x1d, 0x9d, 0x03, 0x7a, 0x4a, 0xc0, 0x71, 0xa9, 0x92, 0xa0, 0x59, 0xa1, 0x2f, 0x22, 0x0f, 0xe1,
        0x47, 0xf2, 0x62, 0xb3, 0x6d, 0x40, 0xab, 0x32, 0x82, 0xd8, 0x60, 0x5d, 0x10, 0xb0, 0x9f, 0x95,
        0xaa, 0x24, 0x3d, 0x4c, 0x37, 0x89, 0x58, 0xbd, 0x4e, 0xeb, 0xf8, 0xec, 0xa3, 0x0d, 0xc6, 0xd4,
        0x43, 0x30, 0xa6, 0x72, 0x3b, 0xe4, 0x49, 0x25, 0x63, 0xd6, 0x90, 0xde, 0x3e, 0x64, 0x9c, 0xe6,
        0xff, 0xd9, 0xe5, 0xae, 0xf3, 0xa5, 0x61, 0x66, 0x44, 0xdb, 0xe8, 0xba, 0xf7, 0xa2, 0x68, 0xe3,
    ])


# AlgorithmDetector
class AlgorithmDetector:
    def __init__(self, data: bytes = b''):
        self._data = data
        self.SBox = SBoxConstants()

    def detect_algorithm(self, data: bytes = None) -> CryptoAlgorithm:
        buf = data if data is not None else self._data
        if not buf or len(buf) < 16:
            return CryptoAlgorithm.CUSTOM

        checks = [
            (self._detect_aes, CryptoAlgorithm.AES),
            (self._detect_sm4, CryptoAlgorithm.SM4),
            (self._detect_gost, CryptoAlgorithm.GOST),
            (self._detect_crc32, CryptoAlgorithm.CRC32),
        ]
        for checker, algo in checks:
            if checker(buf):
                return algo
        if self._detect_chacha20(buf):
            return CryptoAlgorithm.CHACHA20
        if self._detect_sha(buf):
            return CryptoAlgorithm.SHA256
        if self._detect_md5(buf):
            return CryptoAlgorithm.MD5
        return CryptoAlgorithm.CUSTOM

    def _scan_sboxes(self, data: bytes) -> List[Tuple[str, int]]:
        hits: List[Tuple[str, int]] = []
        sb = self.SBox
        sbox_map = [
            ('AES', sb.AES_SBOX),
            ('AES_INV', sb.AES_INV_SBOX),
            ('SM4', sb.SM4_SBOX),
            ('GOST', sb.GOST_SBOX),
        ]
        for name, sbox in sbox_map:
            idx = data.find(sbox)
            if idx != -1:
                hits.append((name, idx))
            # 有时 S-box 首字节被 DWORD 对齐偏移，检查前 16 字节即可匹配
            first16 = sbox[:16]
            pos = data.find(first16)
            if pos != -1 and (name, pos) not in hits:
                hits.append((name, pos))
        return hits

    def _detect_aes(self, data: bytes) -> bool:
        sb = self.SBox
        return (sb.AES_SBOX in data or sb.AES_INV_SBOX in data
                or sb.AES_SBOX[:16] in data or sb.AES_INV_SBOX[:16] in data)

    def _detect_sm4(self, data: bytes) -> bool:
        sb = self.SBox
        return (sb.SM4_SBOX in data or sb.SM4_SBOX[:16] in data)

    def _detect_gost(self, data: bytes) -> bool:
        sb = self.SBox
        return (sb.GOST_SBOX in data or sb.GOST_SBOX[:16] in data)

    def _detect_crc32(self, data: bytes) -> bool:
        poly_le = struct.pack('<I', 0xEDB88320)
        poly_be = struct.pack('>I', 0xEDB88320)
        poly_le2 = struct.pack('<I', 0x82F63B78)
        poly_be2 = struct.pack('>I', 0x82F63B78)
        return (poly_le in data or poly_be in data or poly_le2 in data or poly_be2 in data)

    def _detect_chacha20(self, data: bytes) -> bool:
        return b'expand 32-byte k' in data or b'expand 16-byte k' in data

    def _detect_sha(self, data: bytes) -> bool:
        sha256_iv = bytes([
            0x6a, 0x09, 0xe6, 0x67, 0xbb, 0x67, 0xae, 0x85,
            0x3c, 0x6e, 0xf3, 0x72, 0xa5, 0x4f, 0xf5, 0x3a,
        ])
        sha1_iv = bytes([
            0x67, 0x45, 0x23, 0x01, 0xef, 0xcd, 0xab, 0x89,
            0x98, 0xba, 0xdc, 0xfe, 0x10, 0x32, 0x54, 0x76,
        ])
        return sha256_iv in data or sha1_iv in data

    def _detect_md5(self, data: bytes) -> bool:
        md5_iv = struct.pack('<IIII', 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476)
        return md5_iv in data


# KeyExtractor
class KeyExtractor:
    _HEX_KEY_RE = re.compile(rb'(?:0x)?([0-9A-Fa-f]{16,128})')
    _BASE64_KEY_RE = re.compile(rb'["\']?([A-Za-z0-9+/]{24,}={0,2})["\']?')
    _ARRAY_KEY_RE = re.compile(rb'\{[\s]*0x[0-9a-fA-F]{2}(?:[\s]*,[\s]*0x[0-9a-fA-F]{2}){15,63}[\s]*\}')

    def extract_keys(self, data: bytes, algo: str = "") -> List[KeyMaterial]:
        keys: List[KeyMaterial] = []
        if not data:
            return keys

        # Hex 编码密钥
        for match in self._HEX_KEY_RE.finditer(data):
            hex_str = match.group(1)
            if len(hex_str) in (32, 48, 64, 96, 128):  # 128/192/256 bits
                key_bytes = bytes.fromhex(hex_str.decode('ascii'))
                keys.append(KeyMaterial(
                    key_bytes=key_bytes, format='hex',
                    offset_in_binary=match.start(), algorithm=algo,
                ))

        # Base64 编码密钥
        for match in self._BASE64_KEY_RE.finditer(data):
            b64_str = match.group(1)
            try:
                import base64
                key_bytes = base64.b64decode(b64_str)
                if len(key_bytes) in (16, 24, 32):  # 符合常见密钥长度
                    keys.append(KeyMaterial(
                        key_bytes=key_bytes, format='base64',
                        offset_in_binary=match.start(), algorithm=algo,
                    ))
            except Exception:
                continue

        # C 数组样式
        for match in self._ARRAY_KEY_RE.finditer(data):
            array_str = match.group(0)
            hex_vals = re.findall(rb'0x([0-9a-fA-F]{2})', array_str)
            if 16 <= len(hex_vals) <= 64:
                key_bytes = bytes(int(h, 16) for h in hex_vals)
                keys.append(KeyMaterial(
                    key_bytes=key_bytes, format='array',
                    offset_in_binary=match.start(), algorithm=algo,
                ))

        return keys


# IVExtractor
class IVExtractor:
    def extract_iv(self, data: bytes, algo: CryptoAlgorithm = None) -> List[bytes]:
        ivs: List[bytes] = []
        if not data or len(data) < 8:
            return ivs

        # AES: 16 字节 IV — 扫描前后有 "IV", "iv", "nonce" 等标识符的模式
        iv_patterns = {16: br'(?:IV|iv|nonce|initial)[\s:=]{0,4}',
                       8: br'(?:IV|iv|nonce|initial)[\s:=]{0,4}'}
        sizes = {CryptoAlgorithm.AES: 16, CryptoAlgorithm.DES: 8,
                 CryptoAlgorithm.SM4: 16, CryptoAlgorithm.GOST: 8}

        target_size = sizes.get(algo, 16)
        i = 0
        while i < len(data) - target_size:
            window = data[i:i + target_size]
            # 熵过滤: 全零/全0xFF 的 "IV" 不像是真正的 IV
            if window and len(set(window)) > 2 and not all(b == 0 for b in window):
                # 检查前后上下文
                ctx_before = data[max(0, i - 8):i]
                if b'IV' in ctx_before or b'iv' in ctx_before or b'nonce' in ctx_before.lower():
                    ivs.append(window)
                    i += target_size
                    continue
                # 或前后无上下文时的随机性检测
                entropy = self._byte_entropy(window)
                if entropy > 3.5:  # 高熵 → 可能是 IV
                    ivs.append(window)
                    i += target_size
                    continue
            i += 1

        return ivs[:10]

    @staticmethod
    def _byte_entropy(data: bytes) -> float:
        if not data:
            return 0.0
        freq = [0] * 256
        for b in data:
            freq[b] += 1
        return -sum(f / len(data) * math.log2(f / len(data)) for f in freq if f > 0)


# ModeDetector
class ModeDetector:
    _GHASH_CONST = struct.pack('>Q', 0xE100000000000000)  # GCM GF(2^128) reduction polynomial

    def detect_mode(self, data: bytes, algo: CryptoAlgorithm = None) -> BlockCipherMode:
        if not data or len(data) < 32:
            return BlockCipherMode.ECB

        # GCM 检测: GHASH 常量 + 乘法表
        if self._detect_gcm(data):
            return BlockCipherMode.GCM

        # CTR: counter increment 模式 (add 1, adc 0 序列)
        counter_patterns = [br'\x83\xc0\x01', br'\xff\xc0', br'\x48\xff\xc0']
        ctr_count = 0
        for pat in counter_patterns:
            ctr_count += data.count(pat)
        if ctr_count >= 2:
            return BlockCipherMode.CTR

        # CBC: XOR 模式 — 在加密前后有 XOR 操作的序列
        xor_count = 0
        for i in range(0, len(data) - 4, 1):
            if data[i:i + 1] == b'\x31' or data[i:i + 1] == b'\x33':  # XOR reg, reg or XOR mem, reg
                xor_count += 1
        if xor_count > 10:
            return BlockCipherMode.CBC

        # ECB: 无明显链式操作的重复块调用
        return BlockCipherMode.ECB

    def _detect_gcm(self, data: bytes) -> bool:
        if self._GHASH_CONST in data:
            return True
        # GHASH 域乘法表: 16*16=256 字节预计算表
        # 在 data 中查找连续 256 字节的高熵表
        for i in range(0, len(data) - 256, 16):
            window = data[i:i + 256]
            if len(set(window)) > 200:
                return True
        return False


# ConstantTimeDetector
class ConstantTimeDetector:
    def assess_constant_time(self, data: bytes, func_addr: int = None) -> ConstantTimeScore:
        evidence: List[str] = []
        is_ct = True

        if not data:
            return ConstantTimeScore(is_constant_time=True, confidence=0.0, evidence=[])

        # 检查条件分支指令 (x86/x64) 是否依赖于数据
        # jz/jnz/jl/jg/jb/ja 等
        cond_jumps = [b'\x74', b'\x75', b'\x7c', b'\x7d', b'\x7e', b'\x7f',
                      b'\x72', b'\x77', b'\x0f\x84', b'\x0f\x85',
                      b'\x0f\x8c', b'\x0f\x8d', b'\x0f\x8e', b'\x0f\x8f']
        jump_count = 0
        for jmp in cond_jumps:
            jump_count += data.count(jmp)

        if jump_count > 20:
            is_ct = False
            evidence.append(f'found {jump_count} conditional branches — potential key-dependent control flow')

        # 检查循环内是否有可变长度操作 (rep movs/cmps)
        prefix_rep_count = data.count(b'\xf3') + data.count(b'\xf2')
        if prefix_rep_count > 5:
            is_ct = False
            evidence.append(f'rep prefix count={prefix_rep_count} — variable-length memory ops')

        # 检查位测试指令 (bt/bts/btr) — 常用于逐位处理密钥
        bt_count = 0
        for i in range(len(data) - 1):
            if data[i] == 0x0f and data[i + 1] in (0xa3, 0xab, 0xb3, 0xbb):
                bt_count += 1
        if bt_count > 3:
            evidence.append(f'bit test instructions found={bt_count}')

        confidence = 1.0 if is_ct else max(0.1, 1.0 - (jump_count / 50.0))
        return ConstantTimeScore(
            is_constant_time=is_ct,
            confidence=round(confidence, 2),
            evidence=evidence,
        )


# LibraryDetector
class LibraryDetector:
    _LIB_SYMBOLS = {
        CryptoLibrary.OPENSSL: [b'EVP_', b'SSL_', b'OPENSSL_', b'CRYPTO_', b'PEM_', b'PKCS'],
        CryptoLibrary.WOLFSSL: [b'wolfSSL_', b'wolfCrypt_', b'wc_'],
        CryptoLibrary.MBEDTLS: [b'mbedtls_', b'mbedtls_aes', b'mbedtls_sha'],
        CryptoLibrary.WINCRYPT: [b'CryptAcquireContext', b'CryptEncrypt', b'CryptDecrypt',
                                  b'CryptHashData', b'CryptDeriveKey'],
        CryptoLibrary.CNG: [b'BCrypt', b'NCrypt', b'BCryptOpenAlgorithmProvider',
                             b'BCryptEncrypt', b'BCryptDecrypt'],
        CryptoLibrary.COMMON_CRYPTO: [b'CCCryptorCreate', b'CC_SHA256', b'CCCrypt',
                                       b'CC_MD5', b'CC_SHA1'],
        CryptoLibrary.BOTAN: [b'Botan::', b'Botan_', b'botan_'],
    }

    def detect_crypto_library(self, binary_path: str) -> CryptoLibrary:
        if not binary_path or not os.path.isfile(binary_path):
            return CryptoLibrary.CUSTOM
        try:
            with open(binary_path, 'rb') as fh:
                data = fh.read()
        except OSError:
            return CryptoLibrary.CUSTOM

        scores: Dict[CryptoLibrary, int] = {}
        for lib, symbols in self._LIB_SYMBOLS.items():
            count = 0
            for sym in symbols:
                count += data.count(sym)
                if count >= 3:
                    break
            if count > 0:
                scores[lib] = count

        if scores:
            return max(scores, key=scores.get)
        return CryptoLibrary.CUSTOM


# CryptoParamExtractor (兼容)
class CryptoParamExtractor:
    def __init__(self, path: str = ''):
        self.path = path
        self._raw: bytes | None = None
        self._findings: list = []
        self._detector = AlgorithmDetector()

    def _load(self):
        if self._raw is not None:
            return
        if self.path and os.path.isfile(self.path):
            with open(self.path, 'rb') as f:
                self._raw = f.read()

    def extract(self):
        self._load()
        if not self._raw:
            try:
                from plugins.crypto_scan import scan_crypto
                return scan_crypto(self.path)
            except ImportError:
                return []

        # 算法检测
        algo = self._detector.detect_algorithm(self._raw)

        # S-box 扫描
        sbox_hits = self._detector._scan_sboxes(self._raw)

        # 密钥提取
        ke = KeyExtractor()
        algo_name = algo.value
        key_matches = ke.extract_keys(self._raw, algo_name)

        findings: List[dict] = []

        for name, offset in sbox_hits:
            findings.append({
                'type': 'sbox',
                'algorithm': name,
                'offset': offset,
                'confidence': 0.90 if len(name) > 3 else 0.75,
            })

        for km in key_matches:
            findings.append({
                'type': 'key',
                'algorithm': km.algorithm or algo_name,
                'offset': km.offset_in_binary,
                'key_size': len(km.key_bytes) * 8,
                'format': km.format,
                'confidence': 0.80,
            })

        self._findings = findings
        return [
            {'type': f['type'], 'algorithm': f['algorithm'],
             'offset': f['offset'], 'confidence': f['confidence']}
            for f in findings
        ]

    def extract_params(self):
        findings = self.extract()
        algo_counts: Dict[str, int] = {}
        for f in findings:
            algo = f.get('algorithm', '')
            algo_counts[algo] = algo_counts.get(algo, 0) + 1
        dominant = max(algo_counts, key=algo_counts.get) if algo_counts else 'unknown'

        spec = {
            'AES': {'key_size': 256, 'rounds': 14, 'mode': 'CBC'},
            'AES_INV': {'key_size': 256, 'rounds': 14, 'mode': 'CBC'},
            'SM4': {'key_size': 128, 'rounds': 32, 'mode': 'CBC'},
            'GOST': {'key_size': 256, 'rounds': 32, 'mode': 'ECB'},
            'DES': {'key_size': 56, 'rounds': 16, 'mode': 'CBC'},
            'SHA256': {'key_size': 0, 'rounds': 64, 'mode': 'hash'},
            'MD5': {'key_size': 0, 'rounds': 64, 'mode': 'hash'},
            'RC4': {'key_size': 128, 'rounds': 1, 'mode': 'stream'},
            'ChaCha20': {'key_size': 256, 'rounds': 20, 'mode': 'stream'},
            'CHACHA20': {'key_size': 256, 'rounds': 20, 'mode': 'stream'},
            'CRC32': {'key_size': 0, 'rounds': 1, 'mode': 'hash'},
            'SHA1': {'key_size': 0, 'rounds': 80, 'mode': 'hash'},
        }

        params = dict(spec.get(dominant, {'key_size': 128, 'rounds': 10, 'mode': 'unknown'}))
        params['algorithm'] = dominant
        params['confidence'] = 0.7 if dominant != 'unknown' else 0.3

        if dominant == 'AES':
            md = ModeDetector()
            mode = md.detect_mode(self._raw or b'', CryptoAlgorithm.AES)
            params['mode'] = mode.value

        return params

    def identify_algorithm(self):
        params = self.extract_params()
        return params.get('algorithm', 'unknown')


# 顶层便捷函数
def scan_crypto(filepath: str) -> list:
    """兼容 plugins.crypto_scan 的 scan_crypto 入口"""
    extractor = CryptoParamExtractor(filepath)
    return extractor.extract()


def _scan_bytes(data: bytes) -> list:
    """扫描二进制数据中的密码常量"""
    findings = []
    if not data or len(data) < 16:
        return findings
    detector = AlgorithmDetector(data)
    sbox_hits = detector._scan_sboxes(data)
    for name, offset in sbox_hits:
        findings.append({
            'algorithm': name, 'offset': offset,
            'size': 256, 'label': f'{name} S-box',
            'confidence': 0.85,
        })
    # 检查 SHA/MD5 常量
    sha256_iv = bytes([0x6a, 0x09, 0xe6, 0x67, 0xbb, 0x67, 0xae, 0x85,
                       0x3c, 0x6e, 0xf3, 0x72, 0xa5, 0x4f, 0xf5, 0x3a])
    idx = 0
    while True:
        idx = data.find(sha256_iv, idx)
        if idx == -1:
            break
        findings.append({'algorithm': 'SHA256', 'offset': idx, 'confidence': 0.90})
        idx += 1
    return findings
