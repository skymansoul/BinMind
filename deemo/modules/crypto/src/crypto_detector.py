# 密码学算法检测
# 核心: 魔数常量匹配 + S盒结构分析 + API字符串指纹, 三维正交识别算法。
# Boyer-Moore-Horspool用于大文件加速; S盒检测前16字节quick-eliminate后全256验证。
# 去重策略: 同偏移+同算法 -> 保留高置信度; 同算法+偏移差<16 -> 合并为一个finding。
#
# NTT蝴蝶常量检测(格密码多项式乘法), Keccak-f[1600] RC搜索,
# SM3 IV双端序匹配, ARIA S2独立检测(S1与AES S-box相同需S2消歧义)。
#
# 模糊匹配(_fuzzy_match_sbox) — 逐字节Hamming距离计算, 容忍少量变异。
# 目的: 捕获编译器优化/OLLVM混淆修改少数字节的S-box副本及硬件查表变体。
# 已知误报风险: 随机256B序列与真实S-box距离期望128 +/- 8, 阈值<=4 (~3sigma外)。

from dataclasses import dataclass
from typing import List, Optional
from .constants import (
    AES_SBOX, AES_INV_SBOX, SM4_SBOX, SHA256_IV, SHA512_IV, MD5_IV,
    AES_RCON, CHACHA20_CONSTANTS, CAMELLIA_SBOX, GOST_SBOX,
    AESNI_OPCODES, SHANI_OPCODES, PCLMUL_OPCODES,
    ARIA_S1, ARIA_S2, SEED_SBOX0, SEED_SBOX1, SEED_KC,
    SM3_IV, KECCAK_ROUND_CONSTANTS, BLAKE2_IV, BLAKE3_IV,
    DES_IP,
)
from .utils import shannon_entropy

# 模糊匹配容差 — 权衡: 4字节差异/256 = 1.56%容差。
# P(随机256B序列偶然匹配) ≈ sum_{k=0}^{4} C(256,k)/2^256 ≈ 2^{-183}。
_FUZZY_HAMMING_TOLERANCE = 4

# DES 初始置换表 — 64字节的固定特征常量，用于识别 DES 实现
DES_IP = bytes([
    58, 50, 42, 34, 26, 18, 10,  2,
    60, 52, 44, 36, 28, 20, 12,  4,
    62, 54, 46, 38, 30, 22, 14,  6,
    64, 56, 48, 40, 32, 24, 16,  8,
    57, 49, 41, 33, 25, 17,  9,  1,
    59, 51, 43, 35, 27, 19, 11,  3,
    61, 53, 45, 37, 29, 21, 13,  5,
    63, 55, 47, 39, 31, 23, 15,  7,
])

# 公开常量表 — 供上层引用各算法的特征字节
CRYPTO_CONSTANTS = {
    'aes': {
        'name': 'AES', 'type': 'block_cipher',
        'constants': {
            'sbox': bytes(AES_SBOX),
            'inv_sbox': bytes(AES_INV_SBOX),
            'rcon': bytes(AES_RCON),
        },
    },
    'md5': {
        'name': 'MD5', 'type': 'hash',
        'constants': {'initial': b''.join(w.to_bytes(4, 'little') for w in MD5_IV)},
    },
    'sha256': {
        'name': 'SHA-256', 'type': 'hash',
        'constants': {'initial': SHA256_IV if isinstance(SHA256_IV, bytes) else b''.join(w.to_bytes(4, 'big') for w in SHA256_IV)},
    },
    'des': {
        'name': 'DES', 'type': 'block_cipher',
        'constants': {'ip': DES_IP},
    },
}


def _find_all(data: bytes, pattern: bytes) -> List[int]:
    """返回 pattern 在 data 中的所有出现位置。"""
    _out = []
    _start = 0
    while True:
        _idx = data.find(pattern, _start)
        if _idx == -1:
            break
        _out.append(_idx)
        _start = _idx + 1
    return _out


def _normalize_algo(name: str) -> str:
    """算法名统一为小写短标识，供结果聚合与比对。"""
    _base = name.split(' ')[0].split('/')[0]
    return _base.lower().replace('-', '')


@dataclass
class CryptoFinding:
    algorithm: str
    confidence: float
    evidence: str
    location: int


# //// BMH搜索 — 单次返回下一个匹配位置 ////
def _bmh_search(data: bytes, pattern: bytes, start: int = 0) -> int:
    _dl = len(data)
    _pl = len(pattern)
    if _pl == 0 or _dl < _pl:
        return -1
    _skip = {}
    for _i in range(_pl - 1):
        _skip[pattern[_i]] = _pl - 1 - _i
    _pos = start
    while _pos <= _dl - _pl:
        _j = _pl - 1
        while _j >= 0 and data[_pos + _j] == pattern[_j]:
            _j -= 1
        if _j < 0:
            return _pos
        _bc = data[_pos + _pl - 1]
        _pos += _skip.get(_bc, _pl)
    return -1


def _match_full_sbox(data: bytes, sbox: bytes, start: int) -> bool:
    _dl = len(data)
    if start + 256 > _dl:
        return False
    for _i in range(256):
        if data[start + _i] != sbox[_i]:
            return False
    return True


# S-box模糊匹配
# 计算`start`处256字节窗口与参考`sbox`的逐字节Hamming距离。
# 返回 (is_match, distance, entropy)。
# 设计选择: 精确匹配优先; 模糊匹配仅在精确失败时触发。
def _fuzzy_match_sbox(data: bytes, sbox: bytes, start: int,
                      tolerance: int = _FUZZY_HAMMING_TOLERANCE) -> tuple:
    """
    返回(is_match: bool, hamming_distance: int, approx_entropy: float)。
    256字节随机窗口期望距离128 (二项分布n=256, p=1/256)。
    tolerance <= 4 约3sigma外, P_false ≈ 2^{-183}。
    """
    _dl = len(data)
    if start + 256 > _dl:
        return False, 999, 0.0
    dist = 0
    _win = data[start:start + 256]
    for _i in range(256):
        if _win[_i] != sbox[_i]:
            dist += 1
            if dist > tolerance:
                return False, dist, 0.0
    # 熵合理性检查 — 真实S-box具有接近最大熵
    _ent = shannon_entropy(_win)
    if _ent < 0.97:
        return False, dist, _ent
    return True, dist, _ent


# 魔数常量检测
def detect_by_magic_constants(data: bytes) -> List[CryptoFinding]:
    _out = []

    # AES S-box (正向) / 逆S-box
    for _label, _sbox in [('AES', AES_SBOX), ('AES', AES_INV_SBOX)]:
        _pref = bytes(_sbox[:16])
        _pos = _bmh_search(data, _pref)
        while _pos != -1:
            _tag = 'S-box' if _sbox == AES_SBOX else 'INVERSE S-box'
            if _match_full_sbox(data, _sbox, _pos):
                _out.append(CryptoFinding(
                    algorithm='AES', confidence=0.98,
                    evidence='AES {} at 0x{:x}'.format(_tag, _pos),
                    location=_pos))
            else:
                _is_fuzz, _fuzz_dist, _fuzz_ent = _fuzzy_match_sbox(data, _sbox, _pos)
                if _is_fuzz:
                    _out.append(CryptoFinding(
                        algorithm='AES', confidence=0.82,  # 模糊匹配扣分
                        evidence='AES {}(fuzzy d={},H={:.3f}) at 0x{:x}'.format(_tag, _fuzz_dist, _fuzz_ent, _pos),
                        location=_pos))
            _pos = _bmh_search(data, _pref, _pos + 1)

    # SM4 / GOST / Camellia / ARIA S1 / ARIA S2 / SEED S0 / SEED S1
    _sbox_entries = [
        ('SM4', SM4_SBOX), ('GOST/Kuznyechik', GOST_SBOX),
        ('Camellia', CAMELLIA_SBOX), ('ARIA', ARIA_S1),
        ('ARIA', ARIA_S2), ('SEED', SEED_SBOX0), ('SEED', SEED_SBOX1),
    ]
    for _algo, _sbox in _sbox_entries:
        _pref = bytes(_sbox[:16])
        _pos = _bmh_search(data, _pref)
        while _pos != -1:
            if _match_full_sbox(data, _sbox, _pos):
                _out.append(CryptoFinding(
                    algorithm=_algo, confidence=0.98,
                    evidence='{} S-box at 0x{:x}'.format(_algo, _pos),
                    location=_pos))
            else:
                _is_fuzz, _fuzz_dist, _fuzz_ent = _fuzzy_match_sbox(data, _sbox, _pos)
                if _is_fuzz:
                    _out.append(CryptoFinding(
                        algorithm=_algo, confidence=0.78,
                        evidence='{}(fuzzy d={},H={:.3f}) at 0x{:x}'.format(_algo, _fuzz_dist, _fuzz_ent, _pos),
                        location=_pos))
            _pos = _bmh_search(data, _pref, _pos + 1)

    # SHA256 / SHA512 / MD5 IV
    _iv_entries = [
        ('SHA-256', SHA256_IV, 4, 'big'),
        ('SHA-512', SHA512_IV, 8, 'big'),
        ('MD5', MD5_IV, 4, 'little'),
    ]
    for _name, _iv, _wsize, _endian in _iv_entries:
        if isinstance(_iv, bytes):
            _iv_bytes = _iv
            _iv_words = len(_iv) // _wsize
        else:
            _iv_bytes = b''.join(_w.to_bytes(_wsize, _endian) for _w in _iv)
            _iv_words = len(_iv)
        _pos = _bmh_search(data, _iv_bytes)
        while _pos != -1:
            _out.append(CryptoFinding(
                algorithm=_name, confidence=0.95,
                evidence='{} IV ({}x{}bit) at 0x{:x}'.format(_name, _iv_words, _wsize * 8, _pos),
                location=_pos))
            _pos = _bmh_search(data, _iv_bytes, _pos + 1)

    # SM3 IV (国密哈希) — 双端序搜索
    for _endian, _wsize in [('big', 4), ('little', 4)]:
        _sm3_bytes = b''.join(_w.to_bytes(_wsize, _endian) for _w in SM3_IV)
        _pos = _bmh_search(data, _sm3_bytes)
        while _pos != -1:
            _out.append(CryptoFinding(
                algorithm='SM3', confidence=0.92,
                evidence='SM3 IV ({}, 8x32bit) at 0x{:x}'.format(_endian, _pos),
                location=_pos))
            _pos = _bmh_search(data, _sm3_bytes, _pos + 1)

    # ChaCha20常量
    _pos = _bmh_search(data, CHACHA20_CONSTANTS)
    while _pos != -1:
        _out.append(CryptoFinding(
            algorithm='ChaCha20', confidence=0.96,
            evidence='ChaCha20 "expand 32-byte k" at 0x{:x}'.format(_pos),
            location=_pos))
        _pos = _bmh_search(data, CHACHA20_CONSTANTS, _pos + 1)

    # AES RCON (10字节轮常量序列)
    _rcon_bytes = bytes(AES_RCON)
    _pos = _bmh_search(data, _rcon_bytes[:4])
    while _pos != -1:
        if _pos + 10 <= len(data) and data[_pos:_pos + 10] == _rcon_bytes:
            _out.append(CryptoFinding(
                algorithm='AES', confidence=0.85,
                evidence='AES RCON table at 0x{:x}'.format(_pos),
                location=_pos))
        _pos = _bmh_search(data, _rcon_bytes[:4], _pos + 1)

    # Keccak-f[1600]轮常量 (24x64bit唯一值 — 强鉴别力)
    _krc_bytes = b''.join(_w.to_bytes(8, 'little') for _w in KECCAK_ROUND_CONSTANTS)
    _pos = _bmh_search(data, _krc_bytes[:16])
    while _pos != -1:
        if _pos + 192 <= len(data) and data[_pos:_pos + 192] == _krc_bytes:
            _out.append(CryptoFinding(
                algorithm='SHA-3 (Keccak-f[1600])', confidence=0.97,
                evidence='Keccak-f 24 round constants at 0x{:x}'.format(_pos),
                location=_pos))
        _pos = _bmh_search(data, _krc_bytes[:16], _pos + 1)

    # BLAKE2 IV搜索 (与SHA-512 IV共享初始值 — 消歧义: 同时出现BLAKE2字符串提高置信度)
    _blake2_bytes = b''.join(_w.to_bytes(8, 'little') for _w in BLAKE2_IV)
    _pos = _bmh_search(data, _blake2_bytes[:16])
    while _pos != -1:
        _out.append(CryptoFinding(
            algorithm='BLAKE2', confidence=0.78,
            evidence='BLAKE2 IV at 0x{:x} (可能与SHA-512混淆)'.format(_pos),
            location=_pos))
        _pos = _bmh_search(data, _blake2_bytes[:16], _pos + 1)

    # SEED KC轮密钥常量 (16x32bit, 从黄金比例导出)
    _kc_bytes = b''.join(_w.to_bytes(4, 'little') for _w in SEED_KC)
    _pos = _bmh_search(data, _kc_bytes[:8])
    while _pos != -1:
        _out.append(CryptoFinding(
            algorithm='SEED', confidence=0.88,
            evidence='SEED KC round constants at 0x{:x}'.format(_pos),
            location=_pos))
        _pos = _bmh_search(data, _kc_bytes[:8], _pos + 1)

    return _out


# 结构检测
def detect_by_structure(data: bytes) -> List[CryptoFinding]:
    _out = []
    _dl = len(data)

    # 256字节完美排列 = S-box候选
    for _pos in range(0, _dl - 256, 32):
        _win = data[_pos:_pos + 256]
        if len(set(_win)) == 256:
            _ent = shannon_entropy(_win)
            if _ent > 0.99:
                if _win in (AES_SBOX, AES_INV_SBOX, SM4_SBOX, GOST_SBOX,
                            CAMELLIA_SBOX, ARIA_S1, ARIA_S2, SEED_SBOX0, SEED_SBOX1):
                    continue
                _out.append(CryptoFinding(
                    algorithm='Unknown_Sbox_Permutation', confidence=0.75,
                    evidence='256-byte perfect permutation (H~{:.3f}) at 0x{:x}'.format(_ent, _pos),
                    location=_pos))

    # 16字节重复块 = ECB artifact
    _seen_blocks = {}
    for _pos in range(0, _dl - 16, 16):
        _blk = data[_pos:_pos + 16]
        if _blk in _seen_blocks:
            _first = _seen_blocks[_blk]
            if _pos - _first >= 16:
                _out.append(CryptoFinding(
                    algorithm='AES (ECB_mode嫌疑)', confidence=0.60,
                    evidence='重复16B块 at 0x{:x} / 0x{:x}'.format(_first, _pos),
                    location=_pos))
        else:
            _seen_blocks[_blk] = _pos

    # 64字节重复块 = SHA-512块artifact
    _seen64 = {}
    for _pos in range(0, _dl - 64, 64):
        _blk = data[_pos:_pos + 64]
        if _blk in _seen64:
            _first = _seen64[_blk]
            if _pos - _first >= 64:
                _out.append(CryptoFinding(
                    algorithm='Hash (SHA-512_block嫌疑)', confidence=0.40,
                    evidence='重复64B块 at 0x{:x}/0x{:x}'.format(_first, _pos),
                    location=_pos))
        else:
            _seen64[_blk] = _pos

    # NTT蝴蝶常量检测 — 格密码(Kyber/Dilithium)多项式乘法标志
    # zeta/omega值以(q, 2n)-th primitive root形式出现
    # Kyber q=3329的256-th primitive root = 17; Dilithium q=8380417的512-th root = 1753
    _ntt_primitives = [
        (3329, 17, 2, 'Kyber/ML-KEM (q=3329, 256-th root=17)'),
        (8380417, 1753, 4, 'Dilithium/ML-DSA (q=8380417, 512-th root=1753)'),
    ]
    for _q, _root, _qbytes, _desc in _ntt_primitives:
        _needle = _root.to_bytes(2, 'little')
        _q_bytes = _q.to_bytes(_qbytes, 'little')
        if _q_bytes in data and _needle in data:
            _out.append(CryptoFinding(
                algorithm='Lattice_PQC', confidence=0.72,
                evidence='NTT: {}'.format(_desc), location=data.find(_needle)))

    return _out


# API字符串指纹
_CRYPTO_API_PATTERNS = [
    ('OpenSSL/EV', ['EVP_Encrypt', 'EVP_Decrypt', 'EVP_CIPHER', 'EVP_MD',
                    'EVP_Digest', 'EVP_PKEY', 'EVP_aes_', 'EVP_chacha20',
                    'EVP_sha', 'OPENSSL_init', 'OSSL_PROVIDER']),
    ('OpenSSL/BN', ['BN_bin2bn', 'BN_CTX', 'BN_mod_exp', 'BN_new']),
    ('BCrypt', ['BCryptEncrypt', 'BCryptDecrypt', 'BCryptHash', 'BCryptGenRandom']),
    ('MS-CAPI', ['CryptEncrypt', 'CryptDecrypt', 'CryptAcquireContext',
                 'CryptGenKey', 'CryptHashData', 'CryptImportKey']),
    ('WinCNG', ['BCryptOpenAlgorithmProvider', 'NCryptCreatePersistedKey']),
    ('CC (Apple)', ['CC_SHA1', 'CC_SHA256', 'CC_SHA512', 'CCCrypt',
                    'CC_MD5', 'CCKeyDerivationPBKDF', 'SecKey']),
    ('libsodium', ['crypto_secretbox', 'crypto_sign', 'crypto_box',
                   'crypto_aead', 'crypto_generichash', 'sodium_init']),
    ('Java JCA', ['Cipher.getInstance', 'javax/crypto', 'MessageDigest',
                  'KeyGenerator', 'SecretKeySpec', 'Mac.getInstance']),
    ('Crypto++', ['CryptoPP::', 'AES::Encryption', 'RSA::PrivateKey',
                  'SHA256', 'AutoSeededRandomPool']),
    ('mbedTLS', ['mbedtls_aes_', 'mbedtls_sha256', 'mbedtls_rsa',
                 'mbedtls_ctr_drbg', 'mbedtls_ssl_']),
    ('wolfSSL', ['wc_Aes', 'wc_Sha256', 'wc_Rsa', 'wolfSSL_Init']),
    ('GnuTLS', ['gnutls_', 'GNUTLS_CIPHER_AES']),
    ('NSS', ['PK11_', 'SECKEY_', 'NSS_Init', 'PK11SDR_Encrypt']),
    ('Botan', ['Botan::', 'botan_', 'hash_botan']),
    ('ring', ['ring::aead', 'ring::digest', 'ring::pbkdf2',
              'ring::hmac', 'ring::rand']),
    ('Go crypto', ['crypto/aes', 'crypto/sha256', 'crypto/rsa',
                   'crypto/tls', 'crypto/rand', 'crypto/x509']),
    ('BoringSSL', ['bssl::', 'boringssl', 'EVP_aead_']),
    ('LibreSSL', ['libressl']),
    ('TinyCrypt', ['tc_aes_', 'tc_sha256_', 'tc_hmac_']),
    ('HACL*', ['Hacl_Streaming', 'Hacl_Hash', 'Hacl_AEAD', 'EverCrypt']),
    ('RustCrypto', ['aes::Aes256', 'sha2::Sha256', 'chacha20poly1305',
                    'ed25519_dalek', 'x25519_dalek']),
    ('Nim crypto', ['nimcrypto', 'nimAES', 'nimSHA']),
    ('Zig crypto', ['std.crypto.aes', 'std.crypto.sha2', 'std.crypto.chacha']),
]


def detect_by_api_strings(strings: List[str]) -> List[CryptoFinding]:
    _out = []
    for _lib, _pats in _CRYPTO_API_PATTERNS:
        for _s in strings:
            for _p in _pats:
                if _p.lower() in _s.lower():
                    _out.append(CryptoFinding(
                        algorithm=_lib, confidence=0.70,
                        evidence='API: {} -> {}'.format(_s[:80], _lib),
                        location=0))
                    break
    return _out


# 硬件加速检测
def detect_hardware_accel(data: bytes) -> List[str]:
    _found = []
    for _name, _pat in [('AES-NI', AESNI_OPCODES),
                         ('SHA-NI', SHANI_OPCODES),
                         ('PCLMUL', PCLMUL_OPCODES)]:
        if _bmh_search(data, _pat) != -1:
            _found.append(_name)
    return _found


# 去重
def _dedup(findings: List[CryptoFinding], eps: int = 16) -> List[CryptoFinding]:
    if not findings:
        return []
    _sorted = sorted(findings, key=lambda f: (f.location, -f.confidence))
    _merged = [_sorted[0]]
    for _f in _sorted[1:]:
        _last = _merged[-1]
        if (abs(_f.location - _last.location) <= eps
                and _f.algorithm == _last.algorithm):
            if _f.confidence > _last.confidence:
                _merged[-1] = _f
        elif abs(_f.location - _last.location) <= eps:
            _merged.append(_f)
        else:
            _merged.append(_f)
    return sorted(_merged, key=lambda f: -f.confidence)


# 主检测器
_ALGO_NORM = {
    'AES': 'aes',
    'AES (ECB_mode嫌疑)': 'aes',
    'MD5': 'md5',
    'SHA-256': 'sha256',
    'SHA-512': 'sha512',
    'SM4': 'sm4',
    'SM3': 'sm3',
    'DES': 'des',
    'GOST': 'gost',
    'Blowfish': 'blowfish',
    'CAMELLIA': 'camellia',
    'CHACHA20': 'chacha20',
    'KECCAK': 'keccak',
    'BLAKE2': 'blake2',
    'BLAKE3': 'blake3',
    'ARIA': 'aria',
    'SEED': 'seed',
}

# 公开常量表 — 供上层引用各算法的特征字节
CRYPTO_CONSTANTS = {
    'aes': {
        'name': 'AES', 'type': 'block_cipher',
        'constants': {
            'sbox': bytes(AES_SBOX),
            'inv_sbox': bytes(AES_INV_SBOX),
            'rcon': bytes(AES_RCON),
        },
    },
    'md5': {
        'name': 'MD5', 'type': 'hash',
        'constants': {'initial': b''.join(w.to_bytes(4, 'little') for w in MD5_IV)},
    },
    'sha256': {
        'name': 'SHA-256', 'type': 'hash',
        'constants': {'initial': SHA256_IV if isinstance(SHA256_IV, bytes) else b''.join(w.to_bytes(4, 'big') for w in SHA256_IV)},
    },
    'des': {
        'name': 'DES', 'type': 'block_cipher',
        'constants': {'ip': DES_IP},
    },
}


class CryptoDetector:
    def __init__(self, data: Optional[bytes] = None,
                 strings: Optional[List[str]] = None):
        self._data = data if data is not None else b""
        self._strs = strings or []

    def run_all(self) -> List[CryptoFinding]:
        _all = []
        _all.extend(detect_by_magic_constants(self._data))
        _all.extend(detect_by_structure(self._data))
        if self._strs:
            _all.extend(detect_by_api_strings(self._strs))
        return _dedup(_all)

    def _scan_bytes(self, data: bytes) -> List[CryptoFinding]:
        """字节级扫描，返回算法名规范化为小写的 finding 列表。"""
        strings = _extract_printable(data)
        findings = []
        findings.extend(detect_by_magic_constants(data))
        findings.extend(detect_by_structure(data))
        if strings:
            findings.extend(detect_by_api_strings(strings))
        # DES 初始置换表 —— 弱算法指纹
        try:
            from .constants import DES_IP
            _pos = data.find(DES_IP)
            if _pos >= 0:
                findings.append(CryptoFinding(
                    algorithm='DES', confidence=0.90,
                    evidence='DES IP table at 0x{:x}'.format(_pos), location=_pos))
        except ImportError:
            pass
        for f in findings:
            f.algorithm = _ALGO_NORM.get(f.algorithm, f.algorithm.lower())
        return _dedup(findings)

    def _calculate_entropy(self, data: bytes) -> float:
        return shannon_entropy(data) * 8

    def scan_file(self, path: str):
        """扫描文件，返回 {algorithms, key_candidates, risks} 结构。"""
        from .utils import safeReadBytes as _srb
        raw = _srb(path)
        if raw is None:
            import logging as _log
            _log.getLogger(__name__).error("Cannot open %s", path)
            return []
        strings = _extract_printable(raw)
        det = cls_for_scan(raw, strings)
        return det._build_file_result()

    def format_result(self, result: dict) -> str:
        """格式化扫描结果为可读文本。"""
        lines = ["密码学算法检测结果"]
        for algo in result.get('algorithms', []):
            lines.append("  - {} (confidence={})".format(
                algo.get('name'), algo.get('confidence')))
        for risk in result.get('risks', []):
            lines.append("  [risk] {}: {}".format(
                risk.get('type'), risk.get('description', '')))
        for key in result.get('key_candidates', []):
            lines.append("  [key] offset=0x{:x}".format(
                key.get('offset', 0)))
        return "\n".join(lines)

    def _build_file_result(self) -> dict:
        findings = self._scan_bytes(self._data)
        algorithms = []
        seen = set()
        for f in findings:
            if f.algorithm not in seen:
                seen.add(f.algorithm)
                algorithms.append({'name': f.algorithm, 'confidence': f.confidence})
        risks = []
        if 'des' in seen:
            risks.append({'type': 'weak_algorithm',
                          'description': 'DES 初始置换表 —— 弱加密算法'})
        key_candidates = []
        # 高熵数据段作为潜在硬编码密钥: 16字节窗口内字节去重度高视为候选
        window = 16
        for i in range(0, max(len(self._data) - window, 0) + 1):
            chunk = self._data[i:i + window]
            if len(chunk) < window:
                continue
            if len(set(chunk)) < 14:
                continue
            key_candidates.append({'offset': i, 'entropy': round(self._calculate_entropy(chunk), 3)})
            break
        return {'algorithms': algorithms, 'key_candidates': key_candidates,
                'risks': risks}

    @classmethod
    def scan_bytes(cls, data: bytes) -> list:
        strings = _extract_printable(data)
        det = cls(data, strings)
        return [_finding_to_dict(f) for f in det.run_all()]


def cls_for_scan(data: bytes, strings: Optional[List[str]] = None):
    """scan_file 的实例工厂。"""
    return CryptoDetector(data, strings)


def _extract_printable(data: bytes, min_len: int = 4) -> list:
    import re as _re
    return [m.group().decode('ascii', errors='replace')
            for m in _re.finditer(rb'[\x20-\x7e]{%d,}' % min_len, data)]


def _finding_to_dict(f: CryptoFinding) -> dict:
    return {
        "algorithm": f.algorithm,
        "constant": f.evidence,
        "endian": "any",
        "confidence": f.confidence,
    }
