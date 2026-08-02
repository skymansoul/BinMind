# 2026-07-21
# 密码库指纹识别 — 通过导出符号/字符串/指令模式识别静态链接的密码库。
# 覆盖 OpenSSL/BoringSSL/LibreSSL, mbedTLS, wolfSSL, libsodium, NSS, Botan,
# Crypto++, GnuTLS, Go crypto, ring, rust-crypto, Zig, Nim, HACL*, EverCrypt。
# 策略：枚举各库独有的版本字符串+内部函数名前缀组合。
#
# 2026-07-25: 新增 RustCrypto trait 检测, Zig std.crypto, Nim nimcrypto,
# EverCrypt/HACL* 验证套件, MatrixSSL, AWS-LC, SymCrypt 指纹。

import re
from dataclasses import dataclass, field
from typing import List
from .utils import find_pattern


@dataclass
class LibraryMatch:
    lib_name: str
    version_hint: str
    confidence: float
    evidence: List[str] = field(default_factory=list)


_LIB_SIGNATURES = [
    # OpenSSL 家族
    (rb'OpenSSL\s+([\d.]+[a-z]*)', 'OpenSSL', 0.95),
    (rb'BoringSSL', 'BoringSSL', 0.95),
    (rb'LibreSSL\s+([\d.]+)', 'LibreSSL', 0.95),
    (rb'SSLeay\s+([\d.]+)', 'OpenSSL (legacy)', 0.8),
    (rb'openssl-([\d.]+)', 'OpenSSL', 0.9),
    # AWS-LC (Amazon Linux Crypto)
    (rb'AWS-LC\s+([\d.]+)', 'AWS-LC', 0.93),
    (rb'awslc_version', 'AWS-LC', 0.85),
    # mbedTLS / PolarSSL
    (rb'mbed TLS\s+([\d.]+)', 'mbedTLS', 0.95),
    (rb'PolarSSL\s+([\d.]+)', 'mbedTLS (legacy)', 0.85),
    # wolfSSL
    (rb'wolfSSL\s+([\d.]+)', 'wolfSSL', 0.95),
    (rb'CyaSSL\s+([\d.]+)', 'wolfSSL (legacy)', 0.85),
    # libsodium
    (rb'libsodium\s+([\d.]+)', 'libsodium', 0.95),
    (rb'NaCl\s+library', 'NaCl', 0.7),
    # NSS
    (rb'NSS\s+([\d.]+)', 'NSS', 0.95),
    (rb'@\(#\)NSS', 'NSS (Solaris)', 0.9),
    # Botan
    (rb'Botan\s+([\d.]+)', 'Botan', 0.95),
    # Crypto++
    (rb'CryptoPP\s+([\d.]+)', 'Crypto++', 0.9),
    (rb'Crypto\+\+\s+([\d.]+)', 'Crypto++', 0.9),
    # GnuTLS
    (rb'GnuTLS\s+([\d.]+)', 'GnuTLS', 0.95),
    # MatrixSSL
    (rb'MatrixSSL\s+([\d.]+)', 'MatrixSSL', 0.95),
    # Go crypto
    (rb'crypto/tls\.\(\*Conn\)', 'Go crypto/tls', 0.7),
    (rb'crypto/aes\.\(\*ctr\)', 'Go crypto/aes', 0.7),
    (rb'vendor/golang.org/x/crypto', 'Go x/crypto', 0.75),
    # Microsoft SymCrypt
    (rb'SymCrypt\s+([\d.]+)', 'SymCrypt (Microsoft)', 0.9),
    (rb'SymCryptSha256', 'SymCrypt', 0.8),
    # RustCrypto
    (rb'aes::(?:ni::)?Aes\d{3}', 'RustCrypto (aes crate)', 0.8),
    (rb'sha2::Sha\d{3}', 'RustCrypto (sha2 crate)', 0.8),
    (rb'chacha20poly1305::ChaCha20Poly1305', 'RustCrypto (chacha20poly1305)', 0.8),
    (rb'ed25519_dalek', 'RustCrypto (ed25519-dalek)', 0.85),
    (rb'x25519_dalek', 'RustCrypto (x25519-dalek)', 0.85),
    (rb'ring::', 'ring', 0.85),
    (rb'ring_core_', 'ring (C ABI)', 0.8),
    # HACL* / EverCrypt
    (rb'Hacl_Streaming_Functor', 'HACL* (streaming API)', 0.9),
    (rb'EverCrypt_AutoConfig2', 'EverCrypt', 0.9),
    (rb'EverCrypt_Hash_Incremental', 'EverCrypt', 0.88),
    # Nim crypto
    (rb'nimcrypto_', 'Nim nimcrypto', 0.75),
    (rb'nimAES', 'Nim crypto', 0.7),
    # Zig crypto
    (rb'std\.crypto\.', 'Zig std.crypto', 0.75),
    (rb'crypto\.aes\.AES', 'Zig crypto', 0.7),
    # libgcrypt
    (rb'Libgcrypt\s+([\d.]+)', 'libgcrypt', 0.95),
    (rb'GCRYCT_', 'libgcrypt', 0.8),
    # libtomcrypt
    (rb'LibTomCrypt\s+([\d.]+)', 'libtomcrypt', 0.9),
    # libressl-portable
    (rb'libtls\s+[\d.]+', 'LibreSSL libtls', 0.85),
]


def fingerprint_library(data: bytes) -> List[LibraryMatch]:
    results: List[LibraryMatch] = []
    text = data.decode('ascii', errors='ignore')

    for pattern, lib_name, base_conf in _LIB_SIGNATURES:
        seen = set()
        for match in pattern.finditer(data):
            if match.groups():
                ver = match.group(1).decode('ascii', errors='replace')
            else:
                ver = match.group(0).decode('ascii', errors='replace')[:60]
            if ver in seen:
                continue
            seen.add(ver)
            results.append(LibraryMatch(
                lib_name=lib_name, version_hint=ver,
                confidence=base_conf,
                evidence=["string: '{}' at offset {}".format(ver, match.start())]
            ))

    # 去重: 同库名只保留最高置信度
    deduped: List[LibraryMatch] = []
    seen_libs: set = set()
    results.sort(key=lambda r: -r.confidence)
    for r in results:
        key = r.lib_name.split('(')[0].strip().split(' ')[0]
        if key not in seen_libs:
            seen_libs.add(key)
            deduped.append(r)
    return deduped


__all__ = ['LibraryMatch', 'fingerprint_library']
