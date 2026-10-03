"""
Cryptographic constant scanner. Detects hardcoded cryptographic
material in binaries: AES S-boxes, common primes, magic constants,
XOR keys, and base64 alphabets.
"""

import logging
import re
import struct
from typing import Dict, List, Set

logger = logging.getLogger(__name__)

# Well-known crypto constants
# TODO: SM4 constants (Chinese national standard) — ZUC has been requested
# by several users analyzing IoT firmware from CN vendors
AES_SBOX = bytes([
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
    0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
])

AES_INV_SBOX = bytes([
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38,
    0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
])

# Round constants
AES_RCON = bytes([0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36])

# Common crypto primes (big-endian)
MD5_INIT = bytes.fromhex('0123456789abcdeffedcba9876543210')
SHA1_H0  = bytes.fromhex('67452301efcdab8998badcfe10325476c3d2e1f0')
SHA256_H0 = bytes.fromhex(
    '6a09e667bb67ae853c6ef372a54ff53a'
    '510e527f9b05688c1f83d9ab5be0cd19')

BASE64_ALPHABET = b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'

CRYPTO_CONSTANTS = {
    'AES_Sbox':        AES_SBOX,
    'AES_InvSbox':     AES_INV_SBOX,
    'AES_Rcon':        AES_RCON,
    'MD5_IV':          MD5_INIT,
    'SHA1_IV':         SHA1_H0,
    'SHA256_IV':       SHA256_H0,
    'Base64':          BASE64_ALPHABET,
}


def scan_crypto(binary_path: str) -> List[Dict]:
    """
    Scan a binary for crypto constants. Returns a list of dicts
    with {constant, offset, algorithm}.
    """
    findings = []

    try:
        with open(binary_path, 'rb') as f:
            data = f.read()
    except (OSError, IOError):
        logger.warning("Cannot read %s", binary_path)
        return findings

    for name, const in CRYPTO_CONSTANTS.items():
        offset = 0
        while True:
            pos = data.find(const, offset)
            if pos == -1:
                break
            algorithm = {
                'AES_Sbox': 'AES', 'AES_InvSbox': 'AES',
                'AES_Rcon': 'AES', 'MD5_IV': 'MD5',
                'SHA1_IV': 'SHA-1', 'SHA256_IV': 'SHA-256',
                'Base64': 'Base64',
            }.get(name, 'unknown')

            findings.append({
                'constant': name,
                'offset': pos,
                'algorithm': algorithm,
                'size': len(const),
            })
            offset = pos + 1

    # also search for hardcoded hex key patterns (> 8 bytes)
    for match in re.finditer(rb'[\x20-\x7e]{16,64}', data):
        s = match.group().decode('ascii', errors='replace')
        if re.match(r'^[A-Za-z0-9+/=]{32,}$', s) and '==' in s:
            findings.append({
                'constant': 'Base64-like string',
                'offset': match.start(),
                'algorithm': 'Base64',
                'size': len(s),
            })

    return findings


def check_weak_algorithms(data: bytes) -> List[Dict]:
    """
    Check for weak algorithm indicators (MD5, DES, RC4).
    Returns list of issues found.
    """
    issues = []

    weak_indicators = {
        b'MD5':    ('MD5', 'Weak hash, collision-prone'),
        b'RC4':    ('RC4', 'Stream cipher with known biases'),
        b'DES':    ('DES', 'Obsolete 56-bit block cipher'),
        b'3DES':   ('3DES', 'Consider AES instead'),
        b'SHA-1':  ('SHA-1', 'Deprecated, use SHA-256+'),
        b'ECB':    ('ECB mode', 'ECB mode leaks plaintext patterns'),
        b'MCRYPT': ('mcrypt', 'Abandonware crypto library'),
    }

    for needle, (algo, desc) in weak_indicators.items():
        if needle in data:
            issues.append({
                'algorithm': algo,
                'issue': desc,
                'severity': 'Medium',
            })

    return issues
