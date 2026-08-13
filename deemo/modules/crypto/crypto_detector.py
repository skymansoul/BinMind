# 密码学算法检测 —— 聚合入口
# 检测逻辑在 src/crypto_detector.py；此处定义常量表并重导出检测函数。
from .src.crypto_detector import (
    CryptoDetector, CryptoFinding, detect_by_magic_constants,
    detect_by_structure, detect_by_api_strings, detect_hardware_accel,
)
from .src.constants import AES_SBOX, MD5_IV, SHA256_IV

CRYPTO_CONSTANTS = {
    'aes': {'constants': {'sbox': AES_SBOX}},
    'md5': {'constants': {
        'initial': b''.join(x.to_bytes(4, 'little') for x in MD5_IV)}},
    'sha256': {'constants': {
        'initial': SHA256_IV if isinstance(SHA256_IV, bytes)
        else b''.join(x.to_bytes(4, 'big') for x in SHA256_IV)}},
}

try:
    from .src.constants import DES_IP
    CRYPTO_CONSTANTS['des'] = {'constants': {'ip': DES_IP}}
except ImportError:
    pass

__all__ = [
    'CryptoDetector', 'CryptoFinding', 'CRYPTO_CONSTANTS',
    'detect_by_magic_constants', 'detect_by_structure',
    'detect_by_api_strings', 'detect_hardware_accel',
]
