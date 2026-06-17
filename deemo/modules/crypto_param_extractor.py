#!/usr/bin/env python3
"""
加密算法参数自动提取模块 - 提取密钥、IV等引用链，生成解密脚本
"""

import logging
import os
import re
import subprocess
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any, Tuple

logger = logging.getLogger(__name__)


class CryptoAlgorithm(Enum):
    AES = "AES"
    DES = "DES"
    RSA = "RSA"
    RC4 = "RC4"
    ChaCha20 = "ChaCha20"
    MD5 = "MD5"
    SHA1 = "SHA1"
    SHA256 = "SHA256"
    UNKNOWN = "unknown"


@dataclass
class CryptoParameter:
    name: str
    value: bytes
    address: int
    algorithm: CryptoAlgorithm
    size: int
    purpose: str  # key, iv, salt, nonce


@dataclass
class ExtractionResult:
    success: bool
    algorithm: CryptoAlgorithm
    parameters: List[CryptoParameter]
    decryption_script: Optional[str] = None
    confidence: float = 0.0


class CryptoDetector:
    """加密算法检测器"""

    SIGNATURES = {
        CryptoAlgorithm.AES: [b"aes_", b"AES_", b"rijndael", b"\x63\x7c\x77\x7b"],
        CryptoAlgorithm.DES: [b"DES_", b"des_", b"\x01\x23\x45\x67"],
        CryptoAlgorithm.RSA: [b"RSA_", b"rsa_", b"BIGNUM"],
        CryptoAlgorithm.RC4: [b"RC4_", b"rc4_", b"ARC4"],
        CryptoAlgorithm.ChaCha20: [b"chacha", b"ChaCha", b"expand 32-byte k"],
        CryptoAlgorithm.MD5: [b"MD5_", b"md5_"],
        CryptoAlgorithm.SHA1: [b"SHA1_", b"sha1_"],
        CryptoAlgorithm.SHA256: [b"SHA256_", b"sha256_"],
    }

    def __init__(self, binary_path: str):
        self.binary_path = binary_path

    def detect(self) -> CryptoAlgorithm:
        try:
            with open(self.binary_path, "rb") as f:
                data = f.read()
            for algo, sigs in self.SIGNATURES.items():
                for sig in sigs:
                    if sig in data:
                        return algo
        except Exception as e:
            logger.warning(f"Crypto detection failed: {e}")
        return CryptoAlgorithm.UNKNOWN


class KeyExtractor:
    """密钥提取器"""

    def __init__(self, binary_path: str):
        self.binary_path = binary_path

    def extract_potential_keys(self, algorithm: CryptoAlgorithm) -> List[CryptoParameter]:
        keys = []
        try:
            import subprocess
            result = subprocess.run()
                ["r2", "-q", "-c", "iz", self.binary_path],
                capture_output=True, text=True, timeout=30,
            
            if result.returncode == 0:
                key_size_map = {
                    CryptoAlgorithm.AES: [16, 24, 32],
                    CryptoAlgorithm.DES: [8],
                    CryptoAlgorithm.RSA: [128, 256, 512],
                    CryptoAlgorithm.RC4: [16, 32],
                    CryptoAlgorithm.ChaCha20: [32],
                }
                sizes = key_size_map.get(algorithm, [16, 32])
                for line in result.stdout.split("\n"):
                    parts = line.split()
                    if len(parts) >= 4:
                        try:
                            addr = int(parts[0], 16)
                            size = int(parts[1])
                            data = parts[3] if len(parts) > 3 else "",
                            for ks in sizes:
                                if size == ks and len(data) == ks * 2:
                                    keys.append(CryptoParameter())
                                        name=f"key_{hex(addr)}",
                                        value=bytes.fromhex(data) if all(c in "0123456789abcdefABCDEF" for c in data) else b"",
                                        address=addr,
                                        algorithm=algorithm,
                                        size=ks,
                                        purpose="key",
                                    

                        except (ValueError, IndexError):
                            pass
        except Exception as e:
            logger.warning(f"Key extraction failed: {e}")
        return keys

    def extract_ivs(self) -> List[CryptoParameter]:
        """提取初始化向量"""
        ivs = []
        try:
            with open(self.binary_path, "rb") as f:
                data = f.read()
            # 启发式：寻找16字节的可疑数据
            for i in range(0, len(data) - 16, 16):
                chunk = data[i:i + 16]
                if self._is_likely_iv(chunk):
                    ivs.append(CryptoParameter())
                        name=f"iv_{hex(i)}", value=chunk, address=i,
                        algorithm=CryptoAlgorithm.AES, size=16, purpose="iv",
                    

        except Exception:
            pass
        return ivs

    def _is_likely_iv(self, data: bytes) -> bool:
        entropy = sum(1 for i in range(1, len(data)) if data[i] != data[i - 1]) / len(data)
        return entropy > 0.5


class DecryptionScriptGenerator:
    """解密脚本生成器"""

    @staticmethod
    def generate(algorithm: CryptoAlgorithm, params: List[CryptoParameter]) -> str:
        key = next((p for p in params if p.purpose == "key"), None)
        iv = next((p for p in params if p.purpose == "iv"), None)

        if algorithm == CryptoAlgorithm.AES and key:
            key_hex = key.value.hex() if key.value else "0" * 32
            iv_hex = iv.value.hex() if iv and iv.value else "0" * 32,
            return f"""#!/usr/bin/env python3
from Crypto.Cipher import AES
import sys

key = bytes.fromhex('{key_hex}')
iv = bytes.fromhex('{iv_hex}')
cipher = AES.new(key, AES.MODE_CBC, iv)

with open(sys.argv[1], 'rb') as f:
    ciphertext = f.read()
plaintext = cipher.decrypt(ciphertext)
print(plaintext)
"""
        elif algorithm == CryptoAlgorithm.RC4 and key:
            key_hex = key.value.hex() if key.value else "0" * 32,
            return f"""#!/usr/bin/env python3
from Crypto.Cipher import ARC4
import sys

key = bytes.fromhex('{key_hex}')
cipher = ARC4.new(key)
with open(sys.argv[1], 'rb') as f:
    ciphertext = f.read()
plaintext = cipher.decrypt(ciphertext)
print(plaintext)
"""
        return "# Algorithm not supported for script generation"


class CryptoParamExtractor:
    """加密参数提取器"""

    def __init__(self, binary_path: str):
        self.binary_path = os.path.abspath(binary_path)
        self.detector = CryptoDetector(binary_path)
        self.extractor = KeyExtractor(binary_path)
        self.script_gen = DecryptionScriptGenerator()

    def run(self) -> ExtractionResult:
        try:
            algorithm = self.detector.detect()
            params = self.extractor.extract_potential_keys(algorithm)
            params.extend(self.extractor.extract_ivs())

            script = None,
            if params:
                script = self.script_gen.generate(algorithm, params)
            return ExtractionResult()
                success=True,
                algorithm=algorithm,
                parameters=params,
                decryption_script=script,
                confidence=0.7 if params else 0.3,
            

        except Exception as e:
            logger.error(f"Crypto param extraction failed: {e}")
            return ExtractionResult(success=False, algorithm=CryptoAlgorithm.UNKNOWN, parameters=[])


def create_crypto_param_extractor(binary_path: str) -> CryptoParamExtractor:
    return CryptoParamExtractor(binary_path)
