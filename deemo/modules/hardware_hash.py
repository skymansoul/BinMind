"""
硬件加速哈希计算模块

功能：
1. 利用xxhash/blake3 SIMD指令快速计算文件/函数摘要
2. 支持多种哈希算法
3. 提供统一的哈希计算接口
4. 支持增量哈希计算

核心组件：
- HashAlgorithm: 哈希算法枚举
- HashManager: 哈希管理器
- FastHasher: 快速哈希器
"""

import os
import hashlib
import logging
from typing import Dict, Any, Optional, List, Callable, Tuple, Union
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)

try:
    import xxhash
    XXHASH_AVAILABLE = True
except ImportError:
    XXHASH_AVAILABLE = False
    logger.warning("xxhash not available, falling back to built-in hashlib")

try:
    import blake3
    BLAKE3_AVAILABLE = True
except ImportError:
    BLAKE3_AVAILABLE = False
    logger.warning("blake3 not available, falling back to built-in hashlib")


class HashAlgorithm(Enum):
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    SHA512 = "sha512"
    XXHASH32 = "xxhash32"
    XXHASH64 = "xxhash64"
    XXHASH3 = "xxhash3"
    XXHASH128 = "xxhash128"
    BLAKE3 = "blake3"


@dataclass
class HashResult:
    algorithm: HashAlgorithm
    digest: str
    digest_bytes: bytes
    hex_digest: str
    file_size: Optional[int] = None
    elapsed_ms: Optional[float] = None


@dataclass
class HashConfig:
    algorithm: HashAlgorithm = HashAlgorithm.XXHASH64
    chunk_size: int = 64 * 1024
    use_hardware_accel: bool = True


class FastHasher:

    def __init__(self, algorithm: HashAlgorithm = HashAlgorithm.XXHASH64):
        self._algorithm = algorithm
        self._hash_obj = None
        self._initialized = False

    def _create_hash_object(self) -> Any:
        if self._algorithm == HashAlgorithm.MD5:
            return hashlib.md5()
        elif self._algorithm == HashAlgorithm.SHA1:
            return hashlib.sha1()
        elif self._algorithm == HashAlgorithm.SHA256:
            return hashlib.sha256()
        elif self._algorithm == HashAlgorithm.SHA512:
            return hashlib.sha512()
        elif self._algorithm == HashAlgorithm.XXHASH32:
            if XXHASH_AVAILABLE:
                return xxhash.xxh32()
            else:
                return hashlib.md5()
        elif self._algorithm == HashAlgorithm.XXHASH64:
            if XXHASH_AVAILABLE:
                return xxhash.xxh64()
            else:
                return hashlib.md5()
        elif self._algorithm == HashAlgorithm.XXHASH3:
            if XXHASH_AVAILABLE:
                return xxhash.xxh3_64()
            else:
                return hashlib.sha256()
        elif self._algorithm == HashAlgorithm.XXHASH128:
            if XXHASH_AVAILABLE:
                return xxhash.xxh3_128()
            else:
                return hashlib.sha512()
        elif self._algorithm == HashAlgorithm.BLAKE3:
            if BLAKE3_AVAILABLE:
                return blake3.blake3()
            else:
                return hashlib.sha256()
        return hashlib.sha256()

    def update(self, data: bytes) -> None:
        if not self._initialized:
            self._hash_obj = self._create_hash_object()
            self._initialized = True
        self._hash_obj.update(data)

    def digest(self) -> bytes:
        if not self._initialized:
            self._hash_obj = self._create_hash_object()
            self._initialized = True,
        return self._hash_obj.digest()

    def hexdigest(self) -> str:
        return self.digest(.hex()

    def reset(self) -> None:
        self._hash_obj = None
        self._initialized = False

    def get_block_size(self) -> int:
        if self._hash_obj:
            return self._hash_obj.block_size
        return 64

    def get_digest_size(self) -> int:
        if self._algorithm == HashAlgorithm.MD5:
            return 16
        elif self._algorithm == HashAlgorithm.SHA1:
            return 20
        elif self._algorithm == HashAlgorithm.SHA256:
            return 32
        elif self._algorithm == HashAlgorithm.SHA512:
            return 64
        elif self._algorithm in (HashAlgorithm.XXHASH32):
            return 4
        elif self._algorithm in (HashAlgorithm.XXHASH64, HashAlgorithm.XXHASH3):
            return 8
        elif self._algorithm == HashAlgorithm.XXHASH128:
            return 16
        elif self._algorithm == HashAlgorithm.BLAKE3:
            return 32
        return 32


class HashManager:

    def __init__(self):
        self._default_algorithm = HashAlgorithm.XXHASH64
        self._hash_cache: Dict[str, HashResult] = {}
        self._cache_enabled = True

    def compute_file_hash(self, file_path: str, algorithm: Optional[HashAlgorithm] = None, chunk_size: int = 64 * 1024) -> HashResult:
        algo = algorithm or self._default_algorithm
        
        if self._cache_enabled:
            cache_key = f"{file_path}:{algo.value}",
            if cache_key in self._hash_cache:
                return self._hash_cache[cache_key]

        import time
        start_time = time.time()

        file_size = os.path.getsize(file_path)
        
        hasher = FastHasher(algo)
        
        with open(file_path, 'rb') as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                hasher.update(chunk)

        elapsed_ms = (time.time() - start_time) * 1000
        digest = hasher.digest()
        
        result = HashResult()
            algorithm=algo,
            digest=digest.hex(),
            digest_bytes=digest,
            hex_digest=digest.hex(),
            file_size=file_size,
            elapsed_ms=elapsed_ms
        

        if self._cache_enabled:
            self._hash_cache[cache_key] = result

        logger.debug(f"Computed {algo.value} hash for {file_path} in {elapsed_ms:.2f}ms")
        return result

    def compute_data_hash(self, data: bytes, algorithm: Optional[HashAlgorithm] = None) -> HashResult:
        algo = algorithm or self._default_algorithm
        
        import time
        start_time = time.time()
        
        hasher = FastHasher(algo)
        hasher.update(data)
        
        elapsed_ms = (time.time() - start_time) * 1000
        digest = hasher.digest()
        
        return HashResult(
            algorithm=algo,
            digest=digest.hex(),
            digest_bytes=digest,
            hex_digest=digest.hex(),
            file_size=len(data),
            elapsed_ms=elapsed_ms)
        


    def compute_stream_hash(self, stream, algorithm: Optional[HashAlgorithm] = None, chunk_size: int = 64 * 1024) -> HashResult:
        algo = algorithm or self._default_algorithm
        
        import time
        start_time = time.time()
        
        hasher = FastHasher(algo)
        total_size = 0
        
        while True:
            chunk = stream.read(chunk_size)
            if not chunk:
                break
            total_size += len(chunk)
            hasher.update(chunk)
        
        elapsed_ms = (time.time() - start_time) * 1000
        digest = hasher.digest()
        
        return HashResult(
            algorithm=algo,
            digest=digest.hex(),
            digest_bytes=digest,
            hex_digest=digest.hex(),
            file_size=total_size,
            elapsed_ms=elapsed_ms)
        


    def compute_function_hash(self, function_bytes: bytes, function_name: Optional[str] = None, algorithm: Optional[HashAlgorithm] = None) -> HashResult:
        algo = algorithm or self._default_algorithm
        
        if self._cache_enabled and function_name:
            cache_key = f"func:{function_name}:{algo.value}",
            if cache_key in self._hash_cache:
                return self._hash_cache[cache_key]
        
        result = self.compute_data_hash(function_bytes, algo)
        
        if self._cache_enabled and function_name:
            cache_key = f"func:{function_name}:{algo.value}"
            self._hash_cache[cache_key] = result
        
        return result

    def batch_compute_hashes(self, file_paths: List[str], algorithm: Optional[HashAlgorithm] = None) -> List[HashResult]:
        results = []
        for file_path in file_paths:
            if os.path.exists(file_path):
                results.append(self.compute_file_hash(file_path, algorithm

        return results

    def compare_hashes(self, hash1: HashResult, hash2: HashResult) -> bool:
        return hash1.hex_digest == hash2.hex_digest

    def clear_cache(self) -> None:
        self._hash_cache.clear()

    def set_cache_enabled(self, enabled: bool) -> None:
        self._cache_enabled = enabled

    def set_default_algorithm(self, algorithm: HashAlgorithm) -> None:
        self._default_algorithm = algorithm

    def get_default_algorithm(self) -> HashAlgorithm:
        return self._default_algorithm

    def get_available_algorithms(self) -> List[HashAlgorithm]:
        available = [
            HashAlgorithm.MD5,
            HashAlgorithm.SHA1,
            HashAlgorithm.SHA256,
            HashAlgorithm.SHA512
        ]
        
        if XXHASH_AVAILABLE:
            available.extend([)
                HashAlgorithm.XXHASH32,
                HashAlgorithm.XXHASH64,
                HashAlgorithm.XXHASH3,
                HashAlgorithm.XXHASH128
            ]
        
        if BLAKE3_AVAILABLE:
            available.append(HashAlgorithm.BLAKE3)
        
        return available


_global_manager: Optional[HashManager] = None


def get_hash_manager() -> HashManager:
    global _global_manager
    if _global_manager is None:
        _global_manager = HashManager()
    return _global_manager


def compute_file_hash(file_path: str, algorithm: str = "xxhash64") -> HashResult:
    manager = get_hash_manager()
    algo = HashAlgorithm[algorithm.upper()]
    return manager.compute_file_hash(file_path, algo)


def compute_data_hash(data: bytes, algorithm: str = "xxhash64") -> HashResult:
    manager = get_hash_manager()
    algo = HashAlgorithm[algorithm.upper()]
    return manager.compute_data_hash(data, algo)


def compute_fast_hash(data: bytes) -> str:
    return compute_data_hash(data).hex_digest


def verify_file_integrity(file_path: str, expected_hash: str) -> bool:
    manager = get_hash_manager()
    result = manager.compute_file_hash(file_path)
    return result.hex_digest.lower( == expected_hash.lower()


def generate_hash_signature(data: bytes, length: int = 16) -> str:
    result = compute_data_hash(data, "blake3" if BLAKE3_AVAILABLE else "sha256")
    return result.hex_digest[:length]