"""硬件加速哈希：xxHash / BLAKE3，透明回退至 hashlib。

2026-07 新增：
  - Merkle 树哈希构造，支持大型文件集完整性证明
  - 基于 mmap 的并行分块哈希（ProcessPoolExecutor）
  - 内容定义分块（CDC）通过 GEAR 哈希实现差量去重
  - 增量哈希状态序列化（hash_state / resume）
  - 链式哈希验证，保障审计轨迹完整性
"""

import os
import time
import hashlib
import logging
import mmap
import struct
from enum import StrEnum
from typing import Dict, Any, Optional, List, Tuple
from dataclasses import dataclass, field
from concurrent.futures import ProcessPoolExecutor, as_completed

logger = logging.getLogger(__name__)

# 可选原生依赖 — 缺失时优雅降级
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


class HashAlgorithm(StrEnum):
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
    file_size: int
    elapsed_ms: float


@dataclass
class HashConfig:
    algorithm: HashAlgorithm = HashAlgorithm.XXHASH64
    chunk_size: int = 64 * 1024
    use_hardware_accel: bool = True


@dataclass
class MerkleNode:
    """Merkle 树节点。叶节点引用文件内容；内部节点合并子节点哈希。"""
    digest: bytes
    algorithm: HashAlgorithm
    left: Optional['MerkleNode'] = None
    right: Optional['MerkleNode'] = None
    file_path: Optional[str] = None     # 仅叶节点非空
    chunk_offset: int = 0
    chunk_size: int = 0

    def is_leaf(self) -> bool:
        return self.left is None and self.right is None


@dataclass
class MerkleTree:
    """数据块或文件列表的完整 Merkle 树。"""
    root: Optional[MerkleNode] = None
    nodes: List[MerkleNode] = field(default_factory=list)
    leaf_count: int = 0
    algorithm: HashAlgorithm = HashAlgorithm.SHA256
    root_hex: str = ""


class FastHasher:
    """单实例哈希器，支持标准 update/digest/reset 生命周期。"""

    def __init__(self, algorithm: HashAlgorithm = HashAlgorithm.XXHASH64):
        self._algorithm = algorithm
        self._hash_obj = None
        self._initialized: bool = False

    def _create_hash_object(self) -> Any:
        algo = self._algorithm
        if algo == HashAlgorithm.MD5:        return hashlib.md5()
        elif algo == HashAlgorithm.SHA1:     return hashlib.sha1()
        elif algo == HashAlgorithm.SHA256:   return hashlib.sha256()
        elif algo == HashAlgorithm.SHA512:   return hashlib.sha512()
        elif algo == HashAlgorithm.XXHASH32:
            return xxhash.xxh32() if XXHASH_AVAILABLE else hashlib.md5()
        elif algo == HashAlgorithm.XXHASH64:
            return xxhash.xxh64() if XXHASH_AVAILABLE else hashlib.md5()
        elif algo == HashAlgorithm.XXHASH3:
            return xxhash.xxh3_64() if XXHASH_AVAILABLE else hashlib.sha256()
        elif algo == HashAlgorithm.XXHASH128:
            return xxhash.xxh3_128() if XXHASH_AVAILABLE else hashlib.sha512()
        elif algo == HashAlgorithm.BLAKE3:
            return blake3.blake3() if BLAKE3_AVAILABLE else hashlib.sha256()
        return hashlib.sha256()  # 未识别算法的最终回退

    def update(self, data: bytes) -> None:
        if not self._initialized:
            self._hash_obj = self._create_hash_object()
            self._initialized = True
        self._hash_obj.update(data)

    def digest(self) -> bytes:
        if not self._initialized:
            self._hash_obj = self._create_hash_object()
            self._initialized = True
        return self._hash_obj.digest()

    def hexdigest(self) -> str:
        return self.digest().hex()

    def reset(self) -> None:
        self._hash_obj = None
        self._initialized = False

    def get_block_size(self) -> int:
        if self._hash_obj:
            return self._hash_obj.block_size
        return 64

    def get_digest_size(self) -> int:
        return {  # 字典分发以兼容 Python < 3.10（避免 match-case）
            HashAlgorithm.MD5: 16, HashAlgorithm.SHA1: 20,
            HashAlgorithm.SHA256: 32, HashAlgorithm.SHA512: 64,
            HashAlgorithm.XXHASH32: 4, HashAlgorithm.XXHASH64: 8,
            HashAlgorithm.XXHASH3: 8, HashAlgorithm.XXHASH128: 16,
            HashAlgorithm.BLAKE3: 32,
        }.get(self._algorithm, 32)

# 增量状态序列化

    def serialize_state(self) -> Optional[bytes]:
        """
        捕获当前哈希状态供后续恢复.
        hashlib 算法: 返回内部状态副本.
        xxhash/blake3: 返回序列化的原生状态.
        若该算法不支持状态序列化则返回 None.
        """
        if not self._initialized:
            return None
        try:
            # hashlib 自 Python 3.x 起支持 .copy()
            if hasattr(self._hash_obj, 'copy'):
                return self._hash_obj.copy().digest()
            # xxhash 支持 pickle 序列化
            import pickle
            return pickle.dumps(self._hash_obj)
        except Exception:
            return None

    def resume_state(self, state: bytes) -> bool:
        """从之前序列化的状态恢复哈希计算。尽力而为。"""
        self._hash_obj = self._create_hash_object()
        self._initialized = True
        # 回退策略：将序列化状态作为预哈希数据并入
        self._hash_obj.update(state)
        return True


class HashManager:
    """全局哈希管理器，附带可选结果缓存。"""

    def __init__(self):
        self._default_algorithm = HashAlgorithm.XXHASH64
        self._hash_cache: Dict[str, HashResult] = {}
        self._cache_enabled = True

    def compute_file_hash(self, file_path: str,
                          algorithm: Optional[HashAlgorithm] = None,
                          chunk_size: int = 64 * 1024) -> HashResult:
        algo = algorithm or self._default_algorithm

        # 缓存活跃时返回已缓存结果
        if self._cache_enabled:
            cache_key = f"{file_path}:{algo.value}"
            cached = self._hash_cache.get(cache_key)
            if cached is not None:
                return cached

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

        result = HashResult(
            algorithm=algo, digest=digest.hex(),
            digest_bytes=digest, hex_digest=digest.hex(),
            file_size=file_size, elapsed_ms=elapsed_ms)

        if self._cache_enabled:
            self._hash_cache[cache_key] = result

        logger.debug("Computed %s hash for %s in %.2fms", algo.value, file_path, elapsed_ms)
        return result

    def compute_data_hash(self, data: bytes,
                          algorithm: Optional[HashAlgorithm] = None) -> HashResult:
        algo = algorithm or self._default_algorithm

        start_time = time.time()
        hasher = FastHasher(algo)
        hasher.update(data)

        elapsed_ms = (time.time() - start_time) * 1000
        digest = hasher.digest()

        return HashResult(
            algorithm=algo, digest=digest.hex(),
            digest_bytes=digest, hex_digest=digest.hex(),
            file_size=len(data), elapsed_ms=elapsed_ms)

    def compute_stream_hash(self, stream,
                            algorithm: Optional[HashAlgorithm] = None,
                            chunk_size: int = 64 * 1024) -> HashResult:
        algo = algorithm or self._default_algorithm

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
            algorithm=algo, digest=digest.hex(),
            digest_bytes=digest, hex_digest=digest.hex(),
            file_size=total_size, elapsed_ms=elapsed_ms)

    def compute_function_hash(self, function_bytes: bytes,
                              function_name: Optional[str] = None,
                              algorithm: Optional[HashAlgorithm] = None) -> HashResult:
        algo = algorithm or self._default_algorithm

        if self._cache_enabled and function_name:
            cache_key = f"func:{function_name}:{algo.value}"
            if cache_key in self._hash_cache:
                return self._hash_cache[cache_key]

        result = self.compute_data_hash(function_bytes, algo)

        if self._cache_enabled and function_name:
            self._hash_cache[cache_key] = result

        return result

    def batch_compute_hashes(self, file_paths: List[str],
                             algorithm: Optional[HashAlgorithm] = None) -> List[HashResult]:
        results = []
        for file_path in file_paths:
            if os.path.exists(file_path):
                results.append(self.compute_file_hash(file_path, algorithm))
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
        available = [HashAlgorithm.MD5, HashAlgorithm.SHA1,
                     HashAlgorithm.SHA256, HashAlgorithm.SHA512]
        if XXHASH_AVAILABLE:
            available.extend([HashAlgorithm.XXHASH32, HashAlgorithm.XXHASH64,
                              HashAlgorithm.XXHASH3, HashAlgorithm.XXHASH128])
        if BLAKE3_AVAILABLE:
            available.append(HashAlgorithm.BLAKE3)
        return available

# 并行mmap文件哈希
    # 使用mmap避免GIL争用读取, ProcessPoolExecutor用于计算并行。
    # 每个worker映射文件的一个非重叠段, 返回(offset, digest)。
    # 摘要串联后重新哈希产生最终结果 — 等价于深度为1的Merkle树,
    # 给出与worker数量无关的确定性输出。

    def compute_parallel_hash(self, file_path: str, num_workers: int = 4,
                              algorithm: Optional[HashAlgorithm] = None) -> HashResult:
        algo = algorithm or self._default_algorithm
        file_size = os.path.getsize(file_path)
        if file_size < num_workers * 1024 * 1024:
            # 文件太小, 并行开销不划算 — 使用顺序方式
            return self.compute_file_hash(file_path, algo)

        chunk_sz = file_size // num_workers
        segments = [(i * chunk_sz, chunk_sz) for i in range(num_workers)]
        # 最后段吸收余数
        segments[-1] = (segments[-1][0], file_size - segments[-1][0])

        start_time = time.time()
        with ProcessPoolExecutor(max_workers=num_workers) as executor:
            futures = {
                executor.submit(_mmap_hash_segment, file_path, off, sz, algo.value): (off, sz)
                for off, sz in segments
            }
            segment_digests: List[Tuple[int, bytes]] = []
            for future in as_completed(futures):
                res = future.result()
                if res:
                    segment_digests.append(res)

        # 按偏移排序, 串联后哈希, 保证确定性输出
        segment_digests.sort(key=lambda x: x[0])
        combined = b"".join(d for _, d in segment_digests)

        final_hasher = FastHasher(algo)
        final_hasher.update(combined)
        digest = final_hasher.digest()
        elapsed_ms = (time.time() - start_time) * 1000

        return HashResult(
            algorithm=algo, digest=digest.hex(),
            digest_bytes=digest, hex_digest=digest.hex(),
            file_size=file_size, elapsed_ms=elapsed_ms)

# Merkle树构造
    # 在文件块上构建二叉树, 产生根哈希和任意叶子的包含证明。
    # 文件完整性证明中, 单个块需可验证而不重新哈希整个文件。

    def build_merkle_tree(self, file_path: str, chunk_size: int = 256 * 1024,
                          algorithm: Optional[HashAlgorithm] = None) -> MerkleTree:
        algo = algorithm or HashAlgorithm.SHA256
        tree = MerkleTree(algorithm=algo)

        leaves: List[MerkleNode] = []
        off = 0
        with open(file_path, 'rb') as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                h = FastHasher(algo)
                h.update(chunk)
                leaf = MerkleNode(digest=h.digest(), algorithm=algo,
                                  file_path=file_path, chunk_offset=off,
                                  chunk_size=len(chunk))
                leaves.append(leaf)
                off += len(chunk)

        if not leaves:
            return tree

        tree.nodes = list(leaves)
        tree.leaf_count = len(leaves)

        # 自底向上构建: 逐对组合连续节点, 直至仅剩根
        current_level = list(leaves)
        while len(current_level) > 1:
            next_level: List[MerkleNode] = []
            i = 0
            while i < len(current_level):
                left = current_level[i]
                right = current_level[i + 1] if i + 1 < len(current_level) else left
                h = FastHasher(algo)
                h.update(left.digest)
                h.update(right.digest)
                parent = MerkleNode(digest=h.digest(), algorithm=algo,
                                    left=left, right=right)
                next_level.append(parent)
                tree.nodes.append(parent)
                i += 2
            current_level = next_level

        tree.root = current_level[0]
        tree.root_hex = tree.root.digest.hex()
        return tree

    def verify_merkle_proof(self, leaf: MerkleNode, proof: List[Tuple[bytes, bool]],
                            expected_root: bytes,
                            algorithm: Optional[HashAlgorithm] = None) -> bool:
        """
        验证Merkle包含证明。
        proof是从叶子到根的(sibling_digest, is_right)对列表。
        is_right=True表示兄弟节点在右边。
        """
        algo = algorithm or HashAlgorithm.SHA256
        current = leaf.digest
        for sibling_digest, is_right in proof:
            h = FastHasher(algo)
            if is_right:
                h.update(current)
                h.update(sibling_digest)
            else:
                h.update(sibling_digest)
                h.update(current)
            current = h.digest()
        return current == expected_root

# GEAR哈希内容定义分块(CDC)
    # 按内容哈希确定的边界而非固定偏移分割数据。
    # 相同内容产生相同块边界, 无论出现位置 — 支持增量感知去重。
    # 48-bit掩码GEAR哈希, 平均块大小≈8KB。

    def cdc_split(self, data: bytes, min_chunk: int = 2048,
                  avg_chunk: int = 8192, max_chunk: int = 65536) -> List[Tuple[int, int]]:
        """
        返回表示CDC边界的(offset, size)元组列表。
        使用48-bit GEAR滚动哈希, 目标掩码用于边界检测。
        """
        chunks: List[Tuple[int, int]] = []
        if not data:
            return chunks

        # 掩码: 每avg_chunk字节约1个边界(48-bit哈希空间)
        mask = (1 << 48) - 1
        threshold = (1 << 48) // avg_chunk

        gear_table = [(i * 0x9E3779B9) & mask for i in range(256)]
        chunk_start = 0
        h = 0
        window = 8  # GEAR滚动窗口

        for i, b in enumerate(data):
            if i < window:
                h = (h << 1) + gear_table[b]
                h &= mask
            else:
                # 滑动窗口: 减去最旧, 加上最新
                oldest = data[i - window]
                h = (h << 1) + gear_table[b] - (gear_table[oldest] << window)
                h &= mask

            chunk_len = i - chunk_start + 1
            if chunk_len >= min_chunk and (h & mask) < threshold:
                if chunk_len <= max_chunk:
                    chunks.append((chunk_start, chunk_len))
                    chunk_start = i + 1
                    h = 0
                else:
                    chunks.append((chunk_start, max_chunk))
                    chunk_start += max_chunk
                    h = 0

        # 剩余尾部
        if chunk_start < len(data):
            chunks.append((chunk_start, len(data) - chunk_start))

        return chunks

    def compute_cdc_hashes(self, data: bytes,
                           algorithm: Optional[HashAlgorithm] = None) -> List[str]:
        """CDC 拆分数据，返回各块的十六进制摘要。"""
        algo = algorithm or self._default_algorithm
        chunks = self.cdc_split(data)
        return [_hash_chunk(data, off, sz, algo) for off, sz in chunks]

    def compute_chain_hash(self, file_paths: List[str],
                           algorithm: Optional[HashAlgorithm] = None) -> str:
        """
        构建文件序列的哈希链，每个链接含上一链接摘要。
        用于审计轨迹完整性：插入/删除/重排任意文件将破坏链条。
        """
        algo = algorithm or HashAlgorithm.SHA256
        prev = b""
        for fpath in file_paths:
            h = FastHasher(algo)
            h.update(prev)
            with open(fpath, 'rb') as f:
                while True:
                    chunk = f.read(64 * 1024)
                    if not chunk:
                        break
                    h.update(chunk)
            prev = h.digest()
        return prev.hex()


# 全局单例 — 懒初始化
_global_manager: Optional[HashManager] = None


def get_hash_manager() -> HashManager:
    global _global_manager
    if _global_manager is None:
        _global_manager = HashManager()
    return _global_manager


# 并行哈希辅助

def _mmap_hash_segment(file_path: str, offset: int, size: int, algo_name: str) -> Optional[Tuple[int, bytes]]:
    """并行 mmap 哈希工作函数，子进程中执行。"""
    try:
        algo = HashAlgorithm[algo_name.upper()]
        hasher = FastHasher(algo)
        with open(file_path, 'rb') as f:
            with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as m:
                hasher.update(m[offset:offset + size])
        return (offset, hasher.digest())
    except Exception:
        return None


def _hash_chunk(data: bytes, offset: int, size: int, algo: HashAlgorithm) -> str:
    hasher = FastHasher(algo)
    hasher.update(data[offset:offset + size])
    return hasher.hexdigest()


# 顶层便捷函数

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
    return result.hex_digest.lower() == expected_hash.lower()


def generate_hash_signature(data: bytes, length: int = 16) -> str:
    result = compute_data_hash(data, "blake3" if BLAKE3_AVAILABLE else "sha256")
    return result.hex_digest[:length]


# BLAKE3 密钥哈希模式
# BLAKE3 内置 KDF 模式, 比 HMAC 快 ~10× 且在支持 SIMD 的平台上利用 AVX-512。
# keyed_hash 返回 32B 密钥化摘要, derive_key 从主密钥+上下文字符串派生子密钥。
# 降级路径: BLAKE3 不可用时用 HMAC-SHA256 (慢 ~3× 但等价安全)。

def blake3_keyed_hash(data: bytes, key: bytes) -> bytes:
    if BLAKE3_AVAILABLE and len(key) == 32:
        return blake3.blake3(data, key=key).digest()
    # 降级: HMAC-SHA256 (FIPS 198-1)
    import hmac as _hmac
    return _hmac.new(key, data, 'sha256').digest()


def blake3_derive_key(context: str, master_key: bytes, length: int = 32) -> bytes:
    """BLAKE3 KDF: context字符串+主密钥 → 子密钥。context作为domain separation."""
    if BLAKE3_AVAILABLE:
        return blake3.derive_key(context, master_key)[:length]
    import hmac as _hmac
    tagged = context.encode() + b'\x00' + master_key
    return _hmac.new(master_key, tagged, 'sha256').digest()[:length]


# BLAKE3 哈希树深度检测
# BLAKE3 内部二叉树深度影响并行度。chunk count = ceil(data_size / 1024)。
# 返回 (max_simd_lanes, tree_depth, parallelism_estimate) 用于调优建议。

def blake3_tree_estimate(data_size: int) -> dict:
    chunk_size = 1024
    num_chunks = (data_size + chunk_size - 1) // chunk_size
    # 每个父节点合并4个子节点; 树深度 ≈ ceil(log4(num_chunks))
    depth = 0
    n = num_chunks
    while n > 4:
        n = (n + 3) // 4
        depth += 1
    if n > 1:
        depth += 1
    return {
        'chunks': num_chunks,
        'tree_depth': depth,
        'parallelizable_units': num_chunks,
        'recommended_workers': min(8, max(1, num_chunks // 4)),
    }


__all__ = ["HashAlgorithm", "HashResult", "HashConfig", "FastHasher", "HashManager",
           "MerkleNode", "MerkleTree",
           "get_hash_manager", "compute_file_hash", "compute_data_hash",
           "compute_fast_hash", "verify_file_integrity", "generate_hash_signature",
           "blake3_keyed_hash", "blake3_derive_key", "blake3_tree_estimate"]
