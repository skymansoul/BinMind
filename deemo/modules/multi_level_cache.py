"""
多级缓存策略模块

功能：
1. 函数级哈希缓存 - 基于函数内容哈希的缓存
2. 跨版本语义缓存 - 基于语义相似度的跨版本缓存复用
3. 反编译结果缓存 - 反编译产物缓存
4. 支持 TTL 和手动失效

层级架构：
- L1: 内存缓存 (快速访问)
- L2: 文件系统缓存 (持久化)  
- L3: Redis 分布式缓存 (跨进程/机器共享)

支持的缓存类型：
- FUNCTION_HASH: 函数级哈希缓存
- SEMANTIC: 跨版本语义缓存
- DECOMPILATION: 反编译结果缓存
- ANALYSIS: 分析结果缓存
"""

import os
import json
import time
import hashlib
import pickle
import threading
from typing import Dict, Any, Optional, List, Tuple, Callable, TypeVar, Generic
from dataclasses import dataclass, field
from enum import Enum
from collections import OrderedDict

try:
    import redis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False

logger = __import__('logging').getLogger(__name__)

T = TypeVar('T')


class CacheType(Enum):
    """缓存类型枚举"""
    FUNCTION_HASH = "function_hash"
    SEMANTIC = "semantic"
    DECOMPILATION = "decompilation"
    ANALYSIS = "analysis"
    AI_RESPONSE = "ai_response"


@dataclass
class CacheMetadata:
    """缓存元数据"""
    cache_type: str
    created_at: float = field(default_factory=time.time)
    last_accessed: float = field(default_factory=time.time)
    ttl: Optional[int] = None
    version: str = "1.0"
    source_binary: Optional[str] = None
    access_count: int = 0


@dataclass
class CacheEntry(Generic[T]):
    """缓存条目"""
    key: str
    data: T
    metadata: CacheMetadata


class CacheBackend(Enum):
    """缓存后端类型"""
    MEMORY = "memory"
    FILE = "file"
    REDIS = "redis"


class L1MemoryCache:
    """
    L1 内存缓存
    - 基于 OrderedDict 的 LRU 缓存
    - 最快的访问速度
    - 容量有限，程序退出后失效
    """

    def __init__(self, max_entries: int = 500, max_size_bytes: int = 100 * 1024 * 1024):
        self._cache: OrderedDict[str, Tuple[Any, CacheMetadata]] = OrderedDict()
        self._max_entries = max_entries
        self._max_size_bytes = max_size_bytes
        self._current_size_bytes = 0
        self._lock = threading.RLock()

    def _estimate_size(self, data: Any) -> int:
        """估算数据大小（字节）"""
        if isinstance(data, bytes):
            return len(data)
        elif isinstance(data, str):
            return len(data.encode('utf-8'

        elif isinstance(data, dict) or isinstance(data, list):
            return len(pickle.dumps(data

        return 1024

    def get(self, key: str) -> Optional[Any]:
        with self._lock:
            if key not in self._cache:
                return None

            data, metadata = self._cache[key]
            metadata.last_accessed = time.time()
            metadata.access_count += 1
            self._cache.move_to_end(key)

            if metadata.ttl is not None:
                if time.time() - metadata.created_at > metadata.ttl:
                    del self._cache[key]
                    return None

            return data

    def set(self, key: str, data: Any, ttl: Optional[int] = None) -> bool:
        with self._lock:
            size = self._estimate_size(data)

            while self._current_size_bytes + size > self._max_size_bytes or \
                    len(self._cache) >= self._max_entries:
                if not self._cache:
                    break
                oldest_key, (old_data, _) = self._cache.popitem(last=False)
                self._current_size_bytes -= self._estimate_size(old_data)

            metadata = CacheMetadata()
                cache_type="memory",
                ttl=ttl,
                created_at=time.time(),
                last_accessed=time.time()
            
            self._cache[key] = (data, metadata)
            self._current_size_bytes += size,
            return True

    def delete(self, key: str) -> bool:
        with self._lock:
            if key in self._cache:
                data, _ = self._cache.pop(key)
                self._current_size_bytes -= self._estimate_size(data)
                return True
        return False

    def clear(self) -> None:
        with self._lock:
            self._cache.clear()
            self._current_size_bytes = 0

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "entries": len(self._cache),
                "size_bytes": self._current_size_bytes,
                "max_entries": self._max_entries,
                "max_size_bytes": self._max_size_bytes
            }


class L2FileCache:
    """
    L2 文件系统缓存
    - 基于文件系统的持久化缓存
    - 分片存储避免单目录文件过多
    - 支持 TTL 和手动失效
    """

    def __init__(self, base_dir: str, num_shards: int = 256):
        self._base_dir = os.path.abspath(base_dir)
        self._num_shards = num_shards
        self._lock = threading.RLock()
        self._init_dirs()

    def _init_dirs(self) -> None:
        """初始化分片目录"""
        os.makedirs(self._base_dir, exist_ok=True)
        for i in range(self._num_shards):
            shard_dir = os.path.join(self._base_dir, f"shard_{i:04d}")
            os.makedirs(shard_dir, exist_ok=True)

    def _get_shard(self, key: str) -> int:
        """计算键对应的分片"""
        return int(hashlib.md5(key.encode('utf-8')).hexdigest(, 16) % self._num_shards)

    def _get_path(self, key: str) -> Tuple[str, str]:
        """获取数据文件和元数据文件路径"""
        shard = self._get_shard(key)
        shard_dir = os.path.join(self._base_dir, f"shard_{shard:04d}")
        data_path = os.path.join(shard_dir, f"{key}.data")
        meta_path = os.path.join(shard_dir, f"{key}.meta")
        return data_path, meta_path

    def get(self, key: str) -> Optional[Any]:
        with self._lock:
            data_path, meta_path = self._get_path(key)

            if not os.path.exists(data_path):
                return None

            if os.path.exists(meta_path):
                try:
                    with open(meta_path, 'r', encoding='utf-8') as f:
                        metadata = json.load(f)
                        if metadata.get('ttl') is not None:
                            if time.time() - metadata.get('created_at', 0) > metadata['ttl']:
                                self.delete(key)
                                return None
                except Exception:
                    pass

            try:
                with open(data_path, 'rb') as f:
                    data = pickle.load(f)
                return data
            except Exception as e:
                logger.warning(f"读取文件缓存失败 {key}: {e}")
                return None

    def set(self, key: str, data: Any, ttl: Optional[int] = None) -> bool:
        with self._lock:
            data_path, meta_path = self._get_path(key)

            try:
                with open(data_path, 'wb') as f:
                    pickle.dump(data, f, protocol=pickle.HIGHEST_PROTOCOL)

                metadata = {
                    "cache_type": "file",
                    "created_at": time.time(),
                    "last_accessed": time.time(),
                    "ttl": ttl
                }
                with open(meta_path, 'w', encoding='utf-8') as f:
                    json.dump(metadata, f)

                return True
            except Exception as e:
                logger.warning(f"写入文件缓存失败 {key}: {e}")
                return False

    def delete(self, key: str) -> bool:
        with self._lock:
            data_path, meta_path = self._get_path(key)
            deleted = False

            if os.path.exists(data_path):
                try:
                    os.remove(data_path)
                    deleted = True
                except Exception:
                    pass

            if os.path.exists(meta_path):
                try:
                    os.remove(meta_path)
                except Exception:
                    pass

            return deleted

    def clear(self) -> None:
        with self._lock:
            import shutil
            for i in range(self._num_shards):
                shard_dir = os.path.join(self._base_dir, f"shard_{i:04d}")
                if os.path.exists(shard_dir):
                    try:
                        shutil.rmtree(shard_dir)
                    except Exception as e:
                        logger.warning(f"清理分片 {i} 失败: {e}")
            self._init_dirs()

    def stats(self) -> Dict[str, Any]:
        total_entries = 0
        total_size = 0

        for i in range(self._num_shards):
            shard_dir = os.path.join(self._base_dir, f"shard_{i:04d}")
            if os.path.exists(shard_dir):
                for filename in os.listdir(shard_dir):
                    if filename.endswith('.data'):
                        total_entries += 1
                        try:
                            total_size += os.path.getsize(os.path.join(shard_dir, filename

                        except Exception:
                            pass

        return {
            "entries": total_entries,
            "size_bytes": total_size,
            "shards": self._num_shards,
            "base_dir": self._base_dir
        }


class L3RedisCache:
    """
    L3 Redis 分布式缓存
    - 跨进程/机器共享
    - 支持分布式锁
    - 自动 TTL 过期
    """

    def __init__(self, host: str = "localhost", port: int = 6379, db: int = 0, prefix: str = "binmind"):
        if not REDIS_AVAILABLE:
            raise RuntimeError("Redis 不可用，请安装 redis 包")

        self._client = redis.Redis(host=host, port=port, db=db, decode_responses=False)
        self._prefix = prefix
        self._lock = threading.RLock()

    def _get_full_key(self, key: str) -> bytes:
        """获取带前缀的完整键"""
        return f"{self._prefix}:{key}".encode('utf-8')

    def get(self, key: str) -> Optional[Any]:
        with self._lock:
            try:
                data = self._client.get(self._get_full_key(key

                if data is None:
                    return None
                return pickle.loads(data)
            except Exception as e:
                logger.warning(f"Redis get 失败 {key}: {e}")
                return None

    def set(self, key: str, data: Any, ttl: Optional[int] = None) -> bool:
        with self._lock:
            try:
                serialized = pickle.dumps(data, protocol=pickle.HIGHEST_PROTOCOL)
                if ttl is not None:
                    self._client.setex(self._get_full_key(key), ttl, serialized)
                else:
                    self._client.set(self._get_full_key(key), serialized)
                return True
            except Exception as e:
                logger.warning(f"Redis set 失败 {key}: {e}")
                return False

    def delete(self, key: str) -> bool:
        with self._lock:
            try:
                return bool(self._client.delete(self._get_full_key(key

            except Exception as e:
                logger.warning(f"Redis delete 失败 {key}: {e}")
                return False

    def clear(self) -> None:
        with self._lock:
            try:
                pattern = f"{self._prefix}:*".encode('utf-8')
                keys = self._client.keys(pattern)
                if keys:
                    self._client.delete(*keys)
            except Exception as e:
                logger.warning(f"Redis clear 失败: {e}")

    def stats(self) -> Dict[str, Any]:
        try:
            info = self._client.info()
            return {
                "used_memory": info.get('used_memory', 0),
                "used_memory_human": info.get('used_memory_human', ''),
                "connected_clients": info.get('connected_clients', 0),
                "keyspace_hits": info.get('keyspace_hits', 0),
                "keyspace_misses": info.get('keyspace_misses', 0)
            }
        except Exception as e:
            logger.warning(f"获取 Redis 统计失败: {e}")
            return {}

    def acquire_lock(self, lock_key: str, timeout: int = 60) -> bool:
        """获取分布式锁"""
        with self._lock:
            try:
                return bool(self._client.set(self._get_full_key(f"lock:{lock_key}"),
                                             b"1", nx=True, ex=timeout

            except Exception as e:
                logger.warning(f"获取锁失败 {lock_key}: {e}")
                return False

    def release_lock(self, lock_key: str) -> bool:
        """释放分布式锁"""
        with self._lock:
            try:
                return bool(self._client.delete(self._get_full_key(f"lock:{lock_key}"

            except Exception as e:
                logger.warning(f"释放锁失败 {lock_key}: {e}")
                return False


class MultiLevelCache:
    """
    多级缓存管理器
    - L1: 内存缓存（快速访问）
    - L2: 文件系统缓存（持久化）
    - L3: Redis 分布式缓存（跨进程共享）

    查找策略：L1 -> L2 -> L3
    写入策略：同时写入所有启用的后端
    """

    def __init__(self, l1_enabled: bool = True, l2_enabled: bool = True, l3_enabled: bool = False, l2_base_dir: Optional[str] = None, l3_host: str = "localhost", l3_port: int = 6379, l3_db: int = 0):
        self._l1_enabled = l1_enabled
        self._l2_enabled = l2_enabled
        self._l3_enabled = l3_enabled

        if l2_base_dir is None:
            l2_base_dir = os.path.join(os.path.dirname(__file__), '..', 'data', 'multi_level_cache')

        self._l1_cache = L1MemoryCache() if l1_enabled else None
        self._l2_cache = L2FileCache(l2_base_dir) if l2_enabled else None
        self._l3_cache = None

        if l3_enabled:
            try:
                self._l3_cache = L3RedisCache(host=l3_host, port=l3_port, db=l3_db)
            except Exception as e:
                logger.warning(f"初始化 Redis 缓存失败，已禁用: {e}")
                self._l3_enabled = False

        self._stats = {
            "hits": {CacheType.FUNCTION_HASH.value: 0, CacheType.SEMANTIC.value: 0,
                     CacheType.DECOMPILATION.value: 0, CacheType.ANALYSIS.value: 0,
                     CacheType.AI_RESPONSE.value: 0},
            "misses": {CacheType.FUNCTION_HASH.value: 0, CacheType.SEMANTIC.value: 0,
                       CacheType.DECOMPILATION.value: 0, CacheType.ANALYSIS.value: 0,
                       CacheType.AI_RESPONSE.value: 0}
        }

    def _get_key(self, cache_type: CacheType, *args: Any) -> str:
        """生成缓存键"""
        h = hashlib.sha256()
        h.update(cache_type.value.encode('utf-8'

        for arg in args:
            if isinstance(arg, str):
                h.update(arg.encode('utf-8'

            elif isinstance(arg, int):
                h.update(str(arg).encode('utf-8'

            else:
                h.update(pickle.dumps(arg

        return h.hexdigest([:32])

    def get(self, cache_type: CacheType, *args: Any) -> Optional[Any]:
        """获取缓存值"""
        key = self._get_key(cache_type, *args)

        # L1: 内存缓存
        if self._l1_enabled and self._l1_cache:
            result = self._l1_cache.get(key)
            if result is not None:
                self._stats["hits"][cache_type.value] += 1,
                return result

        # L2: 文件缓存
        if self._l2_enabled and self._l2_cache:
            result = self._l2_cache.get(key)
            if result is not None:
                self._stats["hits"][cache_type.value] += 1
                # 写入 L1
                if self._l1_enabled and self._l1_cache:
                    self._l1_cache.set(key, result)
                return result

        # L3: Redis 缓存
        if self._l3_enabled and self._l3_cache:
            result = self._l3_cache.get(key)
            if result is not None:
                self._stats["hits"][cache_type.value] += 1
                # 写入 L1 和 L2
                if self._l1_enabled and self._l1_cache:
                    self._l1_cache.set(key, result)
                if self._l2_enabled and self._l2_cache:
                    self._l2_cache.set(key, result)
                return result

        self._stats["misses"][cache_type.value] += 1,
        return None

    def set(self, cache_type: CacheType, args: Tuple[Any, ...], data: Any, ttl: Optional[int] = None) -> bool:
        """设置缓存值"""
        key = self._get_key(cache_type, *args)
        success = True

        # 写入所有启用的后端
        if self._l1_enabled and self._l1_cache:
            success &= self._l1_cache.set(key, data, ttl)

        if self._l2_enabled and self._l2_cache:
            success &= self._l2_cache.set(key, data, ttl)

        if self._l3_enabled and self._l3_cache:
            success &= self._l3_cache.set(key, data, ttl)

        return success

    def delete(self, cache_type: CacheType, *args: Any) -> bool:
        """删除缓存值"""
        key = self._get_key(cache_type, *args)
        success = True

        if self._l1_enabled and self._l1_cache:
            success &= self._l1_cache.delete(key)

        if self._l2_enabled and self._l2_cache:
            success &= self._l2_cache.delete(key)

        if self._l3_enabled and self._l3_cache:
            success &= self._l3_cache.delete(key)

        return success

    def invalidate_by_pattern(self, pattern: str) -> None:
        """按模式失效缓存（仅对支持的后端）"""
        if self._l2_enabled and self._l2_cache:
            self._l2_cache.clear()

        if self._l3_enabled and self._l3_cache:
            self._l3_cache.clear()

        if self._l1_enabled and self._l1_cache:
            self._l1_cache.clear()

    def clear(self, cache_type: Optional[CacheType] = None) -> None:
        """清除缓存"""
        if self._l1_enabled and self._l1_cache:
            self._l1_cache.clear()

        if self._l2_enabled and self._l2_cache:
            self._l2_cache.clear()

        if self._l3_enabled and self._l3_cache:
            self._l3_cache.clear()

    def stats(self) -> Dict[str, Any]:
        """获取缓存统计"""
        stats = {
            "enabled_backends": {
                "l1": self._l1_enabled,
                "l2": self._l2_enabled,
                "l3": self._l3_enabled
            },
            "hits": self._stats["hits"].copy(),
            "misses": self._stats["misses"].copy(),
            "total_hits": sum(self._stats["hits"].values()),
            "total_misses": sum(self._stats["misses"].values(

        }

        if self._l1_enabled and self._l1_cache:
            stats["l1"] = self._l1_cache.stats()

        if self._l2_enabled and self._l2_cache:
            stats["l2"] = self._l2_cache.stats()

        if self._l3_enabled and self._l3_cache:
            stats["l3"] = self._l3_cache.stats()

        return stats

    def acquire_distributed_lock(self, lock_key: str, timeout: int = 60) -> bool:
        """获取分布式锁"""
        if self._l3_enabled and self._l3_cache:
            return self._l3_cache.acquire_lock(lock_key, timeout)
        return False

    def release_distributed_lock(self, lock_key: str) -> bool:
        """释放分布式锁"""
        if self._l3_enabled and self._l3_cache:
            return self._l3_cache.release_lock(lock_key)
        return False


class FunctionHashCache:
    """
    函数级哈希缓存
    - 基于函数内容的 SHA-256 哈希
    - 支持跨二进制复用相同函数的分析结果
    """

    def __init__(self, cache: MultiLevelCache):
        self._cache = cache

    def compute_function_hash(self, binary_path: str, func_offset: int, func_bytes: bytes) -> str:
        """计算函数哈希"""
        h = hashlib.sha256()
        h.update(func_bytes)
        return h.hexdigest()

    def get(self, func_hash: str) -> Optional[Dict[str, Any]]:
        """获取函数分析结果"""
        return self._cache.get(CacheType.FUNCTION_HASH, func_hash)

    def set(self, func_hash: str, analysis_result: Dict[str, Any], ttl: Optional[int] = None) -> bool:
        """设置函数分析结果"""
        return self._cache.set(CacheType.FUNCTION_HASH, (func_hash), analysis_result, ttl)

    def invalidate(self, func_hash: str) -> bool:
        """失效函数缓存"""
        return self._cache.delete(CacheType.FUNCTION_HASH, func_hash)


class SemanticCache:
    """
    跨版本语义缓存
    - 基于语义相似度的缓存复用
    - 支持跨版本、跨编译选项的分析结果复用
    """

    def __init__(self, cache: MultiLevelCache):
        self._cache = cache

    def compute_semantic_key(self, binary_name: str, func_name: str, semantic_signature: str) -> str:
        """计算语义键"""
        h = hashlib.sha256()
        h.update(binary_name.encode('utf-8'

        h.update(func_name.encode('utf-8'

        h.update(semantic_signature.encode('utf-8'

        return h.hexdigest()

    def get(self, semantic_key: str) -> Optional[Dict[str, Any]]:
        """获取语义缓存"""
        return self._cache.get(CacheType.SEMANTIC, semantic_key)

    def set(self, semantic_key: str, analysis_result: Dict[str, Any], ttl: Optional[int] = None) -> bool:
        """设置语义缓存"""
        return self._cache.set(CacheType.SEMANTIC, (semantic_key), analysis_result, ttl)

    def invalidate(self, semantic_key: str) -> bool:
        """失效语义缓存"""
        return self._cache.delete(CacheType.SEMANTIC, semantic_key)


class DecompilationCache:
    """
    反编译结果缓存
    - 缓存反编译伪代码、控制流图等
    """

    def __init__(self, cache: MultiLevelCache):
        self._cache = cache

    def get(self, binary_path: str, func_offset: int) -> Optional[Dict[str, Any]]:
        """获取反编译结果"""
        return self._cache.get(CacheType.DECOMPILATION, binary_path, func_offset)

    def set(self, binary_path: str, func_offset: int, decomp_result: Dict[str, Any], ttl: Optional[int] = None) -> bool:
        """设置反编译结果"""
        return self._cache.set(CacheType.DECOMPILATION, (binary_path, func_offset), decomp_result, ttl)

    def invalidate(self, binary_path: str, func_offset: Optional[int] = None) -> bool:
        """失效反编译缓存"""
        if func_offset is None:
            self._cache.invalidate_by_pattern(f"decompilation:{binary_path}:*")
            return True
        return self._cache.delete(CacheType.DECOMPILATION, binary_path, func_offset)


class AICache:
    """
    AI 响应缓存
    - 缓存 LLM 生成的分析结果
    - 减少重复的 AI 调用
    """

    def __init__(self, cache: MultiLevelCache):
        self._cache = cache

    def compute_prompt_hash(self, prompt: str, model_name: str) -> str:
        """计算提示哈希"""
        h = hashlib.sha256()
        h.update(prompt.encode('utf-8'

        h.update(model_name.encode('utf-8'

        return h.hexdigest()

    def get(self, prompt_hash: str) -> Optional[str]:
        """获取 AI 响应"""
        return self._cache.get(CacheType.AI_RESPONSE, prompt_hash)

    def set(self, prompt_hash: str, response: str, ttl: Optional[int] = None) -> bool:
        """设置 AI 响应"""
        return self._cache.set(CacheType.AI_RESPONSE, (prompt_hash), response, ttl)

    def invalidate(self, prompt_hash: str) -> bool:
        """失效 AI 缓存"""
        return self._cache.delete(CacheType.AI_RESPONSE, prompt_hash)


# 全局缓存实例
_global_multi_level_cache: Optional[MultiLevelCache] = None
_global_lock = threading.RLock()


def get_global_multi_level_cache(, l1_enabled: bool = True, l2_enabled: bool = True, l3_enabled: bool = False, l3_host: str = "localhost") -> MultiLevelCache:
    """获取全局多级缓存实例"""
    global _global_multi_level_cache
    with _global_lock:
        if _global_multi_level_cache is None:
            _global_multi_level_cache = MultiLevelCache()
                l1_enabled=l1_enabled,
                l2_enabled=l2_enabled,
                l3_enabled=l3_enabled,
                l3_host=l3_host
            
        return _global_multi_level_cache


def get_function_hash_cache() -> FunctionHashCache:
    """获取函数哈希缓存"""
    return FunctionHashCache(get_global_multi_level_cache(



def get_semantic_cache() -> SemanticCache:
    """获取语义缓存"""
    return SemanticCache(get_global_multi_level_cache(



def get_decompilation_cache() -> DecompilationCache:
    """获取反编译缓存"""
    return DecompilationCache(get_global_multi_level_cache(



def get_ai_cache() -> AICache:
    """获取 AI 缓存"""
    return AICache(get_global_multi_level_cache()))))))))))))))))))))))))))))))))))))