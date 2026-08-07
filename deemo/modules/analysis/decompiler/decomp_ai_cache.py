"""
decomp_ai_cache.py：缓存管理 for 反编译结果

提供 LRU内存与磁盘双级缓存 for 反编译
results external API响应s. 包含 速率限制 for API调用s

All缓存-related 模块级变量与函数 extracted
decomp_ai.py keep 核心模块 focused 业务逻辑
"""

import os
import json
import time
import hashlib
import logging
from typing import Dict, Optional, Any
from collections import OrderedDict

from config import Config

logger = logging.getLogger(__name__)


# 缓存模块级 variables

DECOMP_CACHE: Dict[str, Dict[str, Any]] = {}
DECOMP_CACHE_DIR = os.path.join(os.getcwd(), '.deemo_cache')
API_CACHE_DIR = os.path.join(os.getcwd(), '.api_cache')
API_RATE_LIMIT = getattr(Config, 'EXTERNAL_API_RATE_LIMIT', 10)
_last_api_call_time = 0.0
_api_call_count = 0

_LEGACY_MODE = False  # 保留


# Utility

def compute_binary_hash(binary_path: str) -> Optional[str]:
    # 计算二进制文件的SHA256哈希值，失败返回None
    try:
        if not os.path.exists(binary_path):
            return None

        hash_sha256 = hashlib.sha256()
        with open(binary_path, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                hash_sha256.update(chunk)
        return hash_sha256.hexdigest()
    except Exception as e:
        logger.debug(f"计算二进制哈希失败: {e}")
        return None


# Internal 辅助函数

def _ensure_cache_dir() -> None:
    """
    确保缓存目录存在
    """
    os.makedirs(DECOMP_CACHE_DIR, exist_ok=True)
    os.makedirs(API_CACHE_DIR, exist_ok=True)


def _format_size(size: int) -> str:
    # 格式化 byte size human-readable string
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size < 1024.0:
            return f"{size:.2f} {unit}"
        size /= 1024.0
    return f"{size:.2f} TB"


# 遗留 disk-缓存CRC 校验 (已废弃 v2)
# def _validate_cache_integrity(cache_file):
#     with open(cache_file, 'rb') as f:
#         raw = f.read()
#         expected_crc = struct.unpack('>I', raw[-4:])[0]
#         actual_crc = zlib.crc32(raw[:-4]) & 0xFFFFFFFF
#         return expected_crc == actual_crc

# 反编译 缓存

def get_cached_decompilation(binary_hash: str, func_name: str) -> Optional[Dict[str, Any]]:
    """
    从持久化缓存获取反编译结果
    
    Args:
    binary_hash: 二进制文件的 SHA256 哈希值
    func_name: 函数名
    
    返回:
    缓存的反编译结果字典，如果不存在则返回 None
    
    Example:
    >>> binary_hash = compute_binary_hash('binary.exe')
    >>> result = get_cached_反编译(binary_hash, 'main')
    """
    if not binary_hash or not func_name:
        return None

    try:
        _ensure_cache_dir()

        cache_key = f"{binary_hash}_{func_name}"

        if cache_key in DECOMP_CACHE:
            logger.debug(f"内存缓存命中: {func_name}")
            return DECOMP_CACHE[cache_key]

        cache_file = os.path.join(DECOMP_CACHE_DIR, f"{cache_key}.json")
        if os.path.exists(cache_file):
            cache_ttl = getattr(Config, 'CACHE_TTL', 3600)
            file_age = time.time() - os.path.getmtime(cache_file)

            if file_age < cache_ttl:
                with open(cache_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    DECOMP_CACHE[cache_key] = data
                    logger.debug(f"磁盘缓存命中: {func_name}")
                    return data
            else:
                logger.debug(f"缓存已过期: {func_name} (age={file_age:.0f}s)")
                os.remove(cache_file)

        return None
    except Exception as e:
        logger.debug(f"读取反编译缓存失败: {e}")
        return None


def cache_decompilation(
    binary_hash: str,
    func_name: str,
    decomp_result: Dict[str, Any]
) -> bool:
    """
    缓存反编译结果到内存和磁盘
    
    Args:
    binary_hash: 二进制文件的 SHA256 哈希值
    func_name: 函数名
    decomp_result: 反编译结果字典
    
    返回:
    是否缓存成功
    """
    if not binary_hash or not func_name or not decomp_result:
        return False

    try:
        _ensure_cache_dir()

        cache_key = f"{binary_hash}_{func_name}"

        DECOMP_CACHE[cache_key] = decomp_result.copy()

        cache_file = os.path.join(DECOMP_CACHE_DIR, f"{cache_key}.json")

        cache_data = {
            'binary_hash': binary_hash,
            'func_name': func_name,
            'decomp_result': decomp_result,
            'cached_at': time.time()
        }

        with open(cache_file, 'w', encoding='utf-8') as f:
            json.dump(cache_data, f, ensure_ascii=False, indent=2)

        logger.debug(f"反编译结果已缓存: {func_name}")
        return True
    except Exception as e:
        logger.debug(f"缓存反编译结果失败: {e}")
        return False


# API 缓存

def get_cached_api_response(api_key: str, ttl: int = None) -> Optional[Any]:
    """
    从缓存获取 API 响应
    
    Args:
    api_key: API 请求的唯一标识（使用 URL + 参数的哈希）
    ttl: 缓存有效期（秒），默认使用配置值
    
    返回:
    缓存的响应数据，不存在或过期时返回 None
    """
    if not api_key:
        return None

    try:
        _ensure_cache_dir()

        if ttl is None:
            ttl = getattr(Config, 'CACHE_TTL', 3600)

        cache_file = os.path.join(API_CACHE_DIR, f"{api_key}.json")

        if os.path.exists(cache_file):
            file_age = time.time() - os.path.getmtime(cache_file)

            if file_age < ttl:
                with open(cache_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    logger.debug(f"API 缓存命中: {api_key[:32]}...")
                    return data.get('response')
            else:
                logger.debug(f"API 缓存已过期: {api_key[:32]}... (age={file_age:.0f}s)")
                os.remove(cache_file)

        return None
    except Exception as e:
        logger.debug(f"读取 API 缓存失败: {e}")
        return None


def cache_api_response(api_key: str, response: Any) -> bool:
    """
    缓存 API 响应
    
    Args:
    api_key: API 请求的唯一标识
    response: 响应数据（需要可 JSON 序列化）
    
    返回:
    是否缓存成功
    """
    if not api_key:
        return False

    try:
        _ensure_cache_dir()

        cache_file = os.path.join(API_CACHE_DIR, f"{api_key}.json")

        cache_data = {
            'api_key': api_key,
            'response': response,
            'cached_at': time.time()
        }

        with open(cache_file, 'w', encoding='utf-8') as f:
            json.dump(cache_data, f, ensure_ascii=False, indent=2)

        logger.debug(f"API 响应已缓存: {api_key[:32]}...")
        return True
    except Exception as e:
        logger.debug(f"缓存 API 响应失败: {e}")
        return False


# 速率限制

def check_api_rate_limit() -> bool:
    """
    检查 API 调用速率限制
    
    根据时间窗口和最大调用次数判断是否允许调用
    简单实现：使用滑动窗口算法
    
    返回:
    True 表示允许调用，False 表示触发速率限制
    """
    global _last_api_call_time, _api_call_count

    current_time = time.time()
    window_size = 60.0

    if current_time - _last_api_call_time > window_size:
        _api_call_count = 0
        _last_api_call_time = current_time

    if _api_call_count < API_RATE_LIMIT:
        _api_call_count += 1
        _last_api_call_time = current_time
        return True
    else:
        wait_time = window_size - (current_time - _last_api_call_time)
        logger.warning(f"触发 API 速率限制，还需等待 {wait_time:.1f} 秒")
        return False


def wait_for_api_rate_limit(timeout: float = 10.0) -> bool:
    """
    等待直到 API 速率限制解除
    
    Args:
    timeout: 最大等待时间（秒）
    
    返回:
    True 表示可以调用，False 表示等待超时
    """
    start_time = time.time()

    while time.time() - start_time < timeout:
        if check_api_rate_limit():
            return True
        time.sleep(0.5)

    logger.error(f"API 速率限制等待超时 ({timeout}s)")
    return False


# 缓存cleanup

def clear_decomp_cache() -> int:
    """
    清除所有反编译缓存
    
    返回:
    清除的缓存文件数量
    """
    cleared_count = 0

    try:
        DECOMP_CACHE.clear()

        if os.path.exists(DECOMP_CACHE_DIR):
            for filename in os.listdir(DECOMP_CACHE_DIR):
                filepath = os.path.join(DECOMP_CACHE_DIR, filename)
                if os.path.isfile(filepath):
                    os.remove(filepath)
                    cleared_count += 1

        logger.info(f"已清除 {cleared_count} 个反编译缓存文件")
    except Exception as e:
        logger.error(f"清除反编译缓存失败: {e}")

    return cleared_count


def clear_api_cache() -> int:
    """
    清除所有 API 缓存
    
    返回:
    清除的缓存文件数量
    """
    cleared_count = 0

    try:
        if os.path.exists(API_CACHE_DIR):
            for filename in os.listdir(API_CACHE_DIR):
                filepath = os.path.join(API_CACHE_DIR, filename)
                if os.path.isfile(filepath):
                    os.remove(filepath)
                    cleared_count += 1

        logger.info(f"已清除 {cleared_count} 个 API 缓存文件")
    except Exception as e:
        logger.error(f"清除 API 缓存失败: {e}")

    return cleared_count


def get_cache_stats() -> Dict[str, Any]:
    """
    获取缓存统计信息
    
    返回:
    包含缓存统计信息的字典
    """
    try:
        decomp_cache_count = 0
        decomp_cache_size = 0
        api_cache_count = 0
        api_cache_size = 0

        if os.path.exists(DECOMP_CACHE_DIR):
            for filename in os.listdir(DECOMP_CACHE_DIR):
                filepath = os.path.join(DECOMP_CACHE_DIR, filename)
                if os.path.isfile(filepath):
                    decomp_cache_count += 1
                    decomp_cache_size += os.path.getsize(filepath)

        if os.path.exists(API_CACHE_DIR):
            for filename in os.listdir(API_CACHE_DIR):
                filepath = os.path.join(API_CACHE_DIR, filename)
                if os.path.isfile(filepath):
                    api_cache_count += 1
                    api_cache_size += os.path.getsize(filepath)

        return {
            'decomp_cache': {
                'memory_entries': len(DECOMP_CACHE),
                'disk_count': decomp_cache_count,
                'disk_size': _format_size(decomp_cache_size),
                'directory': DECOMP_CACHE_DIR
            },
            'api_cache': {
                'disk_count': api_cache_count,
                'disk_size': _format_size(api_cache_size),
                'directory': API_CACHE_DIR
            },
            'rate_limit': {
                'calls_per_minute': API_RATE_LIMIT,
                'current_count': _api_call_count,
                'window_remaining': max(0.0, 60.0 - (time.time() - _last_api_call_time))
            }
        }
    except Exception as e:
        logger.error(f"获取缓存统计失败: {e}")
        return {'error': str(e)}
