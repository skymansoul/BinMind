"""
内容寻址报告缓存 — 相同输入 → 相同输出路径，规避重复计算。

设计:
  - 缓存键 = SHA-256(binary_path || binary_hash || 分析参数 || decomp_hash)
  - 缓存值 = {format: filepath} 映射
  - 文件系统存储，两层目录: cache/<key[:2]>/<key[2:]>.json
    参考 Git object store 散列分布策略，防单目录文件数过载

失效策略: 仅哈希匹配命中，无 TTL。
          参数或二进制内容变化导致新键 → 天然版本化。

参考:
  Git object store (sha1 前两位为目录名的散列分布)
  Bazel action cache (content-addressable, 输入哈希 ≡ 缓存键)

修改记录:
  2025-07-16 10:45 - 追加缓存统计 (hit/miss/size)
  2025-07-20 08:37 - 缓存值追加时间戳字段，便于旧条目清理
"""

import hashlib
import json
import logging
import os
import time
from typing import Any, Dict, List, Optional, Tuple

_log = logging.getLogger(__name__)


class ReportCache:
    """基于 SHA-256 输入签名的内容寻址报告缓存存储。"""

    def __init__(self, cache_dir: str = './reports/cache'):
        self.cache_dir = cache_dir
        self._hits: int = 0
        self._misses: int = 0
        os.makedirs(cache_dir, exist_ok=True)

    # --- 缓存键计算 ---

    def compute_cache_key(
        self,
        binary_path: str,
        binary_info: Dict[str, Any],
        decomp_results: List[Dict],
        report_formats: List[str],
        crash_analysis: Optional[Dict] = None,
        exploit_result: Optional[Dict] = None,
        symbolic_result: Optional[Dict] = None
    ) -> str:
        """
        缓存键 = SHA-256(输入签名)。

        排除时间戳等扰动字段，仅取影响报告输出的稳定字段。
        binary_info 提取 arch/bits/format/checksec/hash 等结构属性。
        """
        hasher = hashlib.sha256()
        # 二进制身份
        hasher.update(binary_path.encode())
        bh = binary_info.get('binary_hash', binary_info.get('sha256', ''))
        hasher.update(bh.encode())
        hasher.update(binary_info.get('arch', '').encode())
        hasher.update(str(binary_info.get('bits', '')).encode())
        hasher.update(binary_info.get('binary_format', '').encode())
        # 报告格式序列
        hasher.update('|'.join(sorted(report_formats)).encode())
        # 反编译结果 (稳定排序)
        decomp_json = json.dumps(decomp_results, sort_keys=True, default=str)
        hasher.update(decomp_json.encode())
        # 可选分析结果载荷
        if crash_analysis:
            hasher.update(json.dumps(crash_analysis, sort_keys=True, default=str).encode())
        if exploit_result:
            hasher.update(json.dumps(exploit_result, sort_keys=True, default=str).encode())
        if symbolic_result:
            hasher.update(json.dumps(symbolic_result, sort_keys=True, default=str).encode())

        return hasher.hexdigest()

    # --- 读写缓存 ---

    def _cache_path(self, key: str) -> str:
        """哈希键 → cache_dir/ab/cdef...json (双层散列目录)。"""
        return os.path.join(self.cache_dir, key[:2], f"{key[2:]}.json")

    def get(self, key: str) -> Optional[Dict[str, str]]:
        """
        读取缓存条目。命中 → {format: filepath}，未命中 → None。
        """
        path = self._cache_path(key)
        if not os.path.isfile(path):
            self._misses += 1
            return None
        try:
            with open(path, 'r', encoding='utf-8') as f:
                entry = json.load(f)
            # 校验缓存文件路径是否仍存在
            for fmt, fp in entry.get('paths', {}).items():
                if not os.path.isfile(fp):
                    _log.debug("缓存条目失效: %s (文件不存在: %s)", key, fp)
                    self._misses += 1
                    return None
            self._hits += 1
            return entry['paths']
        except (json.JSONDecodeError, KeyError, OSError) as e:
            _log.debug("缓存读取异常: %s", e)
            self._misses += 1
            return None

    def put(self, key: str, report_paths: Dict[str, str]) -> None:
        """原子写入缓存条目 (临时文件 + os.replace)。"""
        path = self._cache_path(key)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        entry = {
            'paths': report_paths,
            'cached_at': time.time(),
            'cache_version': 1,
        }
        # 临时文件 + 原子重命名，防并发写入损坏
        tmp = path + f".{os.getpid()}.tmp"
        try:
            with open(tmp, 'w', encoding='utf-8') as f:
                json.dump(entry, f, ensure_ascii=False)
            os.replace(tmp, path)
        except OSError as e:
            _log.warning("缓存写入失败: %s", e)
            try:
                os.unlink(tmp)
            except OSError:
                pass

    # --- 统计与清理 ---

    @property
    def stats(self) -> Dict[str, Any]:
        total = self._hits + self._misses
        return {
            'hits': self._hits,
            'misses': self._misses,
            'hit_rate': round(self._hits / total, 3) if total > 0 else 0.0,
            'total_requests': total,
        }

    def count_entries(self) -> int:
        """递归遍历缓存目录树，统计 .json 条目总数。"""
        count = 0
        try:
            for root, dirs, files in os.walk(self.cache_dir):
                count += sum(1 for f in files if f.endswith('.json'))
        except OSError:
            pass
        return count
