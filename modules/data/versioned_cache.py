"""
版本化数据缓存 (Versioned Data Cache, VDC)
------------------------------------------
内容寻址 + 版本标记的二进制分析数据缓存, 支持部分失效.

设计依据:
  标准缓存用 TTL 或 LRU 淘汰——对二进制分析数据不合适:
  同一二进制的分析结果可跨多次运行复用, 但分析器版本升级
  或配置变更时需全部或部分失效. TTL 不知道"何时该失效".

  VDC 为每条缓存条目标记 (binary_hash, analyzer_version, config_hash),
  查询时精确匹配——任意维度变化即视为 miss.
  支持分层失效: 仅失效特定分析器的结果而保留其他.
"""
import hashlib
import json
import time
from collections import OrderedDict
from typing import Any, Dict, List, Optional, Tuple


class VersionedCache:
    """版本化数据缓存.

    用法:
      vdc = VersionedCache(max_size=1000)
      vdc.put('binary_abc', 'decompile', 'v2.1', config_hash='cfg1',
              data={'functions': [...]})
      result = vdc.get('binary_abc', 'decompile', 'v2.1', config_hash='cfg1')
    """

    def __init__(self, max_size: int = 1000):
        self._store: OrderedDict = OrderedDict()
        self._max = max_size
        self._hits = 0
        self._misses = 0

    def _make_key(self, binary_hash: str, analyzer: str,
                  version: str, config_hash: str = "") -> str:
        raw = f'{binary_hash}|{analyzer}|{version}|{config_hash}'
        return hashlib.sha256(raw.encode()).hexdigest()[:20]

    def put(self, binary_hash: str, analyzer: str, version: str,
            data: Any, config_hash: str = ""):
        key = self._make_key(binary_hash, analyzer, version, config_hash)
        if key in self._store:
            del self._store[key]
        self._store[key] = {
            'data': data,
            'binary_hash': binary_hash,
            'analyzer': analyzer,
            'version': version,
            'config_hash': config_hash,
            'cached_at': time.time(),
        }
        while len(self._store) > self._max:
            self._store.popitem(last=False)

    def get(self, binary_hash: str, analyzer: str,
            version: str, config_hash: str = "") -> Optional[Any]:
        key = self._make_key(binary_hash, analyzer, version, config_hash)
        entry = self._store.get(key)
        if entry:
            self._store.move_to_end(key)
            self._hits += 1
            return entry['data']
        self._misses += 1
        return None

    def invalidate_analyzer(self, analyzer: str):
        """失效某分析器的所有缓存."""
        keys = [k for k, v in self._store.items() if v['analyzer'] == analyzer]
        for k in keys:
            del self._store[k]

    def invalidate_binary(self, binary_hash: str):
        """失效某二进制的所有缓存."""
        keys = [k for k, v in self._store.items() if v['binary_hash'] == binary_hash]
        for k in keys:
            del self._store[k]

    def hit_rate(self) -> float:
        total = self._hits + self._misses
        return self._hits / total if total > 0 else 0.0

    def stats(self) -> Dict[str, Any]:
        analyzers = {}
        for v in self._store.values():
            a = v['analyzer']
            analyzers[a] = analyzers.get(a, 0) + 1
        return {
            'size': len(self._store), 'max': self._max,
            'hit_rate': round(self.hit_rate(), 3),
            'by_analyzer': analyzers,
        }
