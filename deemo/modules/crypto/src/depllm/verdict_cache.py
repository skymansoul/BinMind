"""
判定缓存 — 相同依赖上下文复用判定。

参考 低开销要求:
  LLM 调用昂贵；同 (误用类型, API, 上下文, 调用链) 组合反复出现时
  缓存直接复用，削减开销。键 = 上下文规范化 SHA-256 摘要。

边界:
  - LRU 上限，防无界增长。
  - 键基于规范化字段排序序列化，字段顺序无关。
  - 线程安全，读写加锁。
"""

import hashlib
import json
import threading
from collections import OrderedDict
from dataclasses import dataclass
from typing import Dict, Optional

@dataclass
class Verdict:
    """单次判定."""
    verdict: str            # confirmed / rejected / uncertain
    reason: str = ""
    from_cache: bool = False
    source: str = "llm"     # llm / heuristic

class VerdictCache:
    """LRU 判定缓存 — 上下文哈希 → Verdict."""

    def __init__(self, maxsize: int = 256) -> None:
        self._data: "OrderedDict[str, Verdict]" = OrderedDict()
        self._maxsize = int(maxsize)
        self._lock = threading.Lock()
        self._hits = 0
        self._misses = 0

    @staticmethod
    def _make_key(context: Dict[str, object]) -> str:
        """依赖上下文 → 缓存键。

        仅取判定相关字段；列表排序后哈希，同集不同序 → 同键。
        """
        up = context.get('upstream_apis') or []
        down = context.get('downstream_apis') or []
        norm = {
            'misuse_type': context.get('misuse_type', ''),
            'api': context.get('api', ''),
            'severity': context.get('severity', ''),
            'upstream': sorted(up),
            'downstream': sorted(down),
            'chain': context.get('call_chain', ''),
            'entropy_bucket': int(context.get('region_entropy', 0.5) * 10),
        }
        blob = json.dumps(norm, sort_keys=True, ensure_ascii=False).encode('utf-8')
        return hashlib.sha256(blob).hexdigest()

    def get(self, context: Dict[str, object]) -> Optional[Verdict]:
        key = self._make_key(context)
        with self._lock:
            if key in self._data:
                self._hits += 1
                self._data.move_to_end(key)
                v = self._data[key]
                v.from_cache = True
                return v
            self._misses += 1
            return None

    def put(self, context: Dict[str, object], verdict: Verdict) -> None:
        key = self._make_key(context)
        with self._lock:
            verdict.from_cache = False
            self._data[key] = verdict
            self._data.move_to_end(key)
            if len(self._data) > self._maxsize:
                self._data.popitem(last=False)

    def stats(self) -> Dict[str, object]:
        with self._lock:
            total = self._hits + self._misses
            return {
                'size': len(self._data),
                'maxsize': self._maxsize,
                'hits': self._hits,
                'misses': self._misses,
                'hit_rate': round(self._hits / total, 3) if total else 0.0,
            }

    def clear(self) -> None:
        with self._lock:
            self._data.clear()
