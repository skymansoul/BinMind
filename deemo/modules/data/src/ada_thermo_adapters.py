# coding: utf-8
"""
AdaThermoLBF 兼容桥接层 —— 为现有 dedup/cache 接口提供温度自适应替换方案。

桥接映射:
  - BloomLikeFilter: 替代 dedup.BloomFilter, DedupEngine._bloom 可直插替换。
  - CuckooLikeFilter: 替代 dedup.CuckooFilter (insert/contains/delete)。
  - ThermoFilterCache: 替代 cache.LRUCache 的值缓存 (get/set/delete/clear),
    以 AdaThermoLBF 做负向预判, 淘汰最低温条目并同步 delete 出过滤器。
  - ThermoDedupEngine: DedupEngine 子类, 将静态 Bloom 置换为温度自适应过滤器。

论文关联: 同 ada_thermo_lbf —— 温度加权 + 可删除位 + 对抗上界 (DWLBF 2025,
,, ICML 2025)。
"""

import time
from typing import Any, Dict, List, Optional, Tuple

from .ada_thermo_lbf import AdaThermoLBF
from .dedup import DedupEngine

__all__ = [
    "BloomLikeFilter",
    "CuckooLikeFilter",
    "ThermoFilterCache",
    "ThermoDedupEngine",
    "thermo_dedup_from_config",
    "thermo_dedup_engine_from_config",
    "self_test",
]

# BloomLikeFilter —— dedup.BloomFilter 签名兼容适配

class BloomLikeFilter:
    """dedup.BloomFilter 的等接口适配器。

    方法映射:
      BloomFilter.add            -> AdaThermoLBF.add
      BloomFilter.might_contain  -> AdaThermoLBF.contains
      BloomFilter.approx_count   -> AdaThermoLBF.__len__
      BloomFilter.estimated_fpr  -> AdaThermoLBF.estimated_fpr

    去重查询主体为非成员 (新唯一键), 默认 weight_mode="plbf" 使冷带
    获取更多内存并挂载精确兜底, 将高频查询路径的误判压至零。
    """

    def __init__(self, capacity: int = 1 << 20, target_fpr: float = 0.01,
                 num_bands: int = 4, weight_mode: str = "plbf", **kw):
        self._lbf = AdaThermoLBF(capacity=capacity, target_fpr=target_fpr,
                                 num_bands=num_bands, weight_mode=weight_mode,
                                 heat_on_query=False, **kw)

    def add(self, data: bytes):
        self._lbf.add(data)

    def might_contain(self, data: bytes) -> bool:
        return self._lbf.contains(data)

    @property
    def approx_count(self) -> int:
        return len(self._lbf)

    def estimated_fpr(self) -> float:
        return self._lbf.estimated_fpr()

# 温度自适应扩展接口 (诊断与调优用)
    def delete(self, data: bytes) -> bool:
        return self._lbf.delete(data)

    def touch(self, data: bytes):
        return self._lbf.touch(data)

    def worst_case_fpr_estimate(self) -> Dict:
        return self._lbf.worst_case_fpr_estimate()

    def resilience_escalate(self, budget: Optional[float] = None) -> Dict:
        return self._lbf.resilience_escalate(budget)

    def adjust_capacity(self, bits: int):
        return self._lbf.adjust_capacity(bits)

    def stats(self) -> Dict:
        return self._lbf.stats()

# CuckooLikeFilter —— dedup.CuckooFilter 等接口适配

class CuckooLikeFilter:
    """dedup.CuckooFilter 的兼容封装 (insert/contains/delete/load_factor)。

    保留 CuckooFilter 构造签名 (capacity/bucket_size/fingerprint_bits),
    桶参数仅作兼容占位; 底层行为完全由 AdaThermoLBF 提供。
    """

    def __init__(self, capacity: int = 100000, bucket_size: int = 4,
                 fingerprint_bits: int = 12, **kw):
        self._capacity = max(int(capacity), 1)
        self._bucket_size = bucket_size
        self._fingerprint_bits = fingerprint_bits
        self._lbf = AdaThermoLBF(capacity=self._capacity, target_fpr=0.01,
                                 weight_mode="plbf", heat_on_query=False, **kw)

    def insert(self, data: bytes) -> bool:
        return self._lbf.add(data)

    def contains(self, data: bytes) -> bool:
        return self._lbf.contains(data)

    def delete(self, data: bytes) -> bool:
        return self._lbf.delete(data)

    def __len__(self) -> int:
        return len(self._lbf)

    @property
    def load_factor(self) -> float:
        return len(self._lbf) / self._capacity

# ThermoFilterCache —— 温度自适应值缓存, LRUCache 替换方案

class ThermoFilterCache:
    """温度自适应值缓存 —— AdaThermoLBF 负向预判 + 低温条目优先逐出。

    接口同 cache.LRUCache: get/set/delete/clear/count/size_bytes/stats。
    逐出策略: 移除温度最低的条目并同步 delete 过滤器 —— DWLBF 的
    "冷数据可删除"语义在缓存层的具体应用。

    边界: _coldest_key 为 O(n) 线性扫描, 属参考实现;
    高频写入可替换为堆结构维护温度排序。
    """

    def __init__(self, max_bytes: int = 64 * 1024 * 1024,
                 default_ttl: float = 300.0, capacity: int = 1 << 18,
                 target_fpr: float = 0.02, num_bands: int = 4,
                 exact_cap: int = 0):
        self.max_bytes = max(int(max_bytes), 1)
        self.default_ttl = default_ttl
        self._lbf = AdaThermoLBF(capacity=capacity, target_fpr=target_fpr,
                                 num_bands=num_bands, weight_mode="dwlbf",
                                 heat_on_query=True, exact_cap=exact_cap)
        self._store: Dict[str, Tuple[Any, float, int]] = {}
        self._used = 0
        self._hits = 0
        self._misses = 0

    def get(self, key: str) -> Optional[Any]:
        now = time.monotonic()
        if not self._lbf.contains(key.encode("utf-8")):
            self._misses += 1
            return None
        item = self._store.get(key)
        if item is None:
            self._misses += 1
            return None
        value, expires, cost = item
        if expires > 0 and now >= expires:
            self._store.pop(key, None)
            self._used -= cost
            self._lbf.delete(key.encode("utf-8"))
            self._misses += 1
            return None
        self._lbf.touch(key.encode("utf-8"))
        self._hits += 1
        return value

    def set(self, key: str, value: Any, ttl: Optional[float] = None,
            cost: Optional[int] = None):
        ttl = self.default_ttl if ttl is None else ttl
        cost = cost if cost is not None else (
            len(value) if isinstance(value, (bytes, str)) else 64)
        expires = time.monotonic() + ttl if ttl > 0 else 0
        kb = key.encode("utf-8")
        # 逐出低温条目至空间足够
        while self._used + cost > self.max_bytes and self._store:
            cold = self._coldest_key()
            if cold is None:
                break
            _v, _e, c = self._store.pop(cold)
            self._used -= c
            self._lbf.delete(cold.encode("utf-8"))
        self._store[key] = (value, expires, cost)
        self._used += cost
        self._lbf.add(kb)

    def _coldest_key(self) -> Optional[str]:
        best = None
        best_f = None
        for k in self._store:
            f = self._lbf.frequency(k.encode("utf-8"))
            if best_f is None or f < best_f:
                best_f = f
                best = k
        return best

    def delete(self, key: str):
        item = self._store.pop(key, None)
        if item is not None:
            self._used -= item[2]
        self._lbf.delete(key.encode("utf-8"))

    def clear(self):
        self._store.clear()
        self._used = 0
        self._hits = 0
        self._misses = 0
        self._lbf.clear()

    @property
    def count(self) -> int:
        return len(self._store)

    @property
    def size_bytes(self) -> int:
        return self._used

    @property
    def hit_rate(self) -> float:
        total = self._hits + self._misses
        return self._hits / max(total, 1)

    @property
    def stats(self) -> Dict:
        return {
            "count": self.count,
            "used_bytes": self._used,
            "hits": self._hits,
            "misses": self._misses,
            "hit_rate": round(self.hit_rate, 4),
            "filter": self._lbf.stats(),
        }

# ThermoDedupEngine —— DedupEngine 温度自适应派生

class ThermoDedupEngine(DedupEngine):
    """DedupEngine 的温度自适应实现 —— 静态 Bloom 替换为 AdaThermoLBF。

    用法与 DedupEngine 完全一致 (dedup_by_hash / dedup_binary /
    register_duplicate / bloom_stats 等); 额外暴露 thermo_stats /
    escalate / thermo_worst_case 供诊断与对抗调优。
    """

    def __init__(self, db, config, capacity: int = 1 << 20,
                 target_fpr: float = 0.01, num_bands: int = 4,
                 exact_cap: int = 0):
        super().__init__(db, config)
        self._bloom = BloomLikeFilter(capacity=capacity, target_fpr=target_fpr,
                                      num_bands=num_bands, exact_cap=exact_cap)

    def thermo_stats(self) -> Dict:
        return self._bloom.stats()

    def thermo_worst_case(self) -> Dict:
        return self._bloom.worst_case_fpr_estimate()

    def escalate(self, budget: Optional[float] = None) -> Dict:
        return self._bloom.resilience_escalate(budget)

def thermo_dedup_from_config(db, config=None, **kw):
    """从 config 构造 ThermoDedupEngine (对应 dedup.dedup_from_config)。"""
    if config is None:
        from .config import get_config
        config = get_config()
    return ThermoDedupEngine(db, config.dedup, **kw)

# 别名 —— 与 dedup_from_config 命名对称
thermo_dedup_engine_from_config = thermo_dedup_from_config

# self_test —— 模块导入冒烟 + 正确性验证

def self_test() -> Dict:
    """冒烟测试: 验证无假阴性 + 删除语义 + 兼容接口 + 对抗上界。

    返回汇总字典; 断言失败抛出 AssertionError。
    """
    result: Dict[str, Any] = {"checks": []}

    def check(name: str, cond: bool):
        result["checks"].append((name, bool(cond)))
        assert cond, name

    # 1) 无假阴性 + 冷桶误判消除
    lbf = AdaThermoLBF(capacity=2000, target_fpr=0.05, num_bands=4,
                       exact_cap=0, rebalance_interval=300)
    keys = [f"k_{i}".encode() for i in range(800)]
    for k in keys:
        lbf.add(k)
    check("no_false_negative", all(lbf.contains(k) for k in keys))
    check("estimated_fpr_bounded", lbf.estimated_fpr() < 0.06)

    # 2) 删除语义: 冷带可删, 删除后不再命中
    lbf2 = AdaThermoLBF(capacity=2000, target_fpr=0.05, num_bands=2,
                        deletable_ratio=1.0, exact_cap=0)
    for k in keys[:400]:
        lbf2.add(k)
    for k in keys[:400]:
        check("delete_ok", lbf2.delete(k))
    check("deleted_absent", all(not lbf2.contains(k) for k in keys[:400]))

    # 3) 热键锁定: deletable_ratio=0 → 全部热桶, delete 拒绝
    lbf3 = AdaThermoLBF(capacity=1000, target_fpr=0.05, num_bands=2,
                        deletable_ratio=0.0)
    lbf3.add(b"pin")
    check("hot_delete_refused", not lbf3.delete(b"pin"))
    check("hot_still_present", lbf3.contains(b"pin"))

    # 4) BloomLikeFilter 兼容 dedup.BloomFilter
    bf = BloomLikeFilter(capacity=1000, target_fpr=0.05, num_bands=3)
    for k in keys[:300]:
        bf.add(k)
    check("bloom_approx_count", bf.approx_count == 300)
    check("bloom_might_contain", bf.might_contain(keys[0]))
    check("bloom_fpr_callable", 0.0 <= bf.estimated_fpr() <= 1.0)

    # 5) CuckooLikeFilter 兼容 dedup.CuckooFilter
    cf = CuckooLikeFilter(capacity=1000, num_bands=3)
    cf.insert(b"a")
    check("cuckoo_contains", cf.contains(b"a"))
    check("cuckoo_delete", cf.delete(b"a"))
    check("cuckoo_len", len(cf) == 0)

    # 6) ThermoFilterCache 兼容 LRUCache
    tc = ThermoFilterCache(max_bytes=4096, capacity=512, num_bands=3)
    for i in range(50):
        tc.set(f"c_{i}", f"v_{i}")
        tc.get(f"c_{i}")
    check("cache_get", tc.get("c_0") == "v_0")
    check("cache_delete", (tc.delete("c_0"), tc.get("c_0")) == (None, None))

    # 7) 对抗上界 + 升级
    st = lbf.worst_case_fpr_estimate()
    check("worst_has_fields", all(k in st for k in (
        "worst_band_fpr", "effective_worst_fpr", "within_budget")))
    r = lbf.resilience_escalate(0.02)
    check("escalate_returns", "escalated" in r)

    # 8) 自适应调整接口
    lbf.adjust_capacity(lbf.stats()["total_mem_bits"] * 2)
    lbf.set_target_fpr(0.02)
    check("post_adjust_no_fn", all(lbf.contains(k) for k in keys))

    result["ok"] = all(ok for _n, ok in result["checks"])
    return result
