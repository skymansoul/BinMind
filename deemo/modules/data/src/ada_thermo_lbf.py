# coding: utf-8
"""
AdaThermoLBF —— 自适应学习型布隆过滤器 + 数据温度加权删除。

核心机制:
  - 以访问频率量化数据温度, 温度决定桶路由、表示复杂度与可删除性。
  - 热桶: 紧凑位布隆 (1 bit/格, 不可删); 冷桶: 计数布隆 (4 bit/格,
    可删除) 并挂载精确兜底集合 —— 冷数据的误判惩罚由精确兜底吸收至零。
  - 每桶内存与哈希数 k 由温度分布自适应推导; 周期间隔重建 (rebuild) 为
    O(n) 全量重建, 频度由 rebalance_interval 参数约束。
  - 对抗鲁棒: worst_case_fpr_estimate() 输出最坏情况误判上界;
    resilience_escalate() 在超预算时将对抗目标带强制转为可删除 + 精确兜底。

边界条件:
  - 默认 max_tracked=0 (无上限跟踪): 计数布隆保证 add/delete 一一抵消,
    消除"双增残留"导致的语义错误。
  - 默认 exact_cap=0 (无上限精确兜底): 冷桶无假阴性, 误判消除成立;
    设定有界 cap 后兜底退化为纯正向缓存, 不改变成员判定结果。
  - rebalance 为 O(n) 重建, 高频写入应调大 rebalance_interval。

相关文献:
  - Learned LSM-trees: Two Approaches Using Learned Bloom Filters
: 按热度分配过滤器预算, 热键用更紧凑表示。
  - DWLBF: a deletable weighted learned Bloom Filter based on data
    temperature: deletable bit
    + 温度加权删除。
  - Adversary Resilient Learned Bloom Filters:
    最坏情况误判上界与兜底降级机制。
  - Ensemble Learned Bloom Filters: Two Oracles are Better than One
: 温度信号与稳定哈希特征的双信号集成。
"""

import bisect
import math
from typing import Dict, List, Optional, Sequence, Tuple

from .dedup import _fnv1a_64

__all__ = [
    "AdaThermoLBF",
    "LearnedOracle",
    "_CountingBloom",
    "_BitBloom",
    "_FreqSketch",
    "_splitmix64",
    "_bloom_fpr",
    "_key_hash",
]

# 底层哈希与误判率公式

def _splitmix64(x: int) -> int:
    """splitmix64 混合 —— 为双哈希方案提供第二条独立伪随机序列。"""
    x = (x + 0x9E3779B97F4A7C15) & 0xFFFFFFFFFFFFFFFF
    x = ((x ^ (x >> 30)) * 0xBF58476D1CE4E5B9) & 0xFFFFFFFFFFFFFFFF
    x = ((x ^ (x >> 27)) * 0x94D049BB133111EB) & 0xFFFFFFFFFFFFFFFF
    return x ^ (x >> 31)

def _key_hash(key) -> int:
    """bytes/str 归一化为 64-bit 键哈希。"""
    if isinstance(key, str):
        key = key.encode("utf-8")
    return _fnv1a_64(key)

def _bloom_fpr(k: int, n: int, m: int) -> float:
    """标准布隆误判率 (1 - e^{-kn/m})^k; n 或 m 非正时返回 0。

    k: 哈希数, n: 已插入条目数, m: 格子数 (位布隆为 bit 数,
    计数布隆为计数器格数)。FPR 仅由格子负载比 n/m 确定。
    """
    if m <= 0 or k <= 0 or n <= 0:
        return 0.0
    return (1.0 - math.exp(-k * n / m)) ** k

# _FreqSketch —— Count-Min Sketch 频率估计 (温度度量来源)

class _FreqSketch:
    """Count-Min Sketch 点查询频率估计 —— 上界估计, 不低估。

    d=4 行 × w=1024 列 → 约 4KB; 全局计数超阈值后减半,
    避免旧频率永久压制新条目 (TinyLFU reset 思想)。
    温度定义: 每次 insert/query/touch 使对应键计数 +1。
    """

    def __init__(self, d: int = 4, w: int = 1024, seed: int = 0x5bd1):
        self.d = d
        self.w = w
        self._seed = seed
        self._rows = [bytearray(w * 8) for _ in range(d)]
        self._total = 0
        self._reset = w * d * 32

    def touch(self, kh: int, delta: int = 1):
        base = (kh ^ self._seed) & (self.w - 1)
        for r in range(self.d):
            col = (base + r * 0x9E3779B97F4A7C15) % self.w
            off = col * 8
            row = self._rows[r]
            cur = int.from_bytes(row[off:off + 8], "little")
            cur = min(cur + delta, 0xFFFFFFFFFFFF)
            row[off:off + 8] = cur.to_bytes(8, "little")
        self._total += delta
        if self._total > self._reset:
            self._halve()

    def estimate(self, kh: int) -> int:
        base = (kh ^ self._seed) & (self.w - 1)
        lo = 0xFFFFFFFFFFFF
        for r in range(self.d):
            col = (base + r * 0x9E3779B97F4A7C15) % self.w
            off = col * 8
            v = int.from_bytes(self._rows[r][off:off + 8], "little")
            if v < lo:
                lo = v
        return lo

    def _halve(self):
        for r in range(self.d):
            row = self._rows[r]
            for i in range(0, len(row), 8):
                v = int.from_bytes(row[i:i + 8], "little")
                row[i:i + 8] = (v >> 1).to_bytes(8, "little")
        self._total >>= 1

# CountingBloom —— 可删除计数布隆 (冷桶底层表示)

class _CountingBloom:
    """计数布隆 —— 4-bit 半字节计数器, 支持删除。

    add 仅在键首次出现时由上层调用一次, 故每次 delete 恰好抵消一次 add,
    不存在计数残留。计数器饱和于 15 (去重场景下同键重复 insert 被上层
    拦截, 不会触发饱和)。
    """

    def __init__(self, cells: int, k: int, seed: int):
        self.m = max(cells, 16)
        self.k = max(k, 1)
        self._seed = seed
        self._data = bytearray((self.m + 1) // 2)  # 两格共享一个字节
        self.n = 0

    def _get(self, i: int) -> int:
        b = self._data[i >> 1]
        return (b >> 4) & 0xF if (i & 1) else b & 0xF

    def _set(self, i: int, v: int):
        idx = i >> 1
        if i & 1:
            self._data[idx] = (self._data[idx] & 0x0F) | ((v & 0xF) << 4)
        else:
            self._data[idx] = (self._data[idx] & 0xF0) | (v & 0xF)

    def _pos(self, kh: int):
        h1 = _splitmix64(kh ^ self._seed)
        h2 = _splitmix64(h1) | 1
        for i in range(self.k):
            yield (h1 + i * h2) % self.m

    def add(self, kh: int):
        for p in self._pos(kh):
            v = self._get(p)
            if v < 15:
                self._set(p, v + 1)
        self.n += 1

    def contains(self, kh: int) -> bool:
        for p in self._pos(kh):
            if self._get(p) == 0:
                return False
        return True

    def delete(self, kh: int) -> bool:
        if not self.contains(kh):
            return False
        for p in self._pos(kh):
            v = self._get(p)
            if v > 0:
                self._set(p, v - 1)
        self.n = max(0, self.n - 1)
        return True

    def fpr(self) -> float:
        return _bloom_fpr(self.k, self.n, self.m)

# BitBloom —— 紧凑位布隆 (热桶底层表示)

class _BitBloom:
    """紧凑位布隆 —— 每格 1 bit。

    热键稳定存在、禁止删除; 每 bit 提供一个格子, 相对计数布隆
    同等内存下多 8 倍格子, 误判率显著更低 —— 体现"热键用更紧凑表示"
    的内存分配思想 。
    """

    def __init__(self, m_bits: int, k: int, seed: int):
        self.m = max(m_bits, 16)
        self.k = max(k, 1)
        self._seed = seed
        self._bits = bytearray((self.m + 7) // 8)
        self.n = 0

    def _pos(self, kh: int):
        h1 = _splitmix64(kh ^ self._seed)
        h2 = _splitmix64(h1) | 1
        for i in range(self.k):
            yield (h1 + i * h2) % self.m

    def add(self, kh: int):
        for p in self._pos(kh):
            byte_idx, bit_idx = divmod(p, 8)
            self._bits[byte_idx] |= (1 << bit_idx)
        self.n += 1

    def contains(self, kh: int) -> bool:
        for p in self._pos(kh):
            byte_idx, bit_idx = divmod(p, 8)
            if not (self._bits[byte_idx] & (1 << bit_idx)):
                return False
        return True

    def fpr(self) -> float:
        return _bloom_fpr(self.k, self.n, self.m)

# ThermoBand —— 单一温度桶

class _ThermoBand:
    """单一温度桶 —— 一种表示 (位/计数布隆) + 可删除旗标 + 可选精确兜底。

    冷桶 (deletable=True) 挂载精确集合: filter 命中后核对兜底, 将冷数据
    的误判惩罚压至零 (DWLBF 降低误判惩罚思想的实现)。exact_cap=0 时兜底
    无上限, 保证无假阴性; 有界 cap 下兜底退化为纯正向缓存。
    """

    def __init__(self, cells: int, k: int, seed: int, deletable: bool,
                 exact_cap: int = 0):
        self.deletable = deletable
        self.exact_cap = exact_cap
        if deletable:
            self.filter = _CountingBloom(cells, k, seed)
            self.exact: Optional[set] = set()
        else:
            self.filter = _BitBloom(cells, k, seed)
            self.exact = None

    def _exact_room(self) -> bool:
        return self.exact_cap == 0 or len(self.exact) < self.exact_cap

    def add(self, kh: int):
        self.filter.add(kh)
        if self.exact is not None and self._exact_room():
            self.exact.add(kh)

    def contains(self, kh: int) -> bool:
        if not self.filter.contains(kh):
            return False
        if self.exact is not None and self.exact_cap == 0:
            return kh in self.exact  # 精确兜底: 消除冷桶误判
        return True  # 有界 cap 或热桶: 标准 FPR 语义

    def delete(self, kh: int) -> bool:
        if not self.deletable:
            return False  # 热桶锁定: 拒绝删除
        if self.exact is not None:
            if kh not in self.exact:
                return False  # 兜底判定非成员, 不触碰共享计数器
            self.exact.discard(kh)
        return self.filter.delete(kh)

    def fpr_est(self) -> float:
        if self.exact is not None and self.exact_cap == 0:
            return 0.0
        return self.filter.fpr()

# LearnedOracle —— 轻量模型 (无第三方 ML 依赖)

class LearnedOracle:
    """轻量模型 —— 频率 + 稳定哈希特征双信号集成。

    score(kh, freq) = 0.5·tanh(温度项) + 0.5·(稳定哈希特征)。
    温度项源于访问频率, 哈希项源于键本身 —— 对应 ICML 2025 的
    "双 oracle 优于单 oracle" (Ensemble Learned Bloom Filters)。
    train() 从观测 log(1+freq) 分布推理分位数阈值, 作为桶路由边界;
    无训练数据时退化为对数标尺的粗路由。
    """

    def __init__(self, num_bands: int, alpha: float = 1.0, seed: int = 0x51ab):
        self.num_bands = max(1, num_bands)
        self.alpha = alpha
        self._seed = seed
        self._thresholds: List[float] = []
        self._vmin = 0.0
        self._vmax = 1.0

    def score(self, kh: int, freq: int) -> float:
        temp = 0.0
        if freq > 0:
            temp = math.tanh(self.alpha * math.log1p(freq) / max(1.0, self._vmax))
        h1 = _splitmix64(kh ^ self._seed)
        static = (h1 >> 11) / (1 << 53)  # [0,1) 稳定哈希特征
        return 0.5 * temp + 0.5 * static

    def train(self, log_freqs: Sequence[float]):
        """从观测 log(1+freq) 分布推理等频分位数阈值。"""
        if len(log_freqs) < self.num_bands:
            return
        vals = sorted(log_freqs)
        self._vmin = vals[0]
        self._vmax = max(1e-9, vals[-1])
        self._thresholds = []
        for g in range(1, self.num_bands):
            idx = min(len(vals) - 1, int(g * len(vals) / self.num_bands))
            self._thresholds.append(vals[idx])

    def band_for(self, kh: int, freq: int) -> int:
        if freq <= 0:
            return self.num_bands - 1  # 无访问: 最冷带
        v = math.log1p(freq)
        if not self._thresholds:
            # 未训练: 对数标尺粗路由 (freq 越高带越热)
            step = int(v / 0.6931)
            return max(0, self.num_bands - 1 - min(step, self.num_bands - 1))
        idx = bisect.bisect_right(self._thresholds, v)
        return max(0, self.num_bands - 1 - idx)

# AdaThermoLBF —— 核心数据结构

class AdaThermoLBF:
    """自适应学习型布隆过滤器 + 数据温度加权删除。

    参数:
      capacity: 名义键容量, 用于推导默认总内存与对抗饱和份额。
      target_fpr: 目标整体误判率 (内存推导的锚点)。
      num_bands: 温度带数量 (桶数量)。
      weight_mode: "dwlbf"(热带优先分配) | "plbf"(冷带优先分配)。
      alpha: 分配权重递减基 (越小分配越向优先带集中)。
      deletable_ratio: 最冷带中允许删除的比例。
      max_tracked: 频率字典上限; 0 表示无上限 (推荐, 保证计数语义)。
      exact_cap: 每个冷桶精确兜底集合容量; 0 表示无上限 (消除冷桶误判)。
      rebalance_interval: 两次重平衡之间的插入次数; 0 表示自动推导。
      heat_on_query: 查询是否计为访问 (缓存场景 True, 去重场景 False)。

    接口: add / contains / delete / touch / frequency / __len__ 与
    标准布隆一致; 自适应接口: rebalance / adjust_capacity /
    set_target_fpr / set_num_bands; 对抗接口: worst_case_fpr_estimate /
    resilience_escalate。
    """

    def __init__(self, capacity: int = 100000, target_fpr: float = 0.01,
                 num_bands: int = 4, weight_mode: str = "dwlbf",
                 alpha: float = 0.7, seed: int = 0x51ab,
                 deletable_ratio: float = 0.5, max_tracked: int = 0,
                 exact_cap: int = 0, rebalance_interval: int = 0,
                 heat_on_query: bool = True):
        self._capacity = max(int(capacity), 1)
        self._target_fpr = target_fpr
        self._num_bands = max(1, int(num_bands))
        self._weight_mode = weight_mode
        self._alpha = alpha
        self._seed = seed
        self._deletable_ratio = max(0.0, min(1.0, deletable_ratio))
        self._max_tracked = max(int(max_tracked), 0)
        self._exact_cap = max(int(exact_cap), 0)
        self._heat_on_query = heat_on_query
        self._force_deletable: set = set()
        self._total_mem = self._derive_total_mem(self._capacity, target_fpr)
        self._oracle = LearnedOracle(self._num_bands, seed=seed)
        self._sketch = _FreqSketch(seed=seed)
        self._freq: Dict[int, Tuple[int, int]] = {}  # kh -> (count, band)
        self._members = 0
        self._insert_count = 0
        self._escalations = 0
        self._rebalance_interval = rebalance_interval or max(
            64, self._capacity // 16)
        self._specs: List[Dict] = []
        self._bands: List[_ThermoBand] = []
        self.rebuild()

# 内存推导与分配

    @staticmethod
    def _derive_total_mem(capacity: int, fpr: float) -> int:
        """标准位布隆内存公式 m = -n·ln(p) / (ln2)^2 导出总内存 (bit)。"""
        if not 0.0 < fpr < 1.0:
            raise ValueError("target_fpr must be in (0, 1)")
        return max(64, int(-capacity * math.log(fpr) / (0.6931 * 0.6931)))

    def _allocate(self, total_mem: int,
                  counts: Sequence[int]) -> List[Dict]:
        """按温度分布推导每桶 (cells, k, deletable)。

        weight_mode=dwlbf 时带 0 (最热) 权重最大 (热带低 FPR);
        plbf 时带 N-1 (最冷) 权重最大 (冷带低 FPR)。冷桶用计数布隆,
        cells = mem//4 (4-bit 计数器), 热桶位布隆 cells = mem。
        k = ln2·cells/n 取整, 表示复杂度随负载自适应变化。
        """
        weights = []
        for g in range(self._num_bands):
            if self._weight_mode == "plbf":
                # 冷带 (g=N-1) 优先: 常见非成员查询路径获得更多内存
                w = self._alpha ** (self._num_bands - 1 - g)
            else:  # dwlbf
                # 热带 (g=0) 优先: 热键稳定性换取低 FPR
                w = self._alpha ** g
            weights.append(max(w, 1e-6))
        denom = sum(weights)
        # cutoff: 从此带起可删除; ratio=1.0 → cutoff=0 (全部可删),
        # ratio=0.0 → cutoff=N (全部锁定)
        cutoff = int(self._num_bands * (1.0 - self._deletable_ratio))
        cap_share = max(1, self._capacity // self._num_bands)
        specs = []
        for g in range(self._num_bands):
            mem = max(64, int(total_mem * weights[g] / denom))
            deletable = (g in self._force_deletable) or (g >= cutoff)
            cells = mem if not deletable else max(16, mem // 4)
            # k 推导用 max(当前计数, 容量份额) 做下界, 避免早期低负载
            # 时 k 过大、后期负载增长后误判率失控
            n_g = max(cap_share, counts[g]) if counts else cap_share
            k = max(1, min(12, int(0.6931 * cells / n_g)))
            specs.append({"mem": mem, "cells": cells, "k": k,
                          "deletable": deletable})
        return specs

# 全量重建 / 重平衡

    def rebuild(self):
        """全量重建: 重训 oracle 阈值 → 重路由 → 重分配 → 重插。

        O(n), 由 rebalance_interval 控制频度; 保证路由状态与存储一致,
        消除跨重平衡的温度漂移导致的假阴性。
        """
        if self._freq:
            logf = [math.log1p(c) for c, _b in self._freq.values()]
            self._oracle.train(logf)
        counts = [0] * self._num_bands
        for kh, (c, _b) in self._freq.items():
            g = self._oracle.band_for(kh, c)
            counts[g] += 1
        specs = self._allocate(self._total_mem, counts)
        self._specs = specs
        self._bands = [
            _ThermoBand(s["cells"], s["k"], self._seed + g * 0x9E37,
                        s["deletable"], self._exact_cap)
            for g, s in enumerate(specs)
        ]
        for kh, (c, _b) in self._freq.items():
            g = self._oracle.band_for(kh, c)
            self._freq[kh] = (c, g)
            self._bands[g].add(kh)

    def rebalance(self):
        # 间隔为构造时确定的固定节奏; 不在此处放大, 否则 O(n) 重建频度
        # 会随插入规模骤降, 导致 k 长期陈旧 (参考 DWLBF 周期刷新策略)。
        self.rebuild()

# 成员操作接口

    def add(self, key: bytes) -> bool:
        """插入键; 返回 True 表示新成员 (此前不存在)。"""
        kh = _key_hash(key)
        self._insert_count += 1
        hit = self._freq.get(kh)
        if hit is not None:
            c, band = hit
            self._freq[kh] = (c + 1, band)  # 温度上升, 重平衡时再迁移
            self._sketch.touch(kh)
            return False
        if self._max_tracked and len(self._freq) >= self._max_tracked:
            # 超出跟踪上限: 仅入过滤器, 频率走 sketch (best-effort)
            band = self._oracle.band_for(kh, self._sketch.estimate(kh))
            self._bands[band].add(kh)
            self._members += 1
            self._sketch.touch(kh)
            return True
        band = self._oracle.band_for(kh, 1)
        self._freq[kh] = (1, band)
        self._bands[band].add(kh)
        self._members += 1
        self._sketch.touch(kh)
        if self._insert_count % self._rebalance_interval == 0:
            self.rebalance()
        return True

    def contains(self, key: bytes, heat: Optional[bool] = None) -> bool:
        """检查键是否可能存在; 成员无假阴性 (默认全跟踪 + 冷桶兜底)。"""
        kh = _key_hash(key)
        hit = self._freq.get(kh)
        if hit is not None:
            _c, band = hit
            present = self._bands[band].contains(kh)
        else:
            freq = self._sketch.estimate(kh)
            band = self._oracle.band_for(kh, freq)
            present = self._bands[band].contains(kh)
        if self._heat_on_query if heat is None else heat:
            self._sketch.touch(kh)
            if hit is not None:
                self._freq[kh] = (hit[0] + 1, hit[1])
        return present

    def delete(self, key: bytes) -> bool:
        """删除键; 冷桶可删, 热桶拒绝 (返回 False)。"""
        kh = _key_hash(key)
        hit = self._freq.get(kh)
        if hit is not None:
            _c, band = hit
            ok = self._bands[band].delete(kh)
            if ok:
                del self._freq[kh]
                self._members = max(0, self._members - 1)
            return ok
        freq = self._sketch.estimate(kh)
        band = self._oracle.band_for(kh, freq)
        return self._bands[band].delete(kh)

    def touch(self, key: bytes):
        """手动报告一次访问 —— 提升数据温度评分。"""
        kh = _key_hash(key)
        hit = self._freq.get(kh)
        if hit is not None:
            self._freq[kh] = (hit[0] + 1, hit[1])
        self._sketch.touch(kh)

    def frequency(self, key: bytes) -> int:
        """当前估计访问频率 (数据温度的直接代理)。"""
        kh = _key_hash(key)
        hit = self._freq.get(kh)
        if hit is not None:
            return hit[0]
        return self._sketch.estimate(kh)

    def __len__(self) -> int:
        return self._members

# 自适应参数调整

    def adjust_capacity(self, new_total_mem: int):
        """按新总内存预算重分配并重建。"""
        new_total_mem = int(new_total_mem)
        if new_total_mem < self._num_bands * 64:
            raise ValueError("total memory budget too small")
        self._total_mem = new_total_mem
        self.rebuild()

    def set_target_fpr(self, fpr: float):
        """按新目标误判率重推导总内存并重建。"""
        self._target_fpr = fpr
        self._total_mem = self._derive_total_mem(self._capacity, fpr)
        self.rebuild()

    def set_num_bands(self, n: int):
        """调整温度带数量并重建。"""
        self._num_bands = max(1, int(n))
        self._oracle = LearnedOracle(self._num_bands, seed=self._seed)
        self._force_deletable = {g for g in self._force_deletable
                                 if g < self._num_bands}
        self.rebuild()

    def clear(self):
        """清空全部状态 (保留参数配置)。"""
        self._freq.clear()
        self._members = 0
        self._insert_count = 0
        self._escalations = 0
        self._sketch = _FreqSketch(seed=self._seed)
        self._oracle = LearnedOracle(self._num_bands, seed=self._seed)
        self.rebuild()

# 对抗鲁棒性接口

    def worst_case_fpr_estimate(self) -> Dict:
        """最坏情况误判上界估计 (arXiv:2409.06556)。

        对抗者可向任意带饱和注入: 以 n_sat = max(当前 n, 容量份额)
        代入 FPR 公式, 取各带最大值为上界。effective_worst_fpr 计入
        精确兜底 (冷桶为 0), 是面对攻击者的真实误判率。
        """
        per_band: List[float] = []
        eff: List[float] = []
        worst = 0.0
        eff_worst = 0.0
        worst_g = -1
        cap_share = max(1, self._capacity // max(1, self._num_bands))
        for g, b in enumerate(self._bands):
            n_sat = max(b.filter.n, cap_share)
            f = _bloom_fpr(b.filter.k, n_sat, b.filter.m)
            e = 0.0 if (b.exact is not None and b.exact_cap == 0) else f
            per_band.append(round(f, 8))
            eff.append(round(e, 8))
            if f > worst:
                worst = f
                worst_g = g
            eff_worst = max(eff_worst, e)
        return {
            "worst_band_fpr": round(worst, 8),
            "worst_band": worst_g,
            "effective_worst_fpr": round(eff_worst, 8),
            "per_band": per_band,
            "effective_per_band": eff,
            "budget": self._target_fpr,
            "within_budget": eff_worst <= self._target_fpr,
        }

    def resilience_escalate(self, budget: Optional[float] = None) -> Dict:
        """对抗升级: 将有效最坏误判压入预算。

        措施: (1) 将对抗目标带强制转为可删除 + 精确兜底 (兜底降级);
        (2) 总内存上调 20%。多次调用可逐级收敛。
        """
        bgt = self._target_fpr if budget is None else budget
        w = self.worst_case_fpr_estimate()
        if w["within_budget"] and w["effective_worst_fpr"] <= bgt:
            return {"escalated": False, "escalations": self._escalations, **w}
        worst_g = w["worst_band"]
        if worst_g >= 0 and not self._bands[worst_g].deletable:
            self._force_deletable.add(worst_g)
        self._total_mem = int(self._total_mem * 1.2)
        self._escalations += 1
        self.rebuild()
        w2 = self.worst_case_fpr_estimate()
        return {"escalated": True, "escalations": self._escalations, **w2}

# 统计摘要

    def estimated_fpr(self) -> float:
        """整体误判率 —— 按各带成员数加权 (计入冷桶精确兜底)。"""
        total = sum(b.filter.n for b in self._bands)
        if total == 0:
            return 0.0
        wsum = sum(b.filter.n * b.fpr_est() for b in self._bands)
        return wsum / total

    def stats(self) -> Dict:
        bands = []
        for g, b in enumerate(self._bands):
            bands.append({
                "band": g,
                "deletable": b.deletable,
                "type": "counting" if b.deletable else "bit",
                "cells": b.filter.m,
                "k": b.filter.k,
                "n": b.filter.n,
                "load": round(b.filter.n / max(1, b.filter.m), 4),
                "fpr_est": round(b.fpr_est(), 6),
            })
        return {
            "num_bands": self._num_bands,
            "total_mem_bits": self._total_mem,
            "items": self._members,
            "target_fpr": self._target_fpr,
            "estimated_fpr": round(self.estimated_fpr(), 6),
            "weight_mode": self._weight_mode,
            "thresholds": [round(t, 3) for t in self._oracle._thresholds],
            "bands": bands,
            "rebalance_interval": self._rebalance_interval,
            "insert_count": self._insert_count,
            "escalations": self._escalations,
            **self.worst_case_fpr_estimate(),
        }
