# 在线字典压缩: Count-Min Sketch追踪n-gram频率+自适应字典重建+双级编码
# Stage-1: 字典替换(高频模式→短ID), Stage-2: zstd熵编码.
# 区别于 zstd--train(离线), FSST(固定符号表), brotli(文本共享字典).
# 适用: CI/CD构建产物, 固件归档, exploit样本库.

import struct
import time
from collections import deque
from typing import Dict, List, Optional, Set, Tuple

from .compression import compress as _compress, decompress as _decompress

# 在线频率追踪器 (基于 Count-Min Sketch)

class _OnlineFreqTracker:
    """在线 n-gram 频率追踪, CMS + Top-K 最小堆近似."""

    def __init__(self, ngram_sizes: Tuple[int, ...] = (4, 8, 12),
                 top_k: int = 256, cms_width: int = 4096, cms_depth: int = 4):
        self.ngram_sizes = ngram_sizes
        self.top_k = top_k
        self._width = cms_width
        self._depth = cms_depth
        # CMS: d 行 × w 列的 64-bit 计数器
        self._cms = [bytearray(cms_width * 8) for _ in range(cms_depth)]
        self._total = 0
        # Top-K 追踪: 维护 (count, pattern) 的最小堆近似
        self._freq: Dict[bytes, int] = {}
        self._min_top = 0  # 当前 Top-K 集合中的最小频率
        self._decay_counter = 0

    def feed(self, data: bytes):
        """从数据流中提取 n-gram 并更新频率."""
        for n in self.ngram_sizes:
            if len(data) < n:
                continue
            step = max(1, n // 2)  # 重叠采样, 确保覆盖率
            for i in range(0, len(data) - n + 1, step):
                pattern = data[i:i + n]
                self._inc(pattern)

        self._decay_counter += 1
        # 每 10000 条执行一次衰减, 让旧低频模式自然淘汰
        if self._decay_counter > 10000:
            self._apply_decay()
            self._decay_counter = 0

    def _inc(self, pattern: bytes):
        """CMS 增量 + Top-K 更新."""
        h = self._cms_hash(pattern)
        for r in range(self._depth):
            col = ((h >> (r * 16)) % self._width)
            off = col * 8
            val = int.from_bytes(self._cms[r][off:off + 8], 'little')
            val = min(val + 1, 0xFFFFFFFFFFFF)
            self._cms[r][off:off + 8] = val.to_bytes(8, 'little')
        self._total += 1

        # Top-K 维护
        freq = self.estimate(pattern)
        if freq < self._min_top and len(self._freq) >= self.top_k:
            return
        self._freq[pattern] = freq
        if len(self._freq) > self.top_k * 1.5:
            self._prune_topk()

    def estimate(self, pattern: bytes) -> int:
        """CMS 频率估计 (上界)."""
        h = self._cms_hash(pattern)
        lo = 0xFFFFFFFFFFFF
        for r in range(self._depth):
            col = ((h >> (r * 16)) % self._width)
            off = col * 8
            v = int.from_bytes(self._cms[r][off:off + 8], 'little')
            if v < lo:
                lo = v
        return lo

    def top_patterns(self, k: int = None) -> List[Tuple[bytes, int]]:
        """返回频率最高的 k 个模式."""
        k = k or self.top_k
        if not self._freq:
            return []
        # 重新评估当前存储的所有候选
        refreshed = {p: self.estimate(p) for p in self._freq}
        sorted_items = sorted(refreshed.items(), key=lambda x: x[1], reverse=True)
        return sorted_items[:k]

    def _prune_topk(self):
        """裁剪 Top-K 集合至 top_k 大小."""
        if len(self._freq) <= self.top_k:
            return
        refreshed = [(self.estimate(p), p) for p in self._freq]
        refreshed.sort(reverse=True)
        self._freq = {p: c for c, p in refreshed[:self.top_k]}
        self._min_top = refreshed[self.top_k - 1][0] if len(refreshed) >= self.top_k else 0

    def _apply_decay(self):
        """全局衰减: 将所有频率减半, 模拟指数衰减."""
        for r in range(self._depth):
            row = self._cms[r]
            for i in range(0, len(row), 8):
                v = int.from_bytes(row[i:i + 8], 'little')
                row[i:i + 8] = (v >> 1).to_bytes(8, 'little')
        self._total >>= 1

    @staticmethod
    def _cms_hash(pattern: bytes) -> int:
        """64-bit 哈希 (Murmur-inspired finalizer)."""
        h = len(pattern) * 0x9e3779b9
        for i in range(0, len(pattern), 4):
            chunk = pattern[i:i + 4]
            w = int.from_bytes(chunk.ljust(4, b'\x00'), 'little')
            w = (w * 0xcc9e2d51) & 0xFFFFFFFF
            w = ((w << 15) | (w >> 17)) & 0xFFFFFFFF
            w = (w * 0x1b873593) & 0xFFFFFFFF
            h ^= w
            h = ((h << 13) | (h >> 19)) & 0xFFFFFFFF
            h = (h * 5 + 0xe6546b64) & 0xFFFFFFFF
        h ^= h >> 16
        h = (h * 0x85ebca6b) & 0xFFFFFFFF
        h ^= h >> 13
        return (h & 0xFFFFFFFF) | ((h * 0xc2b2ae35) << 32)

# 在线字典压缩器

class OnlineDictCompressor:
    """在线字典学习+双级压缩: stage-1 字典替换(ID编码), stage-2 zstd.
    用法: odc=OnlineDictCompressor(); c=odc.compress(data); r=odc.decompress(c)."""

    DICT_MAGIC = b'BMDC'  # BinMind Dict Compress v1

    def __init__(self, ngram_sizes: Tuple[int, ...] = (4, 8, 12),
                 dict_capacity: int = 256,
                 rebuild_interval: int = 50000,
                 jaccard_threshold: float = 0.3):
        self._tracker = _OnlineFreqTracker(ngram_sizes=ngram_sizes,
                                            top_k=dict_capacity * 2)
        self._dict_capacity = dict_capacity
        self._rebuild_interval = rebuild_interval
        self._jaccard_threshold = jaccard_threshold

        self._dictionary: Dict[bytes, int] = {}     # pattern → id
        self._reverse_dict: Dict[int, bytes] = {}    # id → pattern
        self._dict_version = 0
        self._items_processed = 0
        self._last_snapshot: Set[bytes] = set()
        self._dict_bytes: bytes = b''               # 序列化的字典

    def compress(self, data: bytes) -> bytes:
        """压缩: stage-1 字典替换 → stage-2 zstd 编码."""
        self._tracker.feed(data)
        self._items_processed += 1

        # 定期检查是否需要重建字典
        if self._items_processed % self._rebuild_interval == 0:
            self._maybe_rebuild()

        # Stage 1: 字典替换
        if self._dictionary:
            replaced = self._apply_dict_encode(data)
        else:
            replaced = data

        # Stage 2: zstd 压缩
        compressed, codec = _compress(replaced, "zstd", level=3)

        # 头部: [4B magic][4B dict_version][4B replaced_size]
        hdr = struct.pack('<4sII', self.DICT_MAGIC, self._dict_version,
                         len(replaced))
        return hdr + compressed

    def decompress(self, data: bytes) -> bytes:
        """解压: stage-2 zstd 解码 → stage-1 字典还原."""
        if len(data) < 12:
            return data

        magic = data[:4]
        if magic != self.DICT_MAGIC:
            # 回退: 当旧格式数据传入时尝试原始 zstd 解压
            return _decompress(data, "zstd")

        dict_ver = struct.unpack('<I', data[4:8])[0]
        replaced_size = struct.unpack('<I', data[8:12])[0]

        # Stage 2 解压
        raw = _decompress(data[12:], "zstd")

        # Stage 1: 字典还原
        if self._reverse_dict and dict_ver == self._dict_version:
            return self._apply_dict_decode(raw, replaced_size)
        return raw

    def rebuild_dictionary(self) -> int:
        """手动重建字典: 返回新字典的条目数."""
        patterns = self._tracker.top_patterns(self._dict_capacity)
        if not patterns:
            return 0

        self._dictionary = {}
        self._reverse_dict = {}
        for pid, (pattern, freq) in enumerate(patterns):
            if len(pattern) < 3:
                continue  # 过短的模式无压缩价值 (ID 开销 > 收益)
            self._dictionary[pattern] = pid
            self._reverse_dict[pid] = pattern

        self._dict_version += 1
        self._serialize_dict()
        return len(self._dictionary)

    def _maybe_rebuild(self):
        """检测高频模式变化, 变化显著时触发重建."""
        current = self._tracker.top_patterns(50)
        current_set = {p for p, _ in current}
        if not self._last_snapshot:
            self._last_snapshot = current_set
            return
        if not current_set or not self._last_snapshot:
            return

        # Jaccard 相似度
        intersection = len(current_set & self._last_snapshot)
        union = len(current_set | self._last_snapshot)
        jaccard = intersection / max(union, 1)

        if jaccard < self._jaccard_threshold:
            self.rebuild_dictionary()

        self._last_snapshot = current_set

    def _apply_dict_encode(self, data: bytes) -> bytes:
        """贪心匹配字典模式, 替换为 ID 编码.

        编码: [0xFF][2B pattern_id] 表示字典替换,
              其他字节 [原值] 表示直接透传.
        """
        if not self._dictionary:
            return data

        result = bytearray()
        max_pat_len = max((len(p) for p in self._dictionary), default=0)
        pos = 0
        n = len(data)

        while pos < n:
            best_len, best_id = 0, -1
            # 从当前位置查找最长字典匹配
            for pat_len in range(min(max_pat_len, n - pos), 2, -1):
                chunk = data[pos:pos + pat_len]
                pid = self._dictionary.get(chunk)
                if pid is not None:
                    best_len, best_id = pat_len, pid
                    break

            if best_len >= 3 and best_id >= 0:
                # 字典替换: flag + 2B ID
                result.append(0xFF)
                result.extend(struct.pack('<H', best_id))
                pos += best_len
            else:
                result.append(data[pos])
                pos += 1

        return bytes(result)

    def _apply_dict_decode(self, data: bytes, _expected_size: int) -> bytes:
        if not self._reverse_dict:
            return data
        result, pos, n = bytearray(), 0, len(data)
        while pos < n:
            b = data[pos]
            if b == 0xFF and pos + 2 < n:
                pid = struct.unpack('<H', data[pos + 1:pos + 3])[0]
                pattern = self._reverse_dict.get(pid)
                if pattern is not None:
                    result.extend(pattern); pos += 3; continue
            result.append(b); pos += 1
        return bytes(result)

    def _serialize_dict(self):
        buf = bytearray()
        buf.extend(struct.pack('<4sIH', self.DICT_MAGIC, self._dict_version, len(self._reverse_dict)))
        for pid, pattern in sorted(self._reverse_dict.items()):
            buf.append(len(pattern)); buf.extend(pattern); buf.extend(struct.pack('<H', pid))
        self._dict_bytes = bytes(buf)

    @property
    def dict_size(self) -> int: return len(self._dictionary)

    @property
    def stats(self) -> dict:
        top = self._tracker.top_patterns(10)
        return {"dict_entries":len(self._dictionary),"dict_version":self._dict_version,
                "items_processed":self._items_processed,
                "top_patterns":[{"pattern_hex":p[:8].hex(),"freq":f} for p,f in top],
                "tracked_candidates":len(self._tracker._freq)}

__all__ = ["OnlineDictCompressor"]
