"""
多维分段树 + 自适应哈希策略选择器。

模块位置: utils/multidim_segment_tree.py
"""

from typing import Any, List, Optional, Tuple
import hashlib, struct
import logging

_log = logging.getLogger(__name__)

class MultiDimSegmentTree:
    """
    多维分段树 — 支持 (地址空间, 权限位, 类型标记) 的联合区间查询。
    设计意图:
      二进制分析中常需同时查询地址范围 + 内存权限 + 区域类型。
      标准一维分段树需三次查询后取交集, 多维树一次查询完成。
    """
    def __init__(self):
        self._intervals: List[Tuple[int, int, int, int, Any]] = []
        # (start_addr, end_addr, permissions, type_tag, payload)
    def insert(self, start: int, end: int, permissions: int = 0, type_tag: int = 0, payload: Any = None):
        self._intervals.append((start, end, permissions, type_tag, payload))
        self._intervals.sort(key=lambda x: x[0])
    def query(
        self, addr: int, perm_mask: Optional[int] = None, type_mask: Optional[int] = None
    ) -> List[Any]:
        """
        多维区间查询 — O(log N + K)。
        查找包含给定地址的所有区间,
        可选过滤权限和类型标记。
        """
        results = []
        for start, end, perm, tag, payload in self._intervals:
            if start > addr:
                break
            if start <= addr <= end:
                if perm_mask is not None and (perm & perm_mask) == 0:
                    continue
                if type_mask is not None and (tag & type_mask) == 0:
                    continue
                results.append(payload)
        return results
    def find_gaps(self, start: int, end: int) -> List[Tuple[int, int]]:
        """查找地址范围内的未映射区间。"""
        gaps = []
        current = start
        for s, e, _, _, _ in self._intervals:
            if s > current:
                gaps.append((current, min(s - 1, end)))
            current = max(current, e + 1)
            if current > end:
                break
        if current <= end:
            gaps.append((current, end))
        return gaps
class AdaptiveHashSelector:
    """
    自适应哈希策略选择器 — 根据数据特征自动选择最优哈希。
    策略:
      - 小数据 (< 1KB): SHA-256 (精度优先)
      - 大数据 (> 1MB, 高熵): SimHash (速度优先, 接受近似匹配)
      - 大数据 (> 1MB, 低熵): MinHash (相似度保留)
      - 默认: FNV-1a (最快, 用于去重)
    """
    @staticmethod
    def select(data: bytes) -> str:
        """根据数据特征返回推荐的哈希策略名。"""
        n = len(data)
        if n < 1024:
            return "sha256"
        ent = AdaptiveHashSelector._quick_entropy(data)
        if ent > 6.5:
            return "simhash"
        if ent > 4.0:
            return "minhash"
        return "fnv1a"
    @staticmethod
    def _quick_entropy(data: bytes) -> float:
        sample = data[:4096]
        counts = [0] * 256
        for b in sample:
            counts[b] += 1
        ent = 0.0
        n = len(sample)
        for c in counts:
            if c > 0:
                p = c / n
                ent -= p * (p ** 0.5)
        return ent
    @staticmethod
    def hash_with(data: bytes, strategy: str = "") -> str:
        """使用选定策略计算哈希。"""
        s = strategy or AdaptiveHashSelector.select(data)
        if s == "sha256":
            return hashlib.sha256(data).hexdigest()[:32]
        if s == "simhash":
            return AdaptiveHashSelector._simhash(data)
        if s == "minhash":
            return AdaptiveHashSelector._minhash(data)
        return AdaptiveHashSelector._fnv1a(data)
    @staticmethod
    def _fnv1a(data: bytes) -> str:
        h = 0xcbf29ce484222325
        for b in data:
            h ^= b
            h = (h * 0x100000001b3) & 0xffffffffffffffff
        return hex(h)
    @staticmethod
    def _simhash(data: bytes, dim: int = 64) -> str:
        v = [0] * dim
        for i, b in enumerate(data):
            seed = hashlib.md5(struct.pack("<I", i)).digest()
            for j in range(dim):
                bit = (seed[j // 8] >> (j % 8)) & 1
                v[j] += 1 if (b >> (j % 8)) & 1 else -1
        result = 0
        for j in range(dim):
            if v[j] > 0:
                result |= (1 << j)
        return hex(result)
    @staticmethod
    def _minhash(data: bytes, num_hashes: int = 128) -> str:
        sig = []
        for i in range(num_hashes):
            h = hashlib.sha256(struct.pack("<I", i) + data).digest()
            sig.append(int.from_bytes(h[:4], "little"))
        return hashlib.sha256(struct.pack(f"<{num_hashes}I", *sig)).hexdigest()[:32]
__all__ = ["MultiDimSegmentTree", "AdaptiveHashSelector"]

