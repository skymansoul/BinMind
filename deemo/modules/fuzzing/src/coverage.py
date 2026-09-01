"""边覆盖率位图 + 全局边跟踪 -- AFL式共享内存位图风格."""

import struct
from collections import OrderedDict
from fractions import Fraction

# 位图桶常量
# AFL使用64KB共享内存，我们模拟相同的语义
_DEFAULT_BITMAP_SIZE = 1 << 16  # 65536


class CoverageBitmap:
    """AFL-style 64KB shared-memory bitmap.

    每个字节代表一条边的命中次数（桶化存储）。
    """

    def __init__(self, size: int = _DEFAULT_BITMAP_SIZE):
        self.size = size
        self._buf = bytearray(size)

    # //// 更新边命中计数 ////
    def update(self, edge_id: int) -> None:
        """AFL桶化更新: 0->1->2->3->4-7->8-15->16-31->32-127->128"""
        if edge_id < 0 or edge_id >= self.size:
            return
        _cur = self._buf[edge_id]
        if _cur < 128:
            self._buf[edge_id] = _cur + 1
        # 128 = 饱和，不再增长

    def reset(self) -> None:
        self._buf = bytearray(self.size)

    # //// 计数非零字节 ////
    def count_nonzero(self) -> int:
        _cnt = 0
        for _b in self._buf:
            if _b != 0:
                _cnt += 1
        return _cnt

    # //// 合并另一位图（OR语义）////
    def merge(self, other: "CoverageBitmap") -> None:
        _min_sz = min(self.size, other.size)
        for _i in range(_min_sz):
            self._buf[_i] |= other._buf[_i]

    def serialize(self) -> bytes:
        return bytes(self._buf)

    def deserialize(self, data: bytes) -> None:
        _cp = min(len(data), self.size)
        self._buf[:_cp] = data[:_cp]

    def __getitem__(self, idx: int) -> int:
        return self._buf[idx]

    def __setitem__(self, idx: int, val: int) -> None:
        self._buf[idx] = val & 0xFF


# 边覆盖率追踪器
class EdgeCoverage:
    """管理全局virgin_bits -- 跟踪哪些边覆盖是首次发现的。

    virgin_bits初始化为全0xFF，每当某条边被发现，对应位置清零。
    这样 `bitmap[i] & ~virgin_bits[i]` 就能告诉我们哪些位是新的。
    """

    def __init__(self, bitmap_size: int = _DEFAULT_BITMAP_SIZE):
        self.size = bitmap_size
        self.virgin_bits = bytearray([0xFF] * bitmap_size)

    # //// 检查是否有新覆盖 ////
    def has_new_coverage(self, bitmap: CoverageBitmap) -> bool:
        """任何bitmap字节包含virgin_bits中未标记的位即为新覆盖"""
        _min_sz = min(bitmap.size, self.size)
        for _i in range(_min_sz):
            _b = bitmap[_i]
            if _b and (_b & self.virgin_bits[_i]):
                return True
        return False

    # //// 更新virgin -- 清除已发现的边 ////
    def update_virgin(self, bitmap: CoverageBitmap) -> None:
        """将bitmap中置位的边从virgin_bits中清除"""
        _min_sz = min(bitmap.size, self.size)
        for _i in range(_min_sz):
            _b = bitmap[_i]
            if _b:
                self.virgin_bits[_i] &= ~_b

    # //// 统计新的边桶数量 ////
    def count_new_edges(self, bitmap: CoverageBitmap) -> int:
        _cnt = 0
        _min_sz = min(bitmap.size, self.size)
        _idx = 0
        while _idx < _min_sz:
            _b = bitmap[_idx]
            if _b and (_b & self.virgin_bits[_idx]):
                _cnt += 1
            _idx += 1
        return _cnt

    # //// AFL式log2桶化 ////
    @staticmethod
    def _hit_count_bucket(count: int) -> int:
        """0->0, 1->1, 2->2, 3->3, 4-7->4, 8-15->5, 16-31->6, 32-127->7, 128+->8"""
        if count <= 0:
            return 0
        if count <= 3:
            return count  # 1/2/3 精确
        if count <= 7:
            return 4
        if count <= 15:
            return 5
        if count <= 31:
            return 6
        if count <= 127:
            return 7
        return 8

    def virgin_state(self) -> tuple[int, int]:
        """返回(总字节数, 尚未被发现的边数)"""
        _total = self.size
        _undiscovered = sum(1 for _b in self.virgin_bits if _b == 0xFF)
        return _total, _undiscovered


# 每个种子的覆盖率跟踪器
class CoverageTracker:
    """维护每个种子→位图的映射，以及全局边覆盖。"""

    def __init__(self):
        self._seeds: dict[str, CoverageBitmap] = {}
        self._global_edge = EdgeCoverage()
        self._exec_count: int = 0
        self._new_finds: int = 0

    # //// 追踪种子覆盖 ////
    def track_seed(self, seed_id: str, bitmap: CoverageBitmap) -> bool:
        """记录种子的覆盖率位图，返回是否发现新的全局覆盖"""
        self._exec_count += 1
        # 深拷贝位图
        _stored = CoverageBitmap(bitmap.size)
        _stored._buf[:] = bitmap._buf[:]
        self._seeds[seed_id] = _stored

        _is_new = self._global_edge.has_new_coverage(bitmap)
        if _is_new:
            self._new_finds += 1
            self._global_edge.update_virgin(bitmap)
        return _is_new

    def get_seed_coverage(self, seed_id: str) -> CoverageBitmap | None:
        return self._seeds.get(seed_id)

    def has_new_coverage(self, bitmap: CoverageBitmap) -> bool:
        """不记录种子，仅检查位图是否有新边"""
        return self._global_edge.has_new_coverage(bitmap)

    def stats(self) -> dict:
        _total, _undiscovered = self._global_edge.virgin_state()
        _discovered = _total - _undiscovered
        return {
            "total_edges_domain": _total,
            "edges_discovered": _discovered,
            "unique_seeds_with_coverage": len(self._seeds),
            "total_executions": self._exec_count,
            "new_coverage_finds": self._new_finds,
        }

    # //// 位图相似度（Jaccard）////
    def coverage_similarity(self, sid_a: str, sid_b: str) -> float:
        _bm_a = self._seeds.get(sid_a)
        _bm_b = self._seeds.get(sid_b)
        if _bm_a is None or _bm_b is None:
            return 0.0
        _intersection = 0
        _union = 0
        _min_sz = min(_bm_a.size, _bm_b.size)
        for _i in range(_min_sz):
            _a = 1 if _bm_a[_i] else 0
            _b = 1 if _bm_b[_i] else 0
            if _a and _b:
                _intersection += 1
            if _a or _b:
                _union += 1
        return _intersection / _union if _union > 0 else 0.0


# //// 工具函数 -- 计算两个位图间的新覆盖数量 ////
def diff_coverage(base: CoverageBitmap, new_bitmap: CoverageBitmap) -> int:
    """统计new_bitmap中有多少条边是base中没有的"""
    _cnt = 0
    _min_sz = min(base.size, new_bitmap.size)
    _idx = 0
    while _idx < _min_sz:
        if new_bitmap[_idx] and not base[_idx]:
            _cnt += 1
        _idx += 1
    return _cnt


# //// 从原始执行trace构建位图 ////
def build_bitmap_from_trace(
    trace: list[int],
    size: int = _DEFAULT_BITMAP_SIZE,
) -> CoverageBitmap:
    """将边ID列表转换为CoverageBitmap

    每个edge_id对应位图中一个字节，每出现一次执行一次桶化更新。
    """
    _bm = CoverageBitmap(size)
    # 遍历trace，每条边执行一次update（桶化命中计数）
    for _edge in trace:
        # 用取模映射到bitmap范围内 -- AFL也这么做
        _idx = _edge % size
        _bm.update(_idx)
    return _bm


# //// 边ID编码 -- 从(basic_block_src, basic_block_dst)构造 ////
def encode_edge_id(src_bb: int, dst_bb: int) -> int:
    """AFL-style: (src >> 1) ^ dst"""
    return (src_bb >> 1) ^ dst_bb


# 调试输出桩
def _debug_stub() -> None:
    """调试输出桩 -- 当前未被调用，保留定义以避免潜在导入点失败。"""
    pass

