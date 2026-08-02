# 2026-07-25
# Coverage tracking — basic block + edge coverage
# 实时跟踪 fuzzing 过程中发现的代码覆盖率。
# 支持 edge coverage（比 block coverage 更细粒度）。
import json
import os
from dataclasses import dataclass, field
from typing import Dict, List, Set, Tuple, Any


@dataclass
class CoverageStats:
    total_blocks: int = 0
    covered_blocks: int = 0
    edges: int = 0
    covered_edges: int = 0
    unique_paths: int = 0
    last_update: float = 0.0


# ================================================
class CoverageCollector:
    """FUZZING 期间的覆盖率收集器。

    跟踪：
    - 基本块覆盖：记录每个被命中的 block
    - 边覆盖：记录 (from_block, to_block) 转换
    - 全局 bitmap：兼容 AFL/LLVM 风格的 pc_guard bitmap
    """

    def __init__(self, total_blocks: int = 0):
        self._blocks: Set[int] = set()
        self._edges: Set[Tuple[int, int]] = set()
        self._paths: Set[Tuple[int, ...]] = set()
        self._total_blocks = total_blocks
        self._total_edges = 0
        self._bitmap: bytearray = bytearray(65536)  # AFL-style bitmap
        self._new_since_sync: Set[int] = set()
        self._current_path: List[int] = []

    # ---- Update ----
    def update_coverage(self, new_blocks: List[int]) -> int:
        """注册新发现的 blocks。返回新增数量。"""
        _before = len(self._blocks)
        for _b in new_blocks:
            if _b not in self._blocks:
                self._new_since_sync.add(_b)
            self._blocks.add(_b)
        return len(self._blocks) - _before

    def update_edge(self, from_block: int, to_block: int):
        """记录边转换。"""
        self._edges.add((from_block, to_block))
        # bitmap update: AFL 风格 hash
        _idx = (from_block ^ (to_block << 1)) % 65536
        self._bitmap[_idx] = (self._bitmap[_idx] + 1) & 0xFF

    def update_path(self, block_id: int):
        """路径追踪。"""
        if self._current_path and self._current_path[-1] != block_id:
            self.update_edge(self._current_path[-1], block_id)
        self._current_path.append(block_id)
        if len(self._current_path) > 128:
            self._current_path = self._current_path[-64:]

    def commit_path(self):
        """保存当前路径（到达终止点时调用）。"""
        if self._current_path:
            _t = tuple(self._current_path[-16:])  # last 16 blocks as signature
            self._paths.add(_t)
        self._current_path = []

    # ---- Queries ----
    @property
    def coverage_rate(self) -> float:
        """覆盖率：已覆盖 block / 总 block。"""
        if self._total_blocks <= 0:
            return 0.0
        return len(self._blocks) / self._total_blocks

    @property
    def edge_coverage(self) -> Set[Tuple[int, int]]:
        return self._edges

    @property
    def covered_count(self) -> int:
        return len(self._blocks)

    @property
    def edge_count(self) -> int:
        return len(self._edges)

    def is_novel(self, blocks: List[int]) -> bool:
        """检查是否包含新 block。"""
        return any(_b not in self._blocks for _b in blocks)

    def new_since_last_sync(self) -> Set[int]:
        """自上次同步以来的新 blocks。"""
        _new = self._new_since_sync
        self._new_since_sync = set()
        return _new

    # ---- Export ----
    def export_coverage(self, fmt: str = "lcov") -> str:
        """导出覆盖率数据。"""
        if fmt == "lcov":
            return self._export_lcov()
        elif fmt == "json":
            return self._export_json()
        return ""

    def _export_lcov(self) -> str:
        _lines = ["TN:BinMind Fuzzing"]
        for _b in sorted(self._blocks):
            _lines.append(f"DA:{_b},1")
        _lines.append("LH:{}".format(len(self._blocks)))
        _lines.append(f"LF:{self._total_blocks}")
        _lines.append("end_of_record")
        return "\n".join(_lines)

    def _export_json(self) -> str:
        return json.dumps({
            "covered_blocks": sorted(self._blocks),
            "covered_edges": [[_e[0], _e[1]] for _e in self._edges],
            "total_blocks": self._total_blocks,
            "coverage_rate": self.coverage_rate,
        })

    def export_bitmap(self) -> bytes:
        """导出 AFL 格式 bitmap。"""
        return bytes(self._bitmap)

    # ---- Stats ----
    def get_stats(self) -> CoverageStats:
        return CoverageStats(
            total_blocks=self._total_blocks,
            covered_blocks=len(self._blocks),
            edges=self._total_edges,
            covered_edges=len(self._edges),
            unique_paths=len(self._paths),
        )

    def set_total_blocks(self, count: int):
        self._total_blocks = count

    def merge(self, other: "CoverageCollector"):
        """合并另一个 collector 的覆盖数据。"""
        _before = len(self._blocks)
        self._blocks.update(other._blocks)
        self._edges.update(other._edges)
        self._paths.update(other._paths)
        for _i in range(len(self._bitmap)):
            self._bitmap[_i] = (self._bitmap[_i] + other._bitmap[_i]) & 0xFF
        return len(self._blocks) - _before
