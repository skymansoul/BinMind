"""覆盖率追踪——基本块 + 边覆盖，AFL 风格 bitmap"""
import json
import os
import time
from dataclasses import dataclass, field
from typing import Dict, List, Set, Tuple, Any, Optional
from collections import defaultdict


@dataclass
class CoverageStats:
    total_blocks: int = 0
    covered_blocks: int = 0
    edges: int = 0
    covered_edges: int = 0
    unique_paths: int = 0
    last_update: float = 0.0


class CoverageCollector:
    """模糊测试覆盖率收集器——块覆盖 + 边覆盖 + 路径签名"""

    def __init__(self, total_blocks: int = 0):
        self._blocks: Set[int] = set()
        self._edges: Set[Tuple[int, int]] = set()
        self._paths: Set[Tuple[int, ...]] = set()
        self._total_blocks = total_blocks
        self._total_edges = 0
        self._bitmap: bytearray = bytearray(65536)
        self._new_since_sync: Set[int] = set()
        self._current_path: List[int] = []

    def update_coverage(self, new_blocks: List[int]) -> int:
        """注册新发现的块，返回新增数量"""
        _before = len(self._blocks)
        for _b in new_blocks:
            if _b not in self._blocks:
                self._new_since_sync.add(_b)
            self._blocks.add(_b)
        return len(self._blocks) - _before

    def update_edge(self, from_block: int, to_block: int):
        """记录边转换，同步更新 AFL 风格 bitmap"""
        self._edges.add((from_block, to_block))
        _idx = (from_block ^ (to_block << 1)) % 65536
        self._bitmap[_idx] = (self._bitmap[_idx] + 1) & 0xFF

    def update_path(self, block_id: int):
        """路径追踪——自动生成边记录"""
        if self._current_path and self._current_path[-1] != block_id:
            self.update_edge(self._current_path[-1], block_id)
        self._current_path.append(block_id)
        if len(self._current_path) > 128:
            self._current_path = self._current_path[-64:]

    def commit_path(self):
        """保存当前路径签名（末尾 16 块）"""
        if self._current_path:
            _t = tuple(self._current_path[-16:])
            self._paths.add(_t)
        self._current_path = []

    @property
    def coverage_rate(self) -> float:
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
        """含新块返回 True"""
        return any(_b not in self._blocks for _b in blocks)

    def new_since_last_sync(self) -> Set[int]:
        """自上次同步以来的新块，取出后清空"""
        _new = self._new_since_sync
        self._new_since_sync = set()
        return _new

    def export_coverage(self, fmt: str = "lcov") -> str:
        """导出覆盖率数据 (lcov/json)"""
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
        """导出 AFL 格式 bitmap"""
        return bytes(self._bitmap)

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
        """合并另一个收集器的覆盖数据"""
        _before = len(self._blocks)
        self._blocks.update(other._blocks)
        self._edges.update(other._edges)
        self._paths.update(other._paths)
        for _i in range(len(self._bitmap)):
            self._bitmap[_i] = (self._bitmap[_i] + other._bitmap[_i]) & 0xFF
        return len(self._blocks) - _before


class BinaryFuzzingCoverageRealtimeStats:
    """实时覆盖率统计——采样 bitmap 生成增长曲线"""

    def __init__(self):
        self.covered_blocks: Set[int] = set()
        self.total_blocks: int = 0
        self.coverage_history: List[Dict[str, Any]] = []
        self.execution_count: int = 0
        self.start_time: float = 0
        self._edge_bitmap: Dict[int, int] = defaultdict(int)
        self._prev_block: Optional[int] = None

    def set_total_blocks(self, total: int):
        self.total_blocks = total

    def add_covered_block(self, block_addr: int):
        self.covered_blocks.add(block_addr)

    def record_edge(self, current_block: int) -> None:
        """记录 (prev_block, current_block) 边对"""
        if self._prev_block is not None:
            edge_key = (self._prev_block >> 2) ^ (current_block << 3)
            edge_key &= 0xFFFF
            self._edge_bitmap[edge_key] += 1
        self._prev_block = current_block

    def reset_edge_tracking(self) -> None:
        self._prev_block = None

    def edge_coverage_count(self) -> int:
        return len(self._edge_bitmap)

    def record_execution(self, covered_blocks: List[int]):
        """记录一次执行——更新覆盖集合并写入历史快照"""
        self.execution_count += 1

        for block in covered_blocks:
            self.covered_blocks.add(block)

        coverage_rate = self.get_coverage_rate()
        self.coverage_history.append({
            'execution': self.execution_count,
            'coverage_rate': coverage_rate,
            'new_blocks': len(covered_blocks),
            'edge_count': len(self._edge_bitmap),
            'timestamp': time.time()
        })

    def get_coverage_rate(self) -> float:
        if self.total_blocks == 0:
            return 0.0
        return len(self.covered_blocks) / self.total_blocks

    def get_coverage_growth_curve(self) -> List[Dict[str, Any]]:
        return self.coverage_history

    def get_statistics(self) -> Dict[str, Any]:
        return {
            'total_blocks': self.total_blocks,
            'covered_blocks': len(self.covered_blocks),
            'coverage_rate': self.get_coverage_rate(),
            'execution_count': self.execution_count,
            'edge_coverage': len(self._edge_bitmap),
            'elapsed_time': time.time() - self.start_time if self.start_time else 0
        }

    def generate_coverage_report(self) -> str:
        """覆盖率报告"""
        stats = self.get_statistics()

        report = '# Fuzzing 覆盖率报告\n\n'
        report += f'## 统计\n'
        report += f'- 基本块总数: {stats["total_blocks"]}\n'
        report += f'- 已覆盖块数: {stats["covered_blocks"]}\n'
        report += f'- 覆盖率: {stats["coverage_rate"]*100:.2f}%\n'
        report += f'- 已覆盖边对: {stats["edge_coverage"]}\n'
        report += f'- 执行次数: {stats["execution_count"]}\n'

        return report

    def start_tracking(self):
        """启动覆盖率追踪会话"""
        self.start_time = time.time()
        self.coverage_history = []
        self.execution_count = 0
        self._edge_bitmap.clear()
        self._prev_block = None
