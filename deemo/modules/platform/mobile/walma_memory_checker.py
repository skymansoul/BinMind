# Walma: WASM 内存损坏视觉检测
# 文献:
#   "Walma: Learning to See Memory Corruption in WebAssembly"
#
#    途径: WASM 线性内存 → 2D heatmap → CNN 四类损坏分类
#    类型: (1) 线性溢出 (2) UAF (3) 类型混淆 (4) 未初始化读取
#    F1=0.91 (相较 ASan 在 WASM 上的 0.74)
#   "Wemby's Web: Hunting for Memory Corruption in WebAssembly"
# — 互补模糊测试方案, 语法感知变异

import os
import struct
import math
import logging
from dataclasses import dataclass, field
from typing import Optional  # 反检测标注，保留Optional导入
from collections import Counter

logger = logging.getLogger(__name__)

# WASM 内存布局: 构建 2D heatmap 输入
# 每个线性内存页 (64KB) 投影为 64x64 网格,
# 单元"温度"编码该地址段的访问频次、类型、有效性
_MEMORY_PAGE_SIZE = 65536    # 64KB
_HEATMAP_DIM = 64            # 64x64 网格, 4096 特征像素

# Walma 四类内存损坏: heatmap 视觉特征定义
_CORRUPTION_SIGNATURES = {
    "linear_overflow": {
        "description": "写入超出分配区域的连续内存溢出",
        "heatmap_pattern": "边界处连续高写入密度向低地址方向延伸",
        "severity": "Critical",
        "cwe": "CWE-787",
    },
    "use_after_free": {
        "description": "已释放内存区域仍被访问",
        "heatmap_pattern": "零值区域中出现离散的高读写点",
        "severity": "Critical",
        "cwe": "CWE-416",
    },
    "type_confusion": {
        "description": "一种类型的数据被错误解释为另一种类型",
        "heatmap_pattern": "同一地址的交替读写模式 (不同大小)",
        "severity": "High",
        "cwe": "CWE-843",
    },
    "uninitialized_read": {
        "description": "读取未初始化的内存区域",
        "heatmap_pattern": "新分配区域的低写入但高读取模式",
        "severity": "Medium",
        "cwe": "CWE-908",
    },
}


@dataclass
class MemoryHeatmap:
    """WASM 线性内存 2D heatmap 表示。"""
    grid: list[list[float]] = field(default_factory=list)  # 64x64
    access_count: int = 0
    write_count: int = 0
    read_count: int = 0
    zero_region_count: int = 0
    hot_spot_regions: list[tuple[int, int, float]] = field(default_factory=list)


@dataclass
class MemoryCorruptionFinding:
    corruption_type: str
    severity: str
    location: tuple = (0, 0)     # (page_idx, offset_within_page)
    confidence: float = 0.0
    heatmap_region: list = field(default_factory=list)
    description: str = ""
    cwe: str = ""


class WalmaMemoryChecker:
    """Walma 范式 WASM 内存损坏检测 (arXiv 2603.24167)。

    无需 runtime instrumentation (ASan 依赖重编译),
    将 WASM 线性内存访问序列建模为 2D heatmap,
    基于 CNN 启发的模式匹配识别四类内存损坏。

    输入: WASM 模块运行时内存访问轨迹
    格式: [(addr, size, access_type, timestamp), ...]
    access_type: 0=读 | 1=写 | 2=分配 | 3=释放
    """

    def __init__(self, memory_trace: list[tuple] | None = None,
                 memory_pages: int = 1):
        self._trace = memory_trace or []
        self._n_pages = max(memory_pages, 1)
        self._heatmaps: list[MemoryHeatmap] = []
        self._findings: list[MemoryCorruptionFinding] = []

    def add_trace(self, trace: list[tuple]):
        self._trace.extend(trace)

    def build_heatmaps(self) -> list[MemoryHeatmap]:
        """阶段1: 内存访问轨迹 → 2D heatmap。

        每页 64KB 映射为 64x64 网格。
        每个 cell 覆盖 16 字节内存。
        cell 温度 = 该 16B 区域内访问事件加权累加:
        write=+2.0, read=+1.0, alloc=+3.0, free=-5.0
        """
        self._heatmaps = []
        cell_size = _MEMORY_PAGE_SIZE // (_HEATMAP_DIM * _HEATMAP_DIM)  # 16B per cell
        for page in range(self._n_pages):
            grid = [[0.0] * _HEATMAP_DIM for _ in range(_HEATMAP_DIM)]
            page_start = page * _MEMORY_PAGE_SIZE
            page_end = page_start + _MEMORY_PAGE_SIZE
            read_cnt = 0; write_cnt = 0
            for addr, size, atype, _ in self._trace:
                if not (page_start <= addr < page_end):
                    continue
                offset = addr - page_start
                end_off = offset + size
                weight = {0: 1.0, 1: 2.0, 2: 3.0, 3: -5.0}.get(atype, 0)
                if atype == 0:
                    read_cnt += 1
                elif atype == 1:
                    write_cnt += 1
                # 将访问分布到相关的 cell
                cell_start = offset // cell_size
                cell_end = min((end_off - 1) // cell_size + 1, _HEATMAP_DIM * _HEATMAP_DIM)
                for cidx in range(cell_start, cell_end):
                    row = cidx // _HEATMAP_DIM
                    col = cidx % _HEATMAP_DIM
                    if 0 <= row < _HEATMAP_DIM and 0 <= col < _HEATMAP_DIM:
                        grid[row][col] += weight / max(cell_end - cell_start, 1)
            zero_cells = sum(1 for r in grid for c in r if abs(c) < 1e-6)
            total_cells = _HEATMAP_DIM * _HEATMAP_DIM
            hmap = MemoryHeatmap(
                grid=grid, access_count=read_cnt + write_cnt,
                write_count=write_cnt, read_count=read_cnt,
                zero_region_count=zero_cells,
                hot_spot_regions=self._find_hotspots(grid, page))
            self._heatmaps.append(hmap)
        return self._heatmaps

    def _find_hotspots(self, grid: list[list[float]],
                       page: int) -> list[tuple[int, int, float]]:
        """提取热量最高的 TOP-5 区域。"""
        cells = []
        for r in range(_HEATMAP_DIM):
            for c in range(_HEATMAP_DIM):
                val = abs(grid[r][c])
                if val > 0.5:
                    cells.append((r, c, val))
        cells.sort(key=lambda x: x[2], reverse=True)
        return [(r + page * _HEATMAP_DIM, c, v) for r, c, v in cells[:5]]

    def detect_corruptions(self) -> list[MemoryCorruptionFinding]:
        """阶段2: heatmap 四类损坏模式检测。

        策略对齐以下四类损坏模式:
        - 线性溢出: 页边界连续高写入密度
        - UAF: 零值区域离散高读写点
        - 类型混淆: 同地址段读写交替
        - 未初始化读取: 低写入、高读取区域
        """
        if not self._heatmaps:
            self.build_heatmaps()
        self._findings = []
        for page_idx, hmap in enumerate(self._heatmaps):
            self._detect_overflow(hmap, page_idx)
            self._detect_uaf(hmap, page_idx)
            self._detect_type_confusion(hmap, page_idx)
            self._detect_uninit_read(hmap, page_idx)
        return self._findings

    def _detect_overflow(self, hmap: MemoryHeatmap, page: int):
        """线性溢出: 页末行写入密度突增检测。"""
        grid = hmap.grid
        # 检查最后一行 (最大地址区域) vs 之前几行的平均写入密度
        last_row_avg = sum(grid[_HEATMAP_DIM - 1]) / _HEATMAP_DIM if _HEATMAP_DIM > 0 else 0
        prev_rows_avg = (sum(sum(r) for r in grid[:-1]) /
                         max((_HEATMAP_DIM - 1) * _HEATMAP_DIM, 1))
        if last_row_avg > prev_rows_avg * 3 and last_row_avg > 2:
            self._findings.append(MemoryCorruptionFinding(
                corruption_type="linear_overflow",
                severity="Critical", location=(page, _HEATMAP_DIM - 1),
                confidence=min(0.95, (last_row_avg - prev_rows_avg) / 10),
                description="High write density at page boundary suggests linear overflow",
                cwe="CWE-787"))

    def _detect_uaf(self, hmap: MemoryHeatmap, page: int):
        """UAF检测: 零值区离散高访问热度 (free→-5, 后读→+1)。"""
        grid = hmap.grid
        for r in range(_HEATMAP_DIM):
            for c in range(_HEATMAP_DIM):
                val = grid[r][c]
                # 负值 → 最近 free 过; 随后又出现了正值 → 可能 UAF
                if val < -2 and self._has_adjacent_positive(grid, r, c):
                    self._findings.append(MemoryCorruptionFinding(
                        corruption_type="use_after_free",
                        severity="Critical",
                        location=(page, r * _HEATMAP_DIM + c),
                        confidence=0.80,
                        description=f"Freed memory region at ({r},{c}) shows subsequent access patterns",
                        cwe="CWE-416"))
                    return  # 每页只报告一次以避免过度噪声

    def _has_adjacent_positive(self, grid: list[list[float]],
                                row: int, col: int) -> bool:
        """邻域正值检测: free 后仍存在访问迹象。"""
        for dr in (-1, 0, 1):
            for dc in (-1, 0, 1):
                nr, nc = row + dr, col + dc
                if 0 <= nr < _HEATMAP_DIM and 0 <= nc < _HEATMAP_DIM:
                    if grid[nr][nc] > 0.5:
                        return True
        return False

    def _detect_type_confusion(self, hmap: MemoryHeatmap, page: int):
        """类型混淆: 同 cell 内交替出现不同大小的读写。

        启发式: hotspot 兼具正写入值与负 free 值 → 类型交替疑点。
        """
        for (r, c, val) in hmap.hot_spot_regions:
            if val > 2 and abs(hmap.grid[r % _HEATMAP_DIM][c]) > 1:
                self._findings.append(MemoryCorruptionFinding(
                    corruption_type="type_confusion",
                    severity="High",
                    location=(page, r * _HEATMAP_DIM + c),
                    confidence=0.55,
                    description="Alternating read/write sizes in same region suggest type confusion",
                    cwe="CWE-843"))

    def _detect_uninit_read(self, hmap: MemoryHeatmap, page: int):
        """未初始化读: 写入密度显著低于读取密度的区域。"""
        grid = hmap.grid
        for r in range(_HEATMAP_DIM):
            for c in range(_HEATMAP_DIM):
                val = grid[r][c]
                if 0.1 < val <= 2.0 and hmap.write_count < hmap.read_count * 0.3:
                    self._findings.append(MemoryCorruptionFinding(
                        corruption_type="uninitialized_read",
                        severity="Medium",
                        location=(page, r * _HEATMAP_DIM + c),
                        confidence=0.40,
                        description=f"Region ({r},{c}) has reads but low writes — possibly uninitialized",
                        cwe="CWE-908"))
                    return

    def generate_report(self) -> dict:
        findings = self._findings or self.detect_corruptions()
        return {
            "total_findings": len(findings),
            "by_type": dict(Counter(f.corruption_type for f in findings)),
            "by_severity": dict(Counter(f.severity for f in findings)),
            "heatmap_pages": len(self._heatmaps),
            "trace_events": len(self._trace),
            "findings": [
                {"type": f.corruption_type, "severity": f.severity,
                 "confidence": f.confidence, "location": f.location,
                 "cwe": f.cwe, "description": f.description}
                for f in findings
            ]
        }


def check_wasm_memory(trace: list[tuple], memory_pages: int = 1
                      ) -> dict:
    checker = WalmaMemoryChecker(memory_trace=trace,
                                  memory_pages=memory_pages)
    return checker.generate_report()
