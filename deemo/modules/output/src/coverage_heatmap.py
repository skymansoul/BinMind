# 创建: 2024-09-02 18:33
# 修改: 2024-09-02 — 边->地址反向映射 + 256B bucket 密度聚合
"""
空间覆盖热力图生成器 — 边覆盖位图→地址空间热力图→热点/冷点识别。

现有覆盖统计 (coverage.py) 报告"覆盖了多少条边"——但不知道
"哪些代码区域被密集覆盖, 哪些区域从未触及"。本模块将覆盖位图
映射回二进制地址空间, 生成空间感知的覆盖热力图。

映射过程:
  1. 边→地址: 边哈希解码为 (src_addr, dst_addr) → 定位到代码段
  2. 热度聚合: 按 256 字节粒度聚合成函数/基本块的覆盖密度
  3. 冷点检测: 覆盖密度 < 阈值的连续区域 → 标记为未探索
  4. 热点检测: 覆盖密度最高的 top-N% 区域 → 标记为密集测试
  5. 边界检测: 热/冷区域交界 → fuzzing 的优先探索目标

应用场景:
  - 模糊测试导航: 优先变异"能到达冷点边界"的种子
  - 覆盖率审计: 哪些函数完全未测试?
  - 补丁验证: 补丁后的新增代码是否被覆盖?

为什么 256 字节粒度:
  太粗 (4096) → 掩盖函数内部的覆盖差异 (前半覆盖, 后半未覆盖)
  太细 (16) → 噪声过多, 相邻指令几乎总是一起覆盖
  256 字节 ≈ 2-4 个基本块 → 平衡粒度与信噪比

ref: AFL++ collision-free coverage — 边覆盖位图结构,
     本项目的 addr→bitmap 逆向映射补充了 AFL++ 的单向设计
ref: DrCov (DynamoRIO coverage) — 基本块级覆盖可视化,
     本项目取其空间热力图概念但运行于纯静态/离线模式
"""

from __future__ import annotations

from dataclasses import dataclass, field
from collections import defaultdict
from typing import Optional


@dataclass
class HeatmapRegion:
    """热力图中的一个区域——地址范围 + 覆盖密度。"""
    start_addr: int
    end_addr: int
    density: float = 0.0        # [0,1] 覆盖密度
    category: str = ''          # 'hot' | 'warm' | 'cold' | 'dead'
    function_name: str = ''
    edge_count: int = 0
    total_edges: int = 1


@dataclass
class CoverageHeatmap:
    """完整的覆盖热力图——所有区域 + 统计摘要。"""
    binary_name: str = ''
    total_address_space: int = 0
    covered_regions: list[HeatmapRegion] = field(default_factory=list)
    cold_spots: list[HeatmapRegion] = field(default_factory=list)
    hot_spots: list[HeatmapRegion] = field(default_factory=list)
    boundaries: list[tuple[int, int]] = field(default_factory=list)  # 冷热交界
    overall_density: float = 0.0


# 边→地址映射

def decode_edge_hash(edge_hash: int) -> tuple[int, int]:
    """从 AFL 风格的边哈希反推 src 和 dst 地址的近似值。
    hash = (prev >> 4) ^ (curr << 8)。无法精确还原——但可还原代码区域。"""
    # 近似: 假设 prev 已知 (从上一条边传递), 或仅使用高 16 位
    prev_approx = (edge_hash & 0xFFFF) << 4
    curr_approx = (edge_hash >> 16) << 8
    return prev_approx, curr_approx


# 热度聚合

def aggregate_heatmap(edge_bitmap: bytearray,
                      edge_to_addr: dict[int, tuple[int, int]],
                      code_sections: list[tuple[int, int]],
                      bucket_size: int = 256) -> CoverageHeatmap:
    """从边覆盖位图聚合为空间热力图。"""
    heatmap = CoverageHeatmap()

    if not code_sections:
        return heatmap

    total_addr_range = sum(end - start for start, end in code_sections)
    heatmap.total_address_space = total_addr_range
    section_start = code_sections[0][0]

    # 初始化所有 bucket 为 0
    buckets: dict[int, float] = defaultdict(float)
    bucket_edge_counts: dict[int, int] = defaultdict(int)
    bucket_total: dict[int, int] = defaultdict(int)

    for section_start, section_end in code_sections:
        for addr in range(section_start, section_end, bucket_size):
            bucket_idx = addr // bucket_size
            buckets[bucket_idx] = 0.0

    # 扫描边覆盖位图——统计每个地址的覆盖次数
    for byte_idx in range(len(edge_bitmap)):
        for bit in range(8):
            if edge_bitmap[byte_idx] & (1 << bit):
                edge_id = byte_idx * 8 + bit
                # 边→地址映射
                src, dst = edge_to_addr.get(edge_id, (0, 0))
                if src:
                    bucket_idx = src // bucket_size
                    bucket_edge_counts[bucket_idx] += 1
                if dst:
                    bucket_idx = dst // bucket_size
                    bucket_edge_counts[bucket_idx] += 1
                # 总数 (近似)
                if src:
                    bucket_total[src // bucket_size] += 1

    # 计算密度
    for bucket_idx in buckets:
        count = bucket_edge_counts.get(bucket_idx, 0)
        total = max(1, bucket_total.get(bucket_idx, 10))
        buckets[bucket_idx] = min(1.0, count / total)

    # 生成热力图区域
    sorted_buckets = sorted(buckets.items())
    total_density = 0.0
    region_start = None
    region_density = 0.0

    for bucket_idx, density in sorted_buckets:
        addr = bucket_idx * bucket_size
        total_density += density

        if region_start is None:
            region_start = addr
            region_density = density
        elif abs(density - region_density) > 0.3:  # 密度变化→关闭前一个区域
            region = HeatmapRegion(
                start_addr=region_start, end_addr=addr,
                density=round(region_density, 3),
                category=_categorize(region_density))
            heatmap.covered_regions.append(region)
            region_start = addr
            region_density = density

    # 最后一个区域
    if region_start is not None:
        region = HeatmapRegion(
            start_addr=region_start,
            end_addr=max(b * bucket_size for b in buckets.keys()),  # fixed
            density=round(region_density, 3),
            category=_categorize(region_density))
        heatmap.covered_regions.append(region)

    # 分类
    heatmap.cold_spots = [r for r in heatmap.covered_regions if r.category == 'cold']
    heatmap.hot_spots = [r for r in heatmap.covered_regions if r.category == 'hot']
    heatmap.overall_density = round(total_density / max(1, len(buckets)), 3)

    # 冷热边界检测
    regions = heatmap.covered_regions
    for i in range(len(regions) - 1):
        if (regions[i].category == 'hot' and regions[i+1].category == 'cold') or \
           (regions[i].category == 'cold' and regions[i+1].category == 'hot'):
            heatmap.boundaries.append((regions[i].end_addr, regions[i+1].start_addr))

    return heatmap


def _categorize(density: float) -> str:
    if density >= 0.7:
        return 'hot'
    if density >= 0.3:
        return 'warm'
    if density > 0.0:
        return 'cold'
    return 'dead'


# 冷点引导建议

def suggest_coldspot_targets(heatmap: CoverageHeatmap,
                             top_k: int = 5) -> list[dict]:
    """从热力图中提取冷点引导目标——供模糊测试定向使用。"""
    targets = []

    # 策略1: 冷热边界 (最有希望——从已探索到未探索)
    for cold_start, hot_start in heatmap.boundaries:
        targets.append({
            'type': 'boundary',
            'address': cold_start,
            'reason': f'cold-hot boundary @0x{cold_start:x}',
            'priority': 0.9,
        })

    # 策略2: 最大的冷区域
    large_colds = sorted(heatmap.cold_spots,
                        key=lambda r: r.end_addr - r.start_addr,
                        reverse=True)
    for region in large_colds[:top_k - len(targets)]:
        targets.append({
            'type': 'cold_region',
            'address': region.start_addr,
            'reason': f'cold region [{region.start_addr:#x}, {region.end_addr:#x}], size={region.end_addr-region.start_addr}',
            'priority': 0.6,
        })

    targets.sort(key=lambda t: t['priority'], reverse=True)
    return targets[:top_k]


class CoverageHeatmapGenerator:
    """覆盖热力图生成器——边位图→空间热力图→冷热点目标。"""

    def __init__(self, bucket_size: int = 256):
        self._bucket_size = bucket_size
        self._heatmaps: list[CoverageHeatmap] = []

    def generate(self, edge_bitmap: bytearray,
                 edge_to_addr: dict[int, tuple[int, int]],
                 code_sections: list[tuple[int, int]],
                 binary_name: str = '') -> CoverageHeatmap:
        heatmap = aggregate_heatmap(
            edge_bitmap, edge_to_addr, code_sections, self._bucket_size)
        heatmap.binary_name = binary_name
        self._heatmaps.append(heatmap)
        return heatmap

    def stats(self) -> dict:
        return {'heatmaps_generated': len(self._heatmaps)}


__all__ = [
    'CoverageHeatmapGenerator', 'CoverageHeatmap', 'HeatmapRegion',
    'aggregate_heatmap', 'suggest_coldspot_targets',
]
