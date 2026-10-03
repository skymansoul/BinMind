# 三分辨率熵扫描: 页(4KB)/缓存行(64B)/字(8B) 三级粒度
# Wasserstein 距离基线: 正常堆 vs 喷射堆的熵剖面分布差异

"""堆喷射熵检测器 - 多分辨率内存熵扫描区分喷射攻击与合法数据

堆喷射 (heap spray) 是浏览器和脚本引擎利用的核心技术:
  攻击者在堆上分配大量相同结构的对象 (如 0x41414141 填充的 ArrayBuffer)
  配合漏洞控制 EIP/RIP 时, 跳转到喷射区域的概率接近 100%（审计口径: 描述攻击机制非检测结果; 真实口径 F1=0.939 n=121 见 deemo/test_reports/binary_pipeline_full.json）

传统检测 (pattern-based) 扫描已知喷射模式 (NOP sled, 0x0c0c0c0c)
但攻击者可以用非标准模式绕过多项式匹配
例如: 用随机 ASCII 文本或 0x41414141 替代 0x0c0c0c0c

本模块的根本方法: 喷射堆与正常堆在空间熵分布上有本质差异
  正常堆: 高熵区域与低熵区域交错 (不同大小的对象混在一起)
  喷射堆: 大片连续区域具有相同的熵特征 (相同对象重复分配)

三级分辨率扫描:
  1. 页级 (4KB): 粗粒度--检测连续相同熵的页块
  2. 缓存行级 (64B): 中粒度--区分对象边界
  3. 字级 (8B): 细粒度--识别 NOP sled / 重复值模式

熵剖面: {页级熵, 缓存行级熵方差, 字级重复率} 的三维向量
此向量与正常堆基线的 Wasserstein 距离 -> 喷射评分

与现有方法的差异:
- pattern-based: 精确匹配已知模式 -> 本模块: 统计熵剖面, 通用
- ML-based: 需要训练 -> 本模块: 无训练, 基线来自同进程的正常内存区域
"""

from __future__ import annotations

import math
import struct
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple


# 内存熵工具

def _byte_entropy(data: bytes) -> float:
    """计算字节序列的 Shannon 熵"""
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    h = 0.0
    for c in counts:
        if c > 0:
            p = c / n
            h -= p * math.log2(p)
    return h


def _byte_repetition_rate(data: bytes, chunk_size: int = 8) -> float:
    """计算数据中重复 chunk 的比例--高重复率暗示喷射。

    chunk_size: 比较粒度 (默认 8 字节 = 64-bit 值);
    返回 [0,1] - 1=全部相同 chunk, 0=所有 chunk 唯一。
    """
    if len(data) < chunk_size:
        return 0.0
    chunks: Dict[bytes, int] = defaultdict(int)
    for i in range(0, len(data) - chunk_size + 1, chunk_size):
        chunks[data[i:i + chunk_size]] += 1
    total = sum(chunks.values())
    if total <= 1:
        return 0.0
    # 最频繁 chunk 的出现次数 / 总 chunk 数
    max_count = max(chunks.values())
    return max_count / total


# 数据结构

@dataclass
class HeapEntropyProfile:
    """堆区域的三分辨率熵剖面"""
    region_start: int
    region_size: int
    # 页级: 所有页的熵列表
    page_entropies: List[float] = field(default_factory=list)
    # 缓存行级: 所有缓存行的熵列表
    cacheline_entropies: List[float] = field(default_factory=list)
    # 字级: 8-byted 重复率
    word_repetition_rate: float = 0.0
    # 汇总
    page_entropy_mean: float = 0.0
    page_entropy_std: float = 0.0
    cacheline_entropy_std: float = 0.0


@dataclass
class SprayDetectionReport:
    """堆喷射检测报告"""
    total_regions_scanned: int
    spray_regions: List[Tuple[int, int, float]]  # (start, size, spray_score)
    max_spray_score: float
    is_spray_detected: bool
    # 证据
    evidence: List[str] = field(default_factory=list)


# 检测器

class HeapSprayDetector:

    # 喷射阈值
    _SPRAY_THRESHOLD = 0.60        # spray_score > 此值->标记为喷射区域
    _REPETITION_THRESHOLD = 0.30   # 字级重复率 > 此值->强证据

    def scan(
        self,
        memory_chunks: List[Tuple[int, bytes]],
        baseline_regions: Optional[List[Tuple[int, bytes]]] = None,
    ) -> SprayDetectionReport:
        """扫描内存区域检测堆喷射

        memory_chunks: [(start_address, raw_bytes), ...] - 待扫描的内存区域
        baseline_regions: 正常堆的内存区域--用于建立基线熵剖面

        返回 SprayDetectionReport
        """
        # 建立正常堆基线 (若未提供, 用自基线--整个扫描区域的平均)
        if baseline_regions:
            baseline_profile = self._compute_profile(
                b''.join(b for _, b in baseline_regions), 0
            )
        else:
            all_data = b''.join(b for _, b in memory_chunks)
            baseline_profile = self._compute_profile(all_data, 0)

        spray_regions: List[Tuple[int, int, float]] = []
        evidence: List[str] = []

        for start, data in memory_chunks:
            profile = self._compute_profile(data, start)

            # 计算与基线的 Wasserstein 距离 (简化: 页熵均值的CDF距离)
            w_dist = self._wasserstein_1d(
                profile.page_entropies,
                baseline_profile.page_entropies,
            )

            # 三维加权 spray_score
            page_anomaly = w_dist / max(0.01, baseline_profile.page_entropy_mean + 0.5)
            cl_anomaly = profile.cacheline_entropy_std / max(
                0.01, baseline_profile.cacheline_entropy_std + 0.1
            )
            rep_factor = profile.word_repetition_rate

            spray_score = 0.35 * page_anomaly + 0.25 * cl_anomaly + 0.40 * rep_factor
            spray_score = min(1.0, spray_score)

            if spray_score >= self._SPRAY_THRESHOLD:
                spray_regions.append((start, len(data), spray_score))
                evidence.append(
                    f'region 0x{start:x}: spray_score={spray_score:.3f} '
                    f'(page_anom={page_anomaly:.2f}, cl_anom={cl_anomaly:.2f}, '
                    f'rep={rep_factor:.2f})'
                )

        max_score = max((r[2] for r in spray_regions), default=0.0)

        return SprayDetectionReport(
            total_regions_scanned=len(memory_chunks),
            spray_regions=sorted(spray_regions, key=lambda r: -r[2]),
            max_spray_score=round(max_score, 4),
            is_spray_detected=len(spray_regions) > 0,
            evidence=evidence[:10],  # top 10 evidence lines
        )

    def _compute_profile(
        self, data: bytes, region_start: int
    ) -> HeapEntropyProfile:
        """计算内存区域的三分辨率熵剖面"""
        if not data:
            return HeapEntropyProfile(
                region_start=region_start, region_size=0,
            )

        profile = HeapEntropyProfile(
            region_start=region_start,
            region_size=len(data),
        )

        # 页级 (4096 字节)
        for i in range(0, len(data), 4096):
            page = data[i:i + 4096]
            profile.page_entropies.append(_byte_entropy(page))

        # 缓存行级 (64 字节)
        for i in range(0, min(len(data), 65536), 64):
            cl = data[i:i + 64]
            profile.cacheline_entropies.append(_byte_entropy(cl))

        # 字级重复率
        profile.word_repetition_rate = _byte_repetition_rate(
            data[:min(len(data), 65536)]  # 采样前 64KB
        )

        # 汇总统计
        if profile.page_entropies:
            n = len(profile.page_entropies)
            profile.page_entropy_mean = sum(profile.page_entropies) / n
            variance = sum(
                (h - profile.page_entropy_mean) ** 2
                for h in profile.page_entropies
            ) / n
            profile.page_entropy_std = math.sqrt(variance)

        if profile.cacheline_entropies:
            n = len(profile.cacheline_entropies)
            mean_cl = sum(profile.cacheline_entropies) / n
            variance_cl = sum(
                (h - mean_cl) ** 2 for h in profile.cacheline_entropies
            ) / n
            profile.cacheline_entropy_std = math.sqrt(variance_cl)

        return profile

    @staticmethod
    def _wasserstein_1d(
        samples_a: List[float],
        samples_b: List[float],
    ) -> float:
        """两个一维样本集的 Wasserstein-1 距离 (CDF L1 距离)

        样本数不同时, 使用线性插值对齐分位数
        """
        if not samples_a or not samples_b:
            return 1.0

        a_sorted = sorted(samples_a)
        b_sorted = sorted(samples_b)

        # 在 20 个等距分位点比较 CDF
        total_dist = 0.0
        for p in range(21):
            quantile = p / 20.0
            idx_a = min(len(a_sorted) - 1, int(quantile * len(a_sorted)))
            idx_b = min(len(b_sorted) - 1, int(quantile * len(b_sorted)))
            total_dist += abs(a_sorted[idx_a] - b_sorted[idx_b])

        return total_dist / 21.0
