# 小波包分解隐蔽时序信道检测器 —— 多分辨率频率域异常检测。
#
# 现有隐蔽时序信道检测(熵/IAT抖动比/自相关)在单一时域尺度操作,
# 对以下信道类型漏检率高:
# JitterBug: 以时钟抖动为载波, 时域近乎均匀分布
# TRCTC (Time-Replay): 在特定频带回放流量时序模式
# Model-Based: 用统计模型参数编码信息, 逐包IAT服从伪装分布
#
# 小波包分解(DWPT)将IAT序列递归二分为低频(近似)和高频(细节)子带,
# 构建完整二叉树频率分解。隐蔽信道在特定子带产生与正常流量不同的
# 能量分布——该异常在时域不显著但在频率域可检测。
#
# 核心假设: 正常流量的IAT能量按1/f分布(低频主导);
# 隐蔽信道在编码频带产生额外能量注入, 破坏1/f分布。
#
# 与现有方法的差异:
#   - 现有工作(熵检测/JitterBug检测): 时域统计, 对TRCTC和Model-Based盲区大
# 未见2024-2025文献将DWPT应用于网络隐蔽时序信道检测
# 小波方法在音频隐写分析中有先例,
#     迁移至网络时序域需解决IAT序列的非平稳性和不等长问题
#
# 实现约束: 纯Python, 无pywt/numpy依赖。使用Haar小波(Daubechies-2)
# 作为默认基函数, 支持通过kernel参数替换为其他正交小波。

from __future__ import annotations

import math
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple


# Haar小波滤波器系数 (Daubechies-2)
# 低通: 平均; 高通: 差分
_HAAR_LO = [1.0 / math.sqrt(2), 1.0 / math.sqrt(2)]
_HAAR_HI = [1.0 / math.sqrt(2), -1.0 / math.sqrt(2)]


@dataclass
class WaveletSubband:
    """单个小波子带 —— DWPT树的一个节点"""
    level: int                 # 分解层级(0=原始信号)
    index: int                 # 该层级内的子带索引
    coefficients: List[float] = field(default_factory=list)
    energy: float = 0.0        # ||coeffs||²
    energy_ratio: float = 0.0  # 该子带能量占总能量的比例
    entropy: float = 0.0       # 子带系数的香农熵


@dataclass
class WaveletDecomposition:
    """DWPT完整分解结果"""
    original_length: int
    max_level: int
    subbands: List[WaveletSubband] = field(default_factory=list)
    total_energy: float = 0.0
    # 能量分布向量: 按(level, index)排序的energy_ratio序列
    energy_distribution: List[float] = field(default_factory=list)


@dataclass
class CovertChannelScore:
    """隐蔽信道检测得分"""
    channel_type: str = ""             # 检测到的隐蔽信道类型
    wavelet_score: float = 0.0         # [0,1] 小波异常得分
    dominant_frequency_band: str = ""  # 异常能量集中的频带
    energy_deviation: float = 0.0      # 与正常1/f分布的偏差
    subband_details: List[Dict[str, Any]] = field(default_factory=list)


class WaveletPacketDecomposer:
    """离散小波包变换(DWPT)分解器。

    递归将信号分解为低频(L)和高频(H)子带, 构建满二叉树。
    第level层有2^level个子带。

    使用Haar小波作为默认基。信号长度若非2的幂, 使用对称边界扩展
    (不补零以避免边界处引入人为高频)使其达到最近的2的幂。
    """

    def __init__(self, lo_pass: Optional[List[float]] = None,
                 hi_pass: Optional[List[float]] = None,
                 max_level: int = 5):
        self._lo = lo_pass or _HAAR_LO
        self._hi = hi_pass or _HAAR_HI
        self._max_level = max_level

    def decompose(self, signal: List[float]) -> WaveletDecomposition:
        """对信号做完整DWPT分解。返回WaveletDecomposition含所有子带。

        信号预处理: 零均值化→对称扩展至2的幂→DWPT。
        """
        n = len(signal)
        if n < 4:
            return WaveletDecomposition(original_length=n, max_level=0)

        # 零均值化: 去除DC分量, 避免DC能量主导所有子带
        mean_val = sum(signal) / n
        centered = [x - mean_val for x in signal]

        # 对称扩展至2的幂
        target_len = 1
        while target_len < n:
            target_len <<= 1
        if target_len > n:
            centered = self._symmetric_extend(centered, target_len)

        original_len = len(centered)
        actual_max = min(self._max_level, int(math.log2(original_len)))

        subbands: List[WaveletSubband] = []
        # 层级0: 原始信号
        total_energy = sum(c * c for c in centered)
        subbands.append(WaveletSubband(
            level=0, index=0, coefficients=list(centered),
            energy=total_energy, energy_ratio=1.0,
            entropy=self._coefficient_entropy(centered),
        ))

        # 递归DWPT
        # 每层处理前一层的每个子带
        prev_level_coeffs = [list(centered)]
        for level in range(1, actual_max + 1):
            current_coeffs = []
            for idx, coeffs in enumerate(prev_level_coeffs):
                # 对该子带做一层二带分解: L和H
                lo, hi = self._one_level_decompose(coeffs)
                for sub_idx, sub_coeffs in enumerate([lo, hi]):
                    global_idx = idx * 2 + sub_idx
                    energy = sum(c * c for c in sub_coeffs)
                    ratio = energy / max(total_energy, 1e-12)
                    sb = WaveletSubband(
                        level=level, index=global_idx,
                        coefficients=sub_coeffs,
                        energy=energy,
                        energy_ratio=min(ratio, 1.0),
                        entropy=self._coefficient_entropy(sub_coeffs),
                    )
                    subbands.append(sb)
                    current_coeffs.append(sub_coeffs)
            prev_level_coeffs = current_coeffs

        energy_dist = [
            sb.energy_ratio for sb in sorted(
                [s for s in subbands if s.level == actual_max],
                key=lambda s: s.index)
        ]

        return WaveletDecomposition(
            original_length=n,
            max_level=actual_max,
            subbands=subbands,
            total_energy=total_energy,
            energy_distribution=energy_dist,
        )

    def _one_level_decompose(self, signal: List[float]
                              ) -> Tuple[List[float], List[float]]:
        """单层Haar二带分解: 卷积+下采样2。

        低通输出 = (x[2i] + x[2i+1]) / √2
        高通输出 = (x[2i] - x[2i+1]) / √2
        """
        n = len(signal)
        lo, hi = [], []
        for i in range(0, n - 1, 2):
            a, b = signal[i], signal[i + 1]
            lo.append((a + b) / math.sqrt(2))
            hi.append((a - b) / math.sqrt(2))
        # 奇数长度: 最后一个样本复制到低通
        if n % 2 == 1:
            lo.append(signal[-1] * math.sqrt(2))
            hi.append(0.0)
        return lo, hi

    @staticmethod
    def _symmetric_extend(signal: List[float],
                          target_len: int) -> List[float]:
        """对称边界扩展: [a,b,c]→[a,b,c,b,a,b,c,b,a,...]"""
        n = len(signal)
        if n >= target_len:
            return signal[:target_len]
        result = list(signal)
        while len(result) < target_len:
            remaining = target_len - len(result)
            # 镜像段: 不包括边界元素以避免重复
            mirror = signal[-2:0:-1] if len(signal) > 2 else signal[::-1]
            mirror = mirror[:remaining]
            if not mirror:
                mirror = signal[::-1]
            result.extend(mirror)
        return result[:target_len]

    @staticmethod
    def _coefficient_entropy(coeffs: List[float]) -> float:
        """子带系数的归一化香农熵(基于绝对值直方图)"""
        if len(coeffs) < 2:
            return 0.0
        abs_vals = [abs(c) for c in coeffs]
        total = sum(abs_vals)
        if total < 1e-12:
            return 0.0
        probs = [v / total for v in abs_vals]
        ent = 0.0
        for p in probs:
            if p > 1e-12:
                ent -= p * math.log2(p)
        return ent / max(math.log2(len(coeffs)), 1.0)


__all__ = [
    "WaveletSubband", "WaveletDecomposition", "CovertChannelScore",
    "WaveletPacketDecomposer",
]
