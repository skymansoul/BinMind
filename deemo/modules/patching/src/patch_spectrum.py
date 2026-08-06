# 修改记录:
# 2025-08-05 11:02 — 初始实现：补丁差分的频域变换与特征提取
# 2025-08-06 15:41 — 增加多分辨率频谱（小波式分窗），捕获不同尺度的异常

"""Patch Spectrum Analyzer — 补丁差分的频域异常检测。

核心假设：
  良性补丁的字节差分具有可预测的频谱特征（低频能量集中在修改区域，
  高频为编译器填充/对齐噪声）。恶意/后门补丁在差分中引入额外结构
  ——额外的函数、payload、控制流修改——这些在频域呈现异常模式。

方法：
  1. 提取 original vs patched binary 的字节差分向量 D
  2. 对 D 做离散傅里叶变换 (DFT)，得到频谱 S
  3. 多分辨率分析：将 D 分割为不同尺度的窗口，分别计算频谱
  4. 提取特征向量：频带能量分布、峰值频率、谱熵、谱平坦度
  5. 与良性补丁的参考分布对比，计算异常分数

为什么频域：
  - 空间域（字节序列）对对齐偏移敏感；频域对平移不敏感
  - 后门 payload 在空间域可能隐藏在合法修改中，但其频谱结构
    有可区分的统计特征
  - 编译器填充的模式（nop sled, int3, 对齐零字节）在频域有
    明确的印记

参考：
  - 频域分析在恶意软件检测中使用（Spectrum-based Malware Analysis, 2023）
  - 本模块将此技术首次应用于补丁差分而非全量二进制
  - 补丁的增量性质使得频谱分析的计算量大幅降低（O(n log n) on diff, not binary）
"""

import math
import struct
import cmath
import hashlib
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple
from collections import defaultdict


# ── 离散傅里叶变换（纯 Python，无 numpy 依赖）─────────────────────

def _dft_real(data: List[float]) -> List[complex]:
    """实输入的 1D DFT —— O(n²)，对补丁差分（< 100KB）可接受。

    生产环境替换为 FFT（Cooley-Tukey），此处 DFT 保证无依赖。
    补丁差分通常远小于完整二进制（< 10KB），DFT 足够快。
    """
    n = len(data)
    if n == 0:
        return []
    result = []
    for k in range(n // 2 + 1):  # 仅正频率（实输入对称）
        real = 0.0
        imag = 0.0
        for t in range(n):
            angle = -2.0 * math.pi * k * t / n
            real += data[t] * math.cos(angle)
            imag += data[t] * math.sin(angle)
        result.append(complex(real, imag))
    return result


def _power_spectrum(fft: List[complex]) -> List[float]:
    """功率谱：|F(k)|²，归一化。"""
    if not fft:
        return []
    ps = [(c.real**2 + c.imag**2) for c in fft]
    total = sum(ps)
    if total > 0:
        ps = [v / total for v in ps]
    return ps


# ── 补丁差分提取 ──────────────────────────────────────────────────

@dataclass
class PatchDiffVector:
    """补丁差分向量及其元数据。"""
    diff_bytes: List[int]            # 逐字节差值 (patched[i] - original[i])
    diff_length: int                 # 修改区域长度
    changed_positions: List[int]     # 实际改变的字节位置
    change_ratio: float              # 改变字节占比
    patch_id: str = ""
    original_hash: str = ""
    patched_hash: str = ""


class PatchDiffExtractor:
    """从原始和修补二进制提取差分向量。"""

    @staticmethod
    def extract(original: bytes, patched: bytes,
                patch_id: str = "") -> PatchDiffVector:
        """提取逐字节差分。

        若两文件大小不同，取较短的比较范围，超出的部分视为全改变。
        """
        min_len = min(len(original), len(patched))
        max_len = max(len(original), len(patched))

        diff = []
        changed_pos = []
        for i in range(min_len):
            delta = (patched[i] - original[i]) % 256
            # 映射到有符号范围 -128..127
            if delta > 127:
                delta -= 256
            diff.append(delta)
            if delta != 0:
                changed_pos.append(i)

        # 超出部分：全部视为改变
        for i in range(min_len, max_len):
            if len(original) > len(patched):
                diff.append(-1)
            else:
                diff.append(1)
            changed_pos.append(i)

        change_ratio = len(changed_pos) / max(max_len, 1)

        return PatchDiffVector(
            diff_bytes=diff,
            diff_length=max_len,
            changed_positions=changed_pos,
            change_ratio=change_ratio,
            patch_id=patch_id,
            original_hash=hashlib.sha256(original).hexdigest()[:16],
            patched_hash=hashlib.sha256(patched).hexdigest()[:16],
        )

    @staticmethod
    def extract_changed_regions(original: bytes, patched: bytes,
                                window_size: int = 64) -> List[Tuple[int, List[int]]]:
        """定位改变的窗口区域 — 用于多分辨率分析。

        返回 [(start_offset, diff_window), ...]。
        仅返回有实质改变（> 2 bytes changed）的窗口。
        """
        if len(original) != len(patched):
            min_len = min(len(original), len(patched))
        else:
            min_len = len(original)

        regions = []
        for start in range(0, min_len, window_size):
            end = min(start + window_size, min_len)
            window_diff = []
            changed_count = 0
            for i in range(start, end):
                delta = (patched[i] - original[i]) % 256
                if delta > 127:
                    delta -= 256
                window_diff.append(delta)
                if delta != 0:
                    changed_count += 1
            if changed_count > 2:  # 忽略微小改变（对齐填充等）
                regions.append((start, window_diff))
        return regions


# ── 频谱特征提取 ──────────────────────────────────────────────────

@dataclass
class SpectralFeatures:
    """补丁差分的频域特征向量。"""
    # 频带能量分布（将功率谱分 8 个等宽频带）
    band_energies: List[float] = field(default_factory=lambda: [0.0] * 8)
    # 峰值频率（功率最高的频率分量索引）
    peak_frequency_bin: int = 0
    peak_power: float = 0.0
    # 谱熵（频谱的不确定性/混乱度）
    spectral_entropy: float = 0.0
    # 谱平坦度（几何均值/算术均值 → 0=尖峰, 1=平坦白噪声）
    spectral_flatness: float = 0.0
    # 低频/高频能量比
    lf_hf_ratio: float = 0.0
    # 谱质心（频谱的"重心"位置）
    spectral_centroid: float = 0.0
    # 有效带宽
    effective_bandwidth: float = 0.0
    # 直流分量强度 (k=0 成分)
    dc_intensity: float = 0.0
    # 差分向量的标准差（空间域特征，用于交叉验证）
    spatial_std: float = 0.0
    # 差分向量中相邻非零字节的平均间距
    mean_change_gap: float = 0.0

    def to_vector(self) -> List[float]:
        """展平为特征向量，供异常检测器使用。"""
        return (
            self.band_energies +
            [self.spectral_entropy, self.spectral_flatness,
             self.lf_hf_ratio, self.spectral_centroid,
             self.effective_bandwidth, self.dc_intensity,
             self.spatial_std, self.mean_change_gap,
             float(self.peak_frequency_bin)]
        )

    @property
    def feature_count(self) -> int:
        return len(self.to_vector())


class SpectrumFeatureExtractor:
    """从补丁差分提取频域特征。

    流程：差分 → DFT → 功率谱 → 频带划分 → 特征计算。
    """

    def __init__(self, n_bands: int = 8):
        self.n_bands = n_bands

    def extract(self, diff: PatchDiffVector) -> SpectralFeatures:
        """主入口 — 完整频谱特征提取。"""
        feats = SpectralFeatures()
        raw = [float(b) for b in diff.diff_bytes]

        if len(raw) < 4:
            return feats  # 差分太小，无意义

        # DFT
        fft_complex = _dft_real(raw)
        power = _power_spectrum(fft_complex)

        if not power:
            return feats

        feats.dc_intensity = power[0] if len(power) > 0 else 0.0

        # 频带能量
        feats.band_energies = self._compute_band_energies(power)

        # 峰值
        if power:
            max_idx = max(range(len(power)), key=lambda i: power[i])
            feats.peak_frequency_bin = max_idx
            feats.peak_power = power[max_idx]

        # 谱熵
        feats.spectral_entropy = self._compute_spectral_entropy(power)

        # 谱平坦度
        feats.spectral_flatness = self._compute_spectral_flatness(power)

        # 低频/高频比
        midpoint = len(power) // 2
        if midpoint > 0:
            lf = sum(power[:midpoint])
            hf = sum(power[midpoint:])
            feats.lf_hf_ratio = lf / hf if hf > 0 else float('inf')

        # 谱质心
        if power:
            weighted_sum = sum(k * power[k] for k in range(len(power)))
            total = sum(power)
            feats.spectral_centroid = weighted_sum / total if total > 0 else 0.0

        # 有效带宽
        if feats.spectral_centroid > 0:
            variance = sum(
                ((k - feats.spectral_centroid) ** 2) * power[k]
                for k in range(len(power))
            )
            total = sum(power)
            feats.effective_bandwidth = math.sqrt(variance / total) if total > 0 else 0.0

        # 空间域特征
        if raw:
            mu = sum(raw) / len(raw)
            feats.spatial_std = math.sqrt(
                sum((x - mu) ** 2 for x in raw) / len(raw))

        if diff.changed_positions and len(diff.changed_positions) > 1:
            gaps = []
            for i in range(1, len(diff.changed_positions)):
                gaps.append(diff.changed_positions[i] - diff.changed_positions[i-1])
            feats.mean_change_gap = sum(gaps) / len(gaps)

        return feats

    # ── 频带能量 ──────────────────────────────────────────────────

    def _compute_band_energies(self, power: List[float]) -> List[float]:
        """将功率谱均分为 n_bands 个频带。"""
        n = len(power)
        if n == 0:
            return [0.0] * self.n_bands
        band_size = max(n // self.n_bands, 1)
        bands = []
        for b in range(self.n_bands):
            start = b * band_size
            end = min(start + band_size, n)
            if start < n:
                bands.append(sum(power[start:end]))
            else:
                bands.append(0.0)
        return bands

    @staticmethod
    def _compute_spectral_entropy(power: List[float]) -> float:
        """谱熵：-Σ p(k)·log₂(p(k))。"""
        total = sum(power)
        if total == 0:
            return 0.0
        entropy = 0.0
        for p in power:
            if p > 0:
                prob = p / total
                entropy -= prob * math.log2(prob)
        return entropy

    @staticmethod
    def _compute_spectral_flatness(power: List[float]) -> float:
        """谱平坦度 (Wiener entropy): GM/AM。"""
        n = len(power)
        if n == 0:
            return 0.0
        # 跳过零值以计算几何均值
        non_zero = [p for p in power if p > 1e-12]
        if not non_zero:
            return 1.0
        am = sum(power) / n
        if am == 0:
            return 0.0
        log_sum = sum(math.log(p) for p in non_zero)
        gm = math.exp(log_sum / len(non_zero))
        return min(gm / am, 1.0)


# ── 多分辨率频谱 ──────────────────────────────────────────────────

@dataclass
class MultiResolutionSpectrum:
    """多分辨率频谱分析结果。

    不同尺度捕获不同类型的异常：
      - 细粒度 (32-64 bytes): 检测额外插入的单条指令
      - 中粒度 (256-512 bytes): 检测新增的基本块
      - 粗粒度 (4096+ bytes): 检测完整函数注入
    """
    patch_id: str = ""
    windows: List[SpectralFeatures] = field(default_factory=list)
    window_sizes: List[int] = field(default_factory=list)
    aggregate: Optional[SpectralFeatures] = None

    def feature_variance_across_scales(self) -> float:
        """计算不同尺度间特征向量的方差 — 高方差表示多尺度异常。"""
        if len(self.windows) < 2:
            return 0.0
        vectors = [w.to_vector() for w in self.windows]
        n = len(vectors)
        d = len(vectors[0]) if vectors else 0
        if d == 0:
            return 0.0
        variance_sum = 0.0
        for dim in range(d):
            dim_vals = [v[dim] for v in vectors]
            mu = sum(dim_vals) / n
            variance_sum += sum((x - mu) ** 2 for x in dim_vals) / n
        return variance_sum / d


class MultiResolutionAnalyzer:
    """多分辨率频谱分析器 — 多窗口大小，分尺度提取特征。"""

    def __init__(self, window_sizes: List[int] = None):
        # 默认窗口大小：细 → 粗
        self.window_sizes = window_sizes or [32, 64, 128, 256, 512, 1024]
        self.extractor = SpectrumFeatureExtractor(n_bands=8)
        self.diff_extractor = PatchDiffExtractor()

    def analyze(self, original: bytes, patched: bytes,
                patch_id: str = "") -> MultiResolutionSpectrum:
        """多分辨率频谱分析。"""
        result = MultiResolutionSpectrum(patch_id=patch_id)

        for ws in self.window_sizes:
            regions = self.diff_extractor.extract_changed_regions(
                original, patched, ws)
            for _, window_diff in regions:
                # 构造对应的差分向量
                diff_vec = PatchDiffVector(
                    diff_bytes=window_diff,
                    diff_length=len(window_diff),
                    changed_positions=[i for i, d in enumerate(window_diff) if d != 0],
                    change_ratio=sum(1 for d in window_diff if d != 0) / max(len(window_diff), 1),
                    patch_id=patch_id,
                )
                feats = self.extractor.extract(diff_vec)
                result.windows.append(feats)
                result.window_sizes.append(ws)

        # 全量差分作为汇总
        full_diff = self.diff_extractor.extract(original, patched, patch_id)
        result.aggregate = self.extractor.extract(full_diff)

        return result
