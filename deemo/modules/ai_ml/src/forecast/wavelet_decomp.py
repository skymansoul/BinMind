# 小波包分解与频谱特征提取
# 用于 spectral_temporal_forecaster 的频域分析流
#
# 核心组件:
#   WaveletPacketDecomposition — db4 小波基的多层小波包分解
#   SpectralFeatureExtractor — 从分解系数提取频谱统计特征
#   CrossBandAttention — 跨频带交叉注意力机制
#
# 设计依据:
#   1. 选择db4而非Haar: db4的消失矩为4，对分段三次以下趋势分量有良好压缩效果，
#      Haar仅对常值分量有效，丢失CVE序列中的平滑趋势信息
#   2. 小波包而非标准DWT: 标准DWT仅递归分解近似分量（低频），
#      CVE时间序列的高频尖峰（零日漏洞爆发）包含关键信息，需要对全频带做均匀分辨率分解

from __future__ import annotations

import math
import logging
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field

import numpy as np

logger = logging.getLogger(__name__)


# db4 小波基

class WaveletPacketDecomposition:
    """离散小波包分解——将信号分解为等带宽的频率子带。

    与标准DWT的差异: 同时对近似和细节系数进行递归分解，
    提供全频带的均匀频率分辨率。
    """

    _DB4_LO = np.array([
        0.4829629131445341, 0.8365163037378079,
        0.2241438680420134, -0.1294095225512604
    ], dtype=np.float64)

    _DB4_HI = np.array([
        -0.1294095225512604, -0.2241438680420134,
        0.8365163037378079, -0.4829629131445341
    ], dtype=np.float64)

    _DB4_LO_R = np.array([
        -0.1294095225512604, 0.2241438680420134,
        0.8365163037378079, 0.4829629131445341
    ], dtype=np.float64)

    _DB4_HI_R = np.array([
        0.4829629131445341, -0.8365163037378079,
        0.2241438680420134, 0.1294095225512604
    ], dtype=np.float64)

    def __init__(self, max_level: int = 4):
        self.max_level = max_level

    def decompose(self, signal: np.ndarray) -> Dict[str, np.ndarray]:
        orig_len = len(signal)
        padded_len = 1
        while padded_len < orig_len:
            padded_len <<= 1
        data = np.array(signal, dtype=np.float64)
        if orig_len < padded_len:
            data = np.pad(data, (0, padded_len - orig_len), mode='reflect')

        nodes: Dict[str, np.ndarray] = {'': data.copy()}
        full_tree: Dict[str, np.ndarray] = {}

        for level in range(self.max_level):
            next_nodes = {}
            for path, coeffs in nodes.items():
                lo, hi = self._single_level_decomp(coeffs)
                next_nodes[path + 'L'] = lo
                next_nodes[path + 'H'] = hi
            full_tree.update(next_nodes)
            nodes = next_nodes

        if not full_tree:
            full_tree.update(nodes)

        ratio = orig_len / padded_len
        for key in full_tree:
            target_len = max(1, int(len(full_tree[key]) * ratio))
            full_tree[key] = full_tree[key][:target_len]

        return full_tree

    def _single_level_decomp(self, data: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        n = len(data)
        if n < 4:
            return data.copy()[:max(1, n//2)], data.copy()[:max(1, n//2)]
        lo = np.convolve(data, self._DB4_LO[::-1], mode='same')
        hi = np.convolve(data, self._DB4_HI[::-1], mode='same')
        return lo[::2], hi[::2]

    def reconstruct(self, coefficients: Dict[str, np.ndarray],
                    target_len: int) -> np.ndarray:
        max_depth = max(len(k) for k in coefficients.keys()) if coefficients else 0
        leaf_keys = [k for k in coefficients if len(k) == max_depth]
        if not leaf_keys:
            leaf_keys = list(coefficients.keys())
        reconstructions = []
        for key in leaf_keys:
            signal = self._reconstruct_single(coefficients[key], key, target_len)
            reconstructions.append(signal)
        return np.sum(reconstructions, axis=0) / max(1, len(reconstructions))

    def _reconstruct_single(self, coeffs: np.ndarray, path: str,
                            target_len: int) -> np.ndarray:
        data = coeffs.copy()
        for ch in reversed(path):
            data = self._single_level_recon(data, ch)
        if len(data) > target_len:
            data = data[:target_len]
        elif len(data) < target_len:
            data = np.pad(data, (0, target_len - len(data)), mode='edge')
        return data

    def _single_level_recon(self, data: np.ndarray, band: str) -> np.ndarray:
        n = len(data)
        upsampled = np.zeros(n * 2, dtype=np.float64)
        upsampled[::2] = data
        filt = self._DB4_LO_R if band == 'L' else self._DB4_HI_R
        return np.convolve(upsampled, filt[::-1], mode='same')


# 频谱特征提取

@dataclass
class SpectralFeatures:
    band_energies: Dict[str, float]
    band_entropies: Dict[str, float]
    cross_band_correlations: Dict[Tuple[str, str], float]
    dominant_frequency_band: str
    spectral_flatness: float
    transient_ratio: float
    n_levels: int

    def to_vector(self) -> np.ndarray:
        vec = []
        sorted_bands = sorted(self.band_energies.keys())
        for band in sorted_bands:
            vec.append(self.band_energies.get(band, 0.0))
            vec.append(self.band_entropies.get(band, 0.0))
        vec.append(self.spectral_flatness)
        vec.append(self.transient_ratio)
        return np.array(vec, dtype=np.float64)


class SpectralFeatureExtractor:

    @staticmethod
    def extract(coefficients: Dict[str, np.ndarray]) -> SpectralFeatures:
        band_energies = {}
        band_entropies = {}
        total_energy = 0.0

        for key, coeffs in coefficients.items():
            energy = float(np.sum(coeffs ** 2))
            band_energies[key] = energy
            total_energy += energy
            if len(coeffs) > 1:
                hist, _ = np.histogram(coeffs, bins=min(20, len(coeffs)//2 + 1), density=True)
                entropy = -np.sum(hist * np.log(hist + 1e-12))
                band_entropies[key] = float(entropy)
            else:
                band_entropies[key] = 0.0

        dominant = max(band_energies, key=band_energies.get) if band_energies else ""
        mean_energy = total_energy / max(1, len(band_energies))
        if mean_energy > 1e-12 and len(band_energies) > 1:
            log_energies = [math.log(max(e, 1e-12)) for e in band_energies.values()]
            geo_mean = math.exp(sum(log_energies) / len(log_energies))
            flatness = geo_mean / mean_energy
        else:
            flatness = 1.0

        hf_energy = sum(e for k, e in band_energies.items()
                       if k.startswith('HH') or k.endswith('HH'))
        transient_ratio = hf_energy / max(1e-12, total_energy)

        cross_corr = {}
        bands = sorted(coefficients.keys())
        for i in range(len(bands)):
            for j in range(i + 1, len(bands)):
                a, b = coefficients[bands[i]], coefficients[bands[j]]
                min_len = min(len(a), len(b))
                if min_len > 1:
                    corr = np.corrcoef(a[:min_len], b[:min_len])[0, 1]
                    if not np.isnan(corr):
                        cross_corr[(bands[i], bands[j])] = float(corr)

        return SpectralFeatures(
            band_energies=band_energies,
            band_entropies=band_entropies,
            cross_band_correlations=cross_corr,
            dominant_frequency_band=dominant,
            spectral_flatness=flatness,
            transient_ratio=transient_ratio,
            n_levels=max(len(k) for k in coefficients.keys()) if coefficients else 0,
        )


# 跨频带注意力

class CrossBandAttention:
    """跨频带交叉注意力。

    与标准自注意力的差异:
      - 输入按频带分组，attention在频带间而非时间步间执行
      - 对数间距的位置编码模拟频率轴的几何关系:
        低频带间距大（重要），高频带间距小
      - 残差连接 + 软阈值抑制弱相关频带间的噪声
    """

    def __init__(self, n_bands: int, band_dim: int = 8, n_heads: int = 4):
        self.n_bands = n_bands
        self.band_dim = band_dim
        self.n_heads = n_heads
        self.head_dim = band_dim // n_heads
        self._pos_encoding = self._build_positional_encoding(n_bands, band_dim)
        rng = np.random.RandomState(42)
        scale = math.sqrt(2.0 / band_dim)
        self.W_q = rng.randn(band_dim, band_dim) * scale
        self.W_k = rng.randn(band_dim, band_dim) * scale
        self.W_v = rng.randn(band_dim, band_dim) * scale
        self.W_o = rng.randn(band_dim, band_dim) * scale

    @staticmethod
    def _build_positional_encoding(n_bands: int, dim: int) -> np.ndarray:
        pe = np.zeros((n_bands, dim), dtype=np.float64)
        log_positions = np.log2(np.arange(1, n_bands + 1) + 1)
        for i in range(n_bands):
            for j in range(0, dim, 2):
                omega = 1.0 / (10000.0 ** (j / dim))
                pe[i, j] = math.sin(log_positions[i] * omega)
                if j + 1 < dim:
                    pe[i, j + 1] = math.cos(log_positions[i] * omega)
        return pe

    def forward(self, band_features: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        x = band_features + self._pos_encoding[:self.n_bands, :]
        Q = x @ self.W_q
        K = x @ self.W_k
        V = x @ self.W_v
        scale = math.sqrt(self.band_dim)
        attn_scores = Q @ K.T / scale
        attn_scores = np.where(np.abs(attn_scores) < 0.1, -1e9, attn_scores)
        attn_weights = self._softmax(attn_scores, axis=-1)
        output = attn_weights @ V
        output = output @ self.W_o + x
        return output, attn_weights

    @staticmethod
    def _softmax(x: np.ndarray, axis: int = -1) -> np.ndarray:
        x_max = np.max(x, axis=axis, keepdims=True)
        exp_x = np.exp(x - x_max)
        return exp_x / (np.sum(exp_x, axis=axis, keepdims=True) + 1e-12)
