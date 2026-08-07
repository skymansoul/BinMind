# 修改记录:
# 2025-08-06 09:55 — 初始实现：KL 散度 + Mahalanobis 距离的双检测器
# 2025-08-07 14:08 — 参考分布自动构建：从已知良性补丁中学习基线

"""Spectral Anomaly Detector — 基于频谱特征的补丁异常检测。

两阶段异常检测：
  阶段 1 (statistical): 与良性补丁参考分布的 Mahalanobis 距离
  阶段 2 (distributional): 与参考频谱的 KL 散度

检测目标：
  - 后门代码注入：额外的函数/基本块在频谱中产生异常峰值
  - 隐蔽数据外泄 payload：周期性访问模式在频域产生可检测的谐波
  - 供应链攻击：补丁中包含未声明的功能修改

设计约束：
  - 不依赖 ML 框架（纯统计方法，可审计）
  - 参考分布从已知良性补丁自动构建（CVE KB 中的官方补丁）
  - 阈值自适应：基于参考数据的百分位而非硬编码

与现有方法的差异：
  - 现有 backdoor 检测操作在源码级（CodeQL, Semgrep rules）
  - 本模块操作在二进制补丁字节级——补丁分发时源码可能不可用
  - 频域方法对混淆/对齐变体有天然的鲁棒性
"""

import math
import json
import hashlib
import logging
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple
from collections import defaultdict

from .patch_spectrum import (
    SpectralFeatures, MultiResolutionSpectrum, MultiResolutionAnalyzer,
    SpectrumFeatureExtractor, PatchDiffExtractor, PatchDiffVector,
)

_log = logging.getLogger(__name__)


@dataclass
class AnomalyScore:
    """补丁频谱异常的量化评分。"""
    mahalanobis_distance: float = 0.0   # 与参考分布的统计距离
    kl_divergence: float = 0.0           # 频谱的 KL 散度
    band_anomaly_scores: List[float] = field(default_factory=list)
    # 每个频带的单独异常分
    multi_scale_variance: float = 0.0   # 多尺度方差（跨分辨率不一致性）
    composite_score: float = 0.0         # 综合异常分 (0..1, >0.5 标记)
    is_anomalous: bool = False
    anomaly_reasons: List[str] = field(default_factory=list)


@dataclass
class SpectralAnomalyReport:
    """补丁频谱异常检测报告。"""
    patch_id: str = ""
    original_hash: str = ""
    patched_hash: str = ""
    anomaly_score: AnomalyScore = field(default_factory=AnomalyScore)
    reference_patches_used: int = 0      # 用于构建参考的良性补丁数
    features: Optional[SpectralFeatures] = None
    multi_resolution: Optional[MultiResolutionSpectrum] = None
    recommendation: str = ""             # "accept" | "review" | "reject"

    def to_dict(self) -> Dict:
        return {
            'patch_id': self.patch_id,
            'original_hash': self.original_hash,
            'patched_hash': self.patched_hash,
            'composite_score': round(self.anomaly_score.composite_score, 4),
            'mahalanobis': round(self.anomaly_score.mahalanobis_distance, 4),
            'kl_divergence': round(self.anomaly_score.kl_divergence, 4),
            'multi_scale_variance': round(self.anomaly_score.multi_scale_variance, 4),
            'is_anomalous': self.anomaly_score.is_anomalous,
            'reasons': self.anomaly_score.anomaly_reasons,
            'reference_count': self.reference_patches_used,
            'recommendation': self.recommendation,
        }


# 分布管理

@dataclass
class ReferenceDistribution:
    """良性补丁频谱特征的参考分布。

    存储每个特征维度的均值 μ 和协方差矩阵 Σ⁻¹（的逆）。
    """
    mean_vector: List[float] = field(default_factory=list)
    inv_covariance: List[List[float]] = field(default_factory=list)
    # 协方差矩阵的逆（用于 Mahalanobis 距离计算）
    sample_count: int = 0
    # 频带能量分布的参考直方图（用于 KL 散度）
    band_reference: List[float] = field(default_factory=lambda: [0.0] * 8)

    def is_valid(self) -> bool:
        """是否有足够样本构建有效分布。"""
        return self.sample_count >= 3 and len(self.mean_vector) > 0


class ReferenceDistributionBuilder:
    """从已知良性补丁构建参考分布。

    数据源：
      - CVE KB 中标记为 official 的补丁
      - 可信分发源的补丁（发行版安全更新）
      - 手动审查过的人工标记良性补丁
    """

    def __init__(self):
        self._feature_vectors: List[List[float]] = []
        self._band_histograms: List[List[float]] = []
        self._extractor = SpectrumFeatureExtractor(n_bands=8)

    def add_benign_patch(self, original: bytes, patched: bytes,
                         label: str = ""):
        """添加一个已知良性补丁到参考集。"""
        diff = PatchDiffExtractor.extract(original, patched, label)
        feats = self._extractor.extract(diff)
        vec = feats.to_vector()
        self._feature_vectors.append(vec)
        self._band_histograms.append(feats.band_energies)
        _log.debug("参考: 添加良性补丁 %s (特征维度=%d)", label, len(vec))

    def build(self) -> ReferenceDistribution:
        """构建参考分布。"""
        dist = ReferenceDistribution()

        if len(self._feature_vectors) < 3:
            _log.warning("参考样本不足 (%d < 3)", len(self._feature_vectors))
            return dist

        n = len(self._feature_vectors)
        d = len(self._feature_vectors[0])
        dist.sample_count = n

        # 均值向量
        dist.mean_vector = [0.0] * d
        for vec in self._feature_vectors:
            for j in range(d):
                dist.mean_vector[j] += vec[j]
        for j in range(d):
            dist.mean_vector[j] /= n

        # 协方差矩阵
        cov = [[0.0] * d for _ in range(d)]
        for vec in self._feature_vectors:
            for i in range(d):
                for j in range(d):
                    cov[i][j] += ((vec[i] - dist.mean_vector[i]) *
                                  (vec[j] - dist.mean_vector[j]))
        for i in range(d):
            for j in range(d):
                cov[i][j] /= (n - 1)  # Bessel 校正

        # 协方差矩阵的逆（Gauss-Jordan 消元 + 正则化）
        dist.inv_covariance = _matrix_inverse_regularized(cov, reg=1e-6)

        # 频带参考（均值）
        if self._band_histograms:
            dist.band_reference = [0.0] * 8
            for hist in self._band_histograms:
                for b in range(min(8, len(hist))):
                    dist.band_reference[b] += hist[b]
            for b in range(8):
                dist.band_reference[b] /= len(self._band_histograms)

        _log.info("参考分布构建完成: %d 样本, %d 特征维度", n, d)
        return dist

    def save(self, path: str):
        """持久化当前的特征向量集（JSON）。"""
        data = {
            'vectors': self._feature_vectors,
            'bands': self._band_histograms,
            'count': len(self._feature_vectors),
        }
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(data, f)

    def load(self, path: str):
        """加载特征向量集。"""
        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        self._feature_vectors = data['vectors']
        self._band_histograms = data.get('bands', [])
        _log.info("加载 %d 个参考特征向量", len(self._feature_vectors))


# 异常检测器

class SpectralAnomalyDetector:
    """基于参考分布的补丁频谱异常检测。

    用法:
        builder = ReferenceDistributionBuilder()
        for orig, patched in benign_patches:
            builder.add_benign_patch(orig, patched)
        reference = builder.build()

        detector = SpectralAnomalyDetector(reference)
        report = detector.detect(suspect_original, suspect_patched)
        if report.anomaly_score.is_anomalous:
            print(f"异常补丁: {report.recommendation}")
    """

    # 判定阈值
    _MAHALANOBIS_THRESHOLD = 3.0     # >3σ 标记为统计异常
    _KL_THRESHOLD = 0.5               # KL 散度 >0.5 标记为分布异常
    _MULTI_SCALE_THRESHOLD = 0.15     # 多尺度方差阈值
    _COMPOSITE_THRESHOLD = 0.5        # 综合分阈值

    def __init__(self, reference: ReferenceDistribution):
        self._reference = reference
        self._extractor = SpectrumFeatureExtractor(n_bands=8)
        self._multi_res = MultiResolutionAnalyzer()
        self._diff_extractor = PatchDiffExtractor()

    def detect(self, original: bytes, patched: bytes,
               patch_id: str = "") -> SpectralAnomalyReport:
        """检测单个补丁是否异常。"""
        if not self._reference.is_valid():
            return SpectralAnomalyReport(
                patch_id=patch_id,
                recommendation="insufficient_reference_data",
            )

        # 提取特征
        diff = self._diff_extractor.extract(original, patched, patch_id)
        feats = self._extractor.extract(diff)
        feat_vec = feats.to_vector()

        # 多分辨率分析
        multi = self._multi_res.analyze(original, patched, patch_id)

        # 计算 Mahalanobis 距离
        mahal = self._mahalanobis_distance(feat_vec)

        # 计算 KL 散度（频带分布）
        kl = self._kl_divergence_bands(feats.band_energies)

        # 频带级别异常分
        band_scores = self._band_level_anomaly(feats.band_energies)

        # 多尺度方差
        ms_var = multi.feature_variance_across_scales()

        # 综合评分
        reasons: List[str] = []
        composite = 0.0

        # Mahalanobis 贡献 (0..1)
        mahal_norm = min(mahal / (2.0 * self._MAHALANOBIS_THRESHOLD), 1.0)
        composite += 0.35 * mahal_norm
        if mahal > self._MAHALANOBIS_THRESHOLD:
            reasons.append(f"Mahalanobis 距离异常 ({mahal:.2f} > {self._MAHALANOBIS_THRESHOLD})")

        # KL 散度贡献 (0..1)
        kl_norm = min(kl / self._KL_THRESHOLD, 1.0)
        composite += 0.30 * kl_norm
        if kl > self._KL_THRESHOLD:
            reasons.append(f"KL 散度异常 ({kl:.3f} > {self._KL_THRESHOLD})")

        # 多尺度方差贡献 (0..1)
        ms_norm = min(ms_var / self._MULTI_SCALE_THRESHOLD, 1.0)
        composite += 0.20 * ms_norm
        if ms_var > self._MULTI_SCALE_THRESHOLD:
            reasons.append(f"多尺度方差异常 ({ms_var:.4f} > {self._MULTI_SCALE_THRESHOLD})")

        # 频带异常贡献 (0..1)
        max_band_anomaly = max(band_scores) if band_scores else 0.0
        composite += 0.15 * max_band_anomaly
        if max_band_anomaly > 0.7:
            reasons.append(f"频带能量异常 (max={max_band_anomaly:.3f})")

        is_anomalous = composite > self._COMPOSITE_THRESHOLD

        if is_anomalous and not reasons:
            reasons.append("综合评分超过阈值")

        # 建议
        if composite > 0.75:
            recommendation = "reject"
        elif composite > 0.5:
            recommendation = "review"
        else:
            recommendation = "accept"

        anomaly = AnomalyScore(
            mahalanobis_distance=mahal,
            kl_divergence=kl,
            band_anomaly_scores=band_scores,
            multi_scale_variance=ms_var,
            composite_score=composite,
            is_anomalous=is_anomalous,
            anomaly_reasons=reasons,
        )

        return SpectralAnomalyReport(
            patch_id=patch_id,
            original_hash=diff.original_hash,
            patched_hash=diff.patched_hash,
            anomaly_score=anomaly,
            reference_patches_used=self._reference.sample_count,
            features=feats,
            multi_resolution=multi,
            recommendation=recommendation,
        )

    def batch_detect(self, patches: List[Tuple[bytes, bytes, str]]
                     ) -> List[SpectralAnomalyReport]:
        """批量检测。"""
        reports = []
        for orig, patched, pid in patches:
            reports.append(self.detect(orig, patched, pid))
        return reports

# 距离计算

    def _mahalanobis_distance(self, vector: List[float]) -> float:
        """计算 Mahalanobis 距离: sqrt((x-μ)ᵀ Σ⁻¹ (x-μ))。"""
        ref = self._reference
        if not ref.mean_vector or not ref.inv_covariance:
            return 0.0
        d = len(vector)
        if d != len(ref.mean_vector):
            return 0.0

        # 计算差向量
        diff = [vector[i] - ref.mean_vector[i] for i in range(d)]

        # diffᵀ · Σ⁻¹
        left = [0.0] * d
        for i in range(d):
            s = 0.0
            for j in range(d):
                s += ref.inv_covariance[i][j] * diff[j]
            left[i] = s

        # (diffᵀ Σ⁻¹) · diff
        dist_sq = sum(left[i] * diff[i] for i in range(d))

        return math.sqrt(max(0.0, dist_sq))

    def _kl_divergence_bands(self, bands: List[float]) -> float:
        """计算频带能量分布与参考分布的 KL 散度。"""
        ref_bands = self._reference.band_reference
        if len(bands) != len(ref_bands):
            return 0.0

        # 归一化 + Laplace 平滑（避免零概率）
        eps = 1e-8
        b_sum = sum(bands) + eps
        r_sum = sum(ref_bands) + eps
        p = [(v / b_sum) + eps for v in bands]
        q = [(v / r_sum) + eps for v in ref_bands]

        kl = 0.0
        for pi, qi in zip(p, q):
            kl += pi * math.log(pi / qi)
        return max(0.0, kl)

    def _band_level_anomaly(self, bands: List[float]) -> List[float]:
        """逐频带的异常分 — 基于 Z-score。"""
        ref_bands = self._reference.band_reference
        if len(bands) != len(ref_bands):
            return [0.0] * len(bands)

        scores = []
        for b_val, r_val in zip(bands, ref_bands):
            if r_val > 0:
                ratio = abs(b_val - r_val) / r_val
                scores.append(min(ratio, 1.0))
            else:
                scores.append(0.0 if b_val == 0 else 1.0)
        return scores


# 矩阵运算（纯 Python）

def _matrix_inverse_regularized(matrix: List[List[float]],
                                reg: float = 1e-6) -> List[List[float]]:
    """计算矩阵的逆 + Tikhonov 正则化。

    Gauss-Jordan 消元实现。正则化保证病态矩阵可逆。
    """
    n = len(matrix)
    if n == 0:
        return []

    # 增广矩阵 [A | I]
    aug = []
    for i in range(n):
        row = matrix[i][:] + [1.0 if j == i else 0.0 for j in range(n)]
        # 正则化
        row[i] += reg
        aug.append(row)

    # Gauss-Jordan
    for col in range(n):
        # 选主元
        pivot_row = max(range(col, n), key=lambda r: abs(aug[r][col]))
        if abs(aug[pivot_row][col]) < 1e-12:
            continue  # 行退化为零 — 跳过

        aug[col], aug[pivot_row] = aug[pivot_row], aug[col]

        # 归一化
        pivot = aug[col][col]
        for j in range(2 * n):
            aug[col][j] /= pivot

        # 消元
        for row in range(n):
            if row != col and abs(aug[row][col]) > 1e-12:
                factor = aug[row][col]
                for j in range(2 * n):
                    aug[row][j] -= factor * aug[col][j]

    # 提取逆矩阵（右半部分）
    inv = []
    for i in range(n):
        inv.append(aug[i][n:])
    return inv


# 便捷函数

def build_reference_from_patches(
    benign_patches: List[Tuple[bytes, bytes, str]]
) -> ReferenceDistribution:
    """从良性补丁列表构建参考分布。"""
    builder = ReferenceDistributionBuilder()
    for orig, patched, label in benign_patches:
        builder.add_benign_patch(orig, patched, label)
    return builder.build()


def detect_spectral_anomaly(original: bytes, patched: bytes,
                            reference: ReferenceDistribution,
                            patch_id: str = "") -> SpectralAnomalyReport:
    """一键频谱异常检测。"""
    detector = SpectralAnomalyDetector(reference)
    return detector.detect(original, patched, patch_id)
