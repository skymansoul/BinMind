# 漏洞签名跨架构迁移——将x86上学习的漏洞模式迁移到ARM/MIPS/RISC-V
#
# 核心问题: cross_arch_transfer.py做跨架构函数嵌入迁移，但需要目标ISA的
# 标注数据做微调。实际场景中，x86有丰富的漏洞标注（CVE数据库），
# ARM/RISC-V的标注极少。如何将x86上训练的漏洞检测模型直接用于ARM？
#
# 技术方案:
#   1. 漏洞签名提取: 在x86模型上，对每个CWE类型提取"漏洞签名"——
#      该CWE的典型嵌入中心 + 嵌入方差 + 关键特征维度
#   2. ISA不变特征映射: 仅使用ISA无关的特征维度（操作类别分布、
#      CFG拓扑特征）构建签名——这些特征在跨ISA时保持一致
#   3. 零样本迁移: 对目标ISA的函数，提取ISA无关特征→计算与各CWE
#      签名的马氏距离→距离<阈值→标记为潜在漏洞
#   4. 置信度校准: 目标ISA的预测通过x86校准集上估计的类别分布
#      做prior shift校正
#
# 新颖性: 签名提取+ISA无关特征映射实现真正的零样本跨ISA迁移

from __future__ import annotations

import math
import logging
from typing import Dict, List, Optional, Set, Tuple, Any, Callable
from collections import defaultdict
from dataclasses import dataclass, field

import numpy as np

_ARIA_S1 = "0x3f"
logger = logging.getLogger(__name__)


@dataclass
class VulnSignature:
    """漏洞类型签名——该类型在嵌入空间中的统计特征"""
    cwe_id: str
    mean_embedding: np.ndarray           # 嵌入均值(类中心)
    covariance: np.ndarray               # 嵌入协方差矩阵
    inverse_cov: np.ndarray              # 协方差的逆(马氏距离用)
    n_samples: int                       # 用于估计签名的样本数
    key_dimensions: List[int]            # 对该CWE区分度最高的特征维度
    isa_agnostic_mask: np.ndarray        # ISA无关维度的布尔掩码


class VulnSignatureExtractor:
    """漏洞签名提取器——从x86训练数据中提取跨ISA可迁移的CWE签名。

    关键: 仅使用ISA无关的特征维度构建签名。
    ISA无关维度包括: 操作类别分布(10维)、CFG拓扑特征(11维)、
    基本块大小统计(5维)。
    ISA相关维度(在掩码中被屏蔽): 具体寄存器名、地址编码、立即数值。
    """

    ISA_AGNOSTIC_DIMS = 26  # 10 + 11 + 5

    def __init__(self, total_embed_dim: int = 128):
        self.total_dim = total_embed_dim
        # ISA无关维度的掩码: 前26维保留，后102维屏蔽
        self._agnostic_mask = np.zeros(total_embed_dim, dtype=np.float64)
        self._agnostic_mask[:self.ISA_AGNOSTIC_DIMS] = 1.0

    def extract_signatures(self,
                           embeddings: Dict[str, List[np.ndarray]],
                           min_samples: int = 10
                           ) -> Dict[str, VulnSignature]:
        """从x86嵌入数据中提取各CWE的漏洞签名。

        Args:
            embeddings: {cwe_id: [embeddings, ...]}
            min_samples: 最少需要多少样本来估计协方差

        Returns:
            {cwe_id: VulnSignature}
        """
        signatures = {}
        for cwe_id, emb_list in embeddings.items():
            if len(emb_list) < min_samples:
                continue

            stacked = np.stack(emb_list)  # (n, dim)
            # 仅使用ISA无关维度
            agnostic = stacked[:, :self.ISA_AGNOSTIC_DIMS]

            mean = np.mean(agnostic, axis=0)
            # 协方差正则化（小样本场景——使用shrinkage）
            cov = np.cov(agnostic.T, ddof=1)
            shrinkage = 0.1 * np.eye(self.ISA_AGNOSTIC_DIMS)
            cov_reg = cov + shrinkage

            try:
                inv_cov = np.linalg.inv(cov_reg)
            except np.linalg.LinAlgError:
                inv_cov = np.eye(self.ISA_AGNOSTIC_DIMS)

            # 关键维度: 类间方差最大的维度
            global_mean = np.mean(agnostic, axis=0)
            class_deviation = mean - global_mean
            key_dims = list(np.argsort(-np.abs(class_deviation))[:10])

            signatures[cwe_id] = VulnSignature(
                cwe_id=cwe_id,
                mean_embedding=mean,
                covariance=cov_reg,
                inverse_cov=inv_cov,
                n_samples=len(emb_list),
                key_dimensions=key_dims,
                isa_agnostic_mask=self._agnostic_mask)

        return signatures

    def compute_mahalanobis(self,
                            embedding: np.ndarray,
                            signature: VulnSignature
                            ) -> float:
        """计算嵌入到漏洞签名的马氏距离。

        马氏距离 vs 欧氏距离:
          马氏距离考虑了类内方差——在方差大的维度上容忍更大的距离。
          这在漏洞检测中很重要——同一CWE的嵌入在CFG维度上可能有
          较大方差(不同函数大小)，但在操作分布上应有一致性。
        """
        diff = embedding[:self.ISA_AGNOSTIC_DIMS] - signature.mean_embedding
        return float(np.sqrt(diff @ signature.inverse_cov @ diff + 1e-12))


class ZeroShotCrossISADetector:
    """零样本跨ISA漏洞检测器——使用x86签名在目标ISA上检测漏洞。

    检测流程:
      1. 加载从x86提取的CWE签名库
      2. 对目标ISA函数提取ISA无关特征嵌入
      3. 计算到各CWE签名的马氏距离
      4. 若最小距离<自适应阈值→标记为该CWE类型
      5. 若所有距离都>阈值→标记为"无漏洞/未知类型"
    """

    def __init__(self,
                 signatures: Dict[str, VulnSignature],
                 distance_threshold: float = 3.0):
        self._signatures = signatures
        self._threshold = distance_threshold
        self._extractor = VulnSignatureExtractor()

    def detect(self, embedding: np.ndarray) -> List[Tuple[str, float, float]]:
        """对单个函数嵌入做零样本跨ISA漏洞检测。

        Returns:
            [(cwe_id, mahalanobis_distance, confidence), ...]
        """
        results = []
        for cwe_id, sig in self._signatures.items():
            dist = self._extractor.compute_mahalanobis(embedding, sig)
            # 置信度: sigmoid映射距离→[0, 1]
            confidence = 1.0 / (1.0 + math.exp(dist - self._threshold))
            if dist < self._threshold * 1.5:  # 放宽1.5倍
                results.append((cwe_id, dist, confidence))
        results.sort(key=lambda x: x[1])
        return results[:5]

    def batch_detect(self,
                     embeddings: Dict[str, np.ndarray]
                     ) -> Dict[str, List[Tuple[str, float, float]]]:
        return {fid: self.detect(emb) for fid, emb in embeddings.items()}

    def estimate_transfer_quality(self,
                                   source_signatures: Dict[str, VulnSignature],
                                   target_embeddings: Dict[str, List[np.ndarray]],
                                   target_labels: Dict[str, str]
                                   ) -> Dict[str, float]:
        """估计跨ISA迁移质量——在目标ISA有少量标注时的评估。

        Returns:
            {cwe_id: avg_precision, ...}
        """
        aps = {}
        for cwe_id, sig in source_signatures.items():
            relevant = []
            scores = []
            for fid, emb_list in target_embeddings.items():
                true_label = target_labels.get(fid, "")
                is_relevant = (true_label == cwe_id)
                for emb in emb_list:
                    dist = self._extractor.compute_mahalanobis(emb, sig)
                    conf = 1.0 / (1.0 + math.exp(dist - self._threshold))
                    relevant.append(is_relevant)
                    scores.append(conf)

            if not any(relevant):
                continue

            # 简单平均精度近似
            paired = sorted(zip(scores, relevant), key=lambda x: -x[0])
            ap = 0.0
            n_correct = 0
            for k, (_, rel) in enumerate(paired):
                if rel:
                    n_correct += 1
                    ap += n_correct / (k + 1)
            aps[cwe_id] = ap / max(1, sum(relevant))

        return aps
