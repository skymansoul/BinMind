# 神经分支预测驱动的模糊测试种子优先级排序
#
# 核心问题: 现有种子优先级方案（包括本模块的ai_path_prioritizer.py）
# 基于静态启发式（危险API密度、循环深度惩罚），完全忽略输入与执行路径的
# 动态关系。一个种子是否"好"取决于能否触发新的深层基本块。
#
# 技术方案:
#   1. 轻量神经分支模型: 种子字节统计 → 分支触发概率预测
#   2. 不确定性引导: 预测熵越高的种子越优先（未充分探索区域）
#   3. 在线更新: 每轮用实际分支覆盖更新模型，持续适应目标程序
#   4. 字节归因: 高贡献字节→低突变率，低贡献字节→可激进变异
#
# 模型和特征提取实现在 src/fuzz/branch_model.py

from __future__ import annotations

import math
import logging
from typing import Dict, List, Optional, Set, Tuple, Any, Callable

import numpy as np

from .src.fuzz.branch_model import (
    SeedFeatures, SeedFeatureExtractor, NeuralBranchModel,
)

logger = logging.getLogger(__name__)


class NeuralSeedPrioritizer:
    """基于神经分支预测不确定性的模糊测试种子优先级排序器。

    调度策略:
      优先: 预测不确定性高的种子（落在未充分探索的输入区域）
      突变指导: 高归因字节保留（低突变率），低归因字节可激进变异
      在线适应: 每batch更新模型
    """

    def __init__(self, n_branches: int = 256,
                 uncertainty_weight: float = 0.6,
                 diversity_weight: float = 0.4):
        self._model = NeuralBranchModel(n_branches=n_branches)
        self._extractor = SeedFeatureExtractor()
        self._uncert_weight = uncertainty_weight
        self._diversity_weight = diversity_weight
        self._coverage_history: List[Set[int]] = []
        self._update_count = 0

    def rank_seeds(self,
                   seeds: List[bytes],
                   seed_ids: Optional[List[str]] = None
                   ) -> List[Tuple[int, float, float]]:
        """按优先级降序排列种子。"""
        if seed_ids is None:
            seed_ids = [f"seed_{i}" for i in range(len(seeds))]
        scored = []
        for idx, seed_bytes in enumerate(seeds):
            feat = self._extractor.extract(seed_bytes, seed_ids[idx])
            input_vec = feat.to_input_vector()
            uncertainty = self._model.prediction_uncertainty(input_vec)
            diversity = self._compute_diversity(seed_bytes)
            priority = (self._uncert_weight * uncertainty +
                       self._diversity_weight * diversity)
            scored.append((idx, priority, uncertainty))
        scored.sort(key=lambda x: -x[1])
        return scored

    def _compute_diversity(self, seed_bytes: bytes) -> float:
        if not self._coverage_history:
            return 1.0
        current_set = set(seed_bytes)
        if not current_set:
            return 0.0
        min_jaccard = 1.0
        for hist_set in self._coverage_history[-10:]:
            if not hist_set:
                continue
            inter = len(current_set & hist_set)
            union = len(current_set | hist_set)
            min_jaccard = min(min_jaccard, inter / max(1, union))
        return 1.0 - min_jaccard

    def update_with_coverage(self, seed_bytes: bytes,
                             branch_coverage: List[int]):
        """用实际执行的分支覆盖在线更新模型"""
        feat = self._extractor.extract(seed_bytes)
        input_vec = feat.to_input_vector()
        observed = np.zeros(self._model.n_branches, dtype=np.float64)
        for branch_id in branch_coverage:
            observed[branch_id % self._model.n_branches] = 1.0

        lr_decay = 0.99 ** self._update_count
        self._model.update(input_vec, observed, lr_decay)

        self._coverage_history.append(set(seed_bytes))
        if len(self._coverage_history) > 50:
            self._coverage_history = self._coverage_history[-50:]
        self._update_count += 1

    def get_mutation_guidance(self, seed_bytes: bytes) -> Dict[int, float]:
        """字节级突变指导。"""
        attributions = self._model.byte_attribution(seed_bytes, self._extractor)
        if not attributions:
            return {}
        max_attr = max(attributions.values()) if attributions else 1.0
        guidance = {}
        for offset, importance in attributions.items():
            normalized = importance / max(0.01, max_attr)
            guidance[offset] = max(0.10, 1.0 - normalized * 0.9)
        return guidance
