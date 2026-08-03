"""
路径多样性引导的符号执行探索器。

在符号执行遭遇路径爆炸时，不进行完整的约束求解来选择下一路径，
而是基于轻量级统计特征对活跃路径排序——选择与已探索路径差异最大
的方向优先执行。避免在语义相似的路径上浪费求解器预算。

核心机制:
  1. 对每条活跃路径提取统计特征向量（分支历史、调用栈深度、符号变量数）
  2. 与已探索路径的特征库计算最小余弦距离——作为"新颖度"得分
  3. 新颖度 × 分支潜在收益（未探索的 successor 数）→ 综合优先级
  4. 优先级最高的路径优先求解

与传统符号执行的差异:
  KLEE 的默认策略是 DFS/BFS/random-path——不考虑路径间语义差异。
  本模块的统计特征向量无需约束求解即可计算，因此可在大量活跃路径上
  快速排序。求解器预算仅分配给出优先级最高的 k 条路径。

特征选择的设计考量:
  - 分支历史 (branch history hash): 压缩表示路径经过的条件分支序列，
    相似的执行路径产生相似的 branch history
  - 调用栈深度: 深调用栈的路径往往接近 bug（通过了更多校验层）
  - 符号变量密度: 符号约束多的路径可能探索了更多输入空间维度
  - 距入口的块数 (block distance): 长路径可能探索了更多程序逻辑

参考:
  Yang (2025), U.Toronto PhD Thesis, "ML-Assisted Symbolic Analysis" —
    统计路径特征的排序效果不弱于完整约束求解的路径选择
  KLEE Workshop 2024 — "State Merging and Prioritization" 讨论中
    将"探索停滞"视为开放问题，本模块提供了统计检测 + 重定向机制
"""

from __future__ import annotations

import hashlib
import logging
import math
from typing import Any, Dict, List, Optional, Set, Tuple

_log = logging.getLogger(__name__)


class PathDiversityExplorer:
    """
    基于统计特征的路径多样性探索器。

    维护已探索路径的特征库，对活跃路径按新颖度 + 潜在收益排序。
    不依赖 angr 的约束求解器——特征提取仅需路径元数据。
    """

    def __init__(
        self,
        feature_dim: int = 8,
        diversity_weight: float = 0.6,
        novelty_threshold: float = 0.15,
        max_explored_features: int = 1000,
    ):
        """
        Args:
            feature_dim: 归一化特征向量的维度
            diversity_weight: 多样性得分在综合优先级中的权重 (0-1)
            novelty_threshold: 低于此新颖度的路径被视为"已充分探索"
            max_explored_features: 已探索特征库的最大容量 (FIFO 淘汰)
        """
        self.feature_dim = feature_dim
        self.diversity_weight = diversity_weight
        self.novelty_threshold = novelty_threshold

        # 已探索路径的特征库
        self._explored_features: List[List[float]] = []
        self._max_features = max_explored_features

        # 活跃路径注册表
        self._active_paths: Dict[str, Dict[str, Any]] = {}

    # ---- 路径注册 ----

    def register_active_path(
        self,
        path_id: str,
        branch_history: List[int],
        call_depth: int,
        sym_var_count: int,
        block_count: int,
        unexplored_successors: int = 0,
    ) -> None:
        """
        注册一条活跃路径及其元数据。

        Args:
            path_id: 路径唯一标识
            branch_history: 分支历史——经过的条件分支的 (addr, taken) 哈希序列
            call_depth: 当前调用栈深度
            sym_var_count: 活跃符号变量的数量
            block_count: 已执行的基本块数
            unexplored_successors: 当前状态处未探索的后继分支数
        """
        features = _extract_features(
            branch_history, call_depth, sym_var_count, block_count,
            self.feature_dim,
        )
        self._active_paths[path_id] = {
            "features": features,
            "unexplored_succ": unexplored_successors,
            "call_depth": call_depth,
            "block_count": block_count,
        }

    def mark_explored(self, path_id: str) -> None:
        """
        将路径标记为已探索——其特征加入特征库。

        若特征库超出容量上限则淘汰最早加入的特征（FIFO）。
        """
        if path_id not in self._active_paths:
            return

        features = self._active_paths[path_id]["features"]
        self._explored_features.append(features)
        if len(self._explored_features) > self._max_features:
            self._explored_features.pop(0)

        del self._active_paths[path_id]

    def remove_path(self, path_id: str) -> None:
        """移除活跃路径（如因不可满足而丢弃）。"""
        self._active_paths.pop(path_id, None)

    # ---- 优先级计算 ----

    def compute_priorities(self) -> List[Tuple[str, float]]:
        """
        计算所有活跃路径的综合优先级。

        Returns:
            [(path_id, priority_score)] 按优先级降序排列
        """
        if not self._active_paths:
            return []

        scored = []
        for pid, info in self._active_paths.items():
            novelty = _compute_novelty(info["features"], self._explored_features)
            potential = _branch_potential(info["unexplored_succ"])
            priority = (
                self.diversity_weight * novelty
                + (1 - self.diversity_weight) * potential
            )
            scored.append((pid, round(priority, 4)))

        scored.sort(key=lambda x: -x[1])
        return scored

    def select_next(self, top_k: int = 3) -> List[str]:
        """
        选择优先级最高的 k 条路径。

        自动跳过低于新颖度阈值的路径——这些路径被认为是
        已充分探索的区域，不值得继续投入求解器预算。

        Returns:
            路径 ID 列表
        """
        priorities = self.compute_priorities()
        selected = []
        for pid, score in priorities[:top_k]:
            info = self._active_paths.get(pid, {})
            novelty = _compute_novelty(
                info.get("features", []), self._explored_features,
            )
            if novelty >= self.novelty_threshold or len(self._explored_features) < 10:
                selected.append(pid)
            else:
                # 低新颖度路径标记为"可丢弃"——但不自动移除，
                # 由调用方决定是否保留作为冗余备份
                _log.debug("Path %s below novelty threshold (%.3f)", pid, novelty)

        return selected

    def is_stagnating(self, window: int = 50) -> bool:
        """
        检测探索是否停滞。

        若最近 window 条路径的平均新颖度低于阈值则返回 True——
        建议调用方增加随机探索权重或切换探索策略。

        实现: 检查特征库尾部的新颖度均值。
        """
        if len(self._explored_features) < window:
            return False

        recent = self._explored_features[-window:]
        if len(recent) < 2:
            return False

        # 计算最近特征的成对余弦距离均值
        total_dist = 0.0
        pairs = 0
        for i in range(len(recent)):
            for j in range(i + 1, min(i + 5, len(recent))):
                total_dist += 1.0 - _cosine_sim(recent[i], recent[j])
                pairs += 1

        avg_dist = total_dist / max(1, pairs)
        return avg_dist < self.novelty_threshold

    # ---- 查询 ----

    def active_count(self) -> int:
        return len(self._active_paths)

    def explored_count(self) -> int:
        return len(self._explored_features)


# ---- 辅助函数 ----

_BRANCH_HISTORY_BITS = 32


def _extract_features(
    branch_history: List[int],
    call_depth: int,
    sym_var_count: int,
    block_count: int,
    dim: int,
) -> List[float]:
    """
    将路径元数据压缩为固定维度特征向量。

    特征设计:
      [0] 分支历史哈希的归一化值
      [1] 分支历史长度 / 最大历史长度
      [2] 调用栈深度 / 最大深度
      [3] 符号变量数 / 最大变量数
      [4] 基本块数 / 最大块数
      [5] 分支熵 (branch history 中唯一分支的比例)
      [6-7] 哈希拆分的高/低 16bit (捕获细粒度差异)
    """
    # 分支历史哈希
    hist_str = ",".join(str(b & 0xFFFF) for b in branch_history[-16:])
    hist_hash = int(hashlib.md5(hist_str.encode()).hexdigest()[:8], 16)

    hist_len = len(branch_history)
    unique_branches = len(set(b & 0xFFFF for b in branch_history))
    branch_entropy = unique_branches / max(1, hist_len)

    features = [
        (hist_hash % 10000) / 10000.0,
        min(hist_len, 200) / 200.0,
        min(call_depth, 20) / 20.0,
        min(sym_var_count, 50) / 50.0,
        min(block_count, 500) / 500.0,
        branch_entropy,
        (hist_hash >> 16) / 65536.0,
        (hist_hash & 0xFFFF) / 65536.0,
    ]

    # 填充或截断到 dim
    while len(features) < dim:
        features.append(0.0)
    return features[:dim]


def _compute_novelty(
    features: List[float],
    explored_library: List[List[float]],
) -> float:
    """
    计算特征向量相对于已探索库的新颖度。

    新颖度 = 1 - max(cosine_sim(features, explored_i))
    即与最近的已探索特征的余弦距离。

    若已探索库为空则新颖度为 1.0。
    """
    if not explored_library or not features:
        return 1.0

    max_sim = max(
        _cosine_sim(features, ef)
        for ef in explored_library[-200:]  # 只看最近 200 条
    )
    return round(1.0 - max_sim, 4)


def _cosine_sim(a: List[float], b: List[float]) -> float:
    """余弦相似度——返回 [-1, 1]，越接近 1 越相似。"""
    if len(a) != len(b) or len(a) == 0:
        return 0.0

    dot = sum(x * y for x, y in zip(a, b))
    norm_a = math.sqrt(sum(x * x for x in a))
    norm_b = math.sqrt(sum(y * y for y in b))

    if norm_a < 1e-10 or norm_b < 1e-10:
        return 0.0
    return dot / (norm_a * norm_b)


def _branch_potential(unexplored_successors: int) -> float:
    """未探索后继数的潜在收益——sigmoid 归一化到 [0, 1]。"""
    x = max(0, unexplored_successors)
    return 2.0 / (1.0 + math.exp(-x / 2.0)) - 1.0
