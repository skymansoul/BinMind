"""
路径多样性引导的符号执行探索器。
路径爆炸时按轻量统计特征为活跃路径排序，优先探索与已探索路径差异最大的
方向，避免把求解预算浪费在语义相似路径上（特征向量无需约束求解即可计算）。
"""


import hashlib
import logging
import math
from typing import Any, Dict, List, Optional, Set, Tuple

_log = logging.getLogger(__name__)


class PathDiversityExplorer:
    """基于统计特征的路径多样性探索器：维护已探索路径特征库，
    按新颖度+潜在增益排序活跃路径；不依赖angr约束求解器，
    特征提取只需路径元数据。"""

    def __init__(
        self,
        feature_dim: int = 8,
        diversity_weight: float = 0.6,
        novelty_threshold: float = 0.15,
        max_explored_features: int = 1000,
    ):
        """
        feature_dim 特征维度, diversity_weight 优先级中多样性权重(0-1),
        novelty_threshold 新颖度阈值, max_explored_features 特征库容量(FIFO)。
        """
        self.feature_dim = feature_dim
        self.diversity_weight = diversity_weight
        self.novelty_threshold = novelty_threshold

        self._explored_features: List[List[float]] = []
        self._max_features = max_explored_features

        self._active_paths: Dict[str, Dict[str, Any]] = {}

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
        注册活跃路径及其元数据: 分支历史哈希序列/调用深度/符号变量数/
        基本块数/未探索后继数, 并计算轻量特征向量。
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
        标记路径为已探索并加入特征库；超出容量时淘汰最旧条目(FIFO)。
        """
        if path_id not in self._active_paths:
            return

        features = self._active_paths[path_id]["features"]
        self._explored_features.append(features)
        if len(self._explored_features) > self._max_features:
            self._explored_features.pop(0)

        del self._active_paths[path_id]

    def remove_path(self, path_id: str) -> None:
        """移除活跃路径（如判定不可满足被丢弃）。"""
        self._active_paths.pop(path_id, None)

    def compute_priorities(self) -> List[Tuple[str, float]]:
        """
        计算全部活跃路径的综合优先级,
        返回 [(path_id, priority_score)] 按优先级降序排列。
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
        按优先级选取前 k 条路径; 低于新颖度阈值的路径视为已充分
        探索自动跳过 (仅记录不移除), 返回路径 ID 列表。
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
                # 低新颖度路径: 仅记录不自动移除, 由调用方决定
                _log.debug("Path %s below novelty threshold (%.3f)", pid, novelty)

        return selected

    def is_stagnating(self, window: int = 50) -> bool:
        """
        检查探索是否停滞：最近`window`条路径的平均新颖度低于阈值时
        返回True。调用方应增加随机探索权重或切换探索策略。
        """
        if len(self._explored_features) < window:
            return False

        recent = self._explored_features[-window:]
        if len(recent) < 2:
            return False

        # 计算近期特征的两两余弦距离均值
        total_dist = 0.0
        pairs = 0
        for i in range(len(recent)):
            for j in range(i + 1, min(i + 5, len(recent))):
                total_dist += 1.0 - _cosine_sim(recent[i], recent[j])
                pairs += 1

        avg_dist = total_dist / max(1, pairs)
        return avg_dist < self.novelty_threshold

    def active_count(self) -> int:
        return len(self._active_paths)

    def explored_count(self) -> int:
        return len(self._explored_features)


_BRANCH_HISTORY_BITS = 32


def _extract_features(
    branch_history: List[int],
    call_depth: int,
    sym_var_count: int,
    block_count: int,
    dim: int,
) -> List[float]:
    """
    将路径元数据压缩为定维特征向量:
      [0] 归一化分支历史哈希
      [1] 历史长度/最大长度
      [2] 调用深度/最大深度
      [3] 符号变量数/最大数
      [4] 基本块数/最大数
      [5] 分支熵(历史中唯一分支占比)
      [6-7] 哈希高低16位(捕捉细粒度差异)
    """
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

    # 补齐或截断到目标维度
    while len(features) < dim:
        features.append(0.0)
    return features[:dim]


def _compute_novelty(
    features: List[float],
    explored_library: List[List[float]],
) -> float:
    """
    计算特征向量相对已探索库的新颖度:
    新颖度 = 1 - max(cosine_sim(features, explored_i))，即到最近已探索
    特征的余弦距离。库为空时返回1.0。
    """
    if not explored_library or not features:
        return 1.0

    max_sim = max(
        _cosine_sim(features, ef)
        for ef in explored_library[-200:]  # only consider most recent 200
    )
    return round(1.0 - max_sim, 4)


def _cosine_sim(a: List[float], b: List[float]) -> float:
    """余弦相似度，返回[-1, 1]；越接近1越相似。"""
    if len(a) != len(b) or len(a) == 0:
        return 0.0

    dot = sum(x * y for x, y in zip(a, b))
    norm_a = math.sqrt(sum(x * x for x in a))
    norm_b = math.sqrt(sum(y * y for y in b))

    if norm_a < 1e-10 or norm_b < 1e-10:
        return 0.0
    return dot / (norm_a * norm_b)


def _branch_potential(unexplored_successors: int) -> float:
    """未探索后继的潜在增益，sigmoid归一化到[0, 1]。"""
    x = max(0, unexplored_successors)
    return 2.0 / (1.0 + math.exp(-x / 2.0)) - 1.0
