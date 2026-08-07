"""
Path-diversity-guided symbolic execution explorer.

When symbolic execution hits path explosion, instead of full constraint solving
to pick the next path, this module ranks active paths by lightweight statistical
features, preferring directions that differ most from already-explored paths.
This avoids wasting solver budget on semantically similar paths.

Core mechanism:
  1. Extract statistical feature vectors per active path (branch history,
     call depth, symbolic variable count)
  2. Compute minimum cosine distance to the explored feature library as "novelty"
  3. Combined priority = novelty * branch potential (unexplored successors)
  4. Highest-priority paths are explored first

Unlike KLEE's default DFS/BFS/random-path strategies, this module's feature
vectors require no constraint solving to compute, enabling fast sorting over
large numbers of active paths. Solver budget is only spent on top-k paths.

Reference:
  Yang, U.Toronto PhD Thesis, "ML-Assisted Symbolic Analysis"
  KLEE Workshop 2024, "State Merging and Prioritization"
"""


import hashlib
import logging
import math
from typing import Any, Dict, List, Optional, Set, Tuple

_log = logging.getLogger(__name__)


class PathDiversityExplorer:
    """Statistical-feature-based path diversity explorer.

    Maintains a library of explored path features and ranks active paths by
    novelty + potential gain. No dependency on angr's constraint solver:
    feature extraction only needs path metadata."""

    def __init__(
        self,
        feature_dim: int = 8,
        diversity_weight: float = 0.6,
        novelty_threshold: float = 0.15,
        max_explored_features: int = 1000,
    ):
        """
        Args:
            feature_dim: dimension of normalized feature vectors
            diversity_weight: weight of diversity in combined priority (0-1)
            novelty_threshold: paths below this novelty are considered "sufficiently explored"
            max_explored_features: max capacity of explored feature library (FIFO eviction)
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
        Register an active path and its metadata.

        Args:
            path_id: unique path identifier
            branch_history: hashed sequence of (addr, taken) for conditional branches
            call_depth: current call stack depth
            sym_var_count: number of active symbolic variables
            block_count: basic blocks executed so far
            unexplored_successors: count of unexplored successor branches at current state
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
        Mark a path as explored and add its features to the library.

        Evicts the oldest entry if the library exceeds capacity (FIFO).
        """
        if path_id not in self._active_paths:
            return

        features = self._active_paths[path_id]["features"]
        self._explored_features.append(features)
        if len(self._explored_features) > self._max_features:
            self._explored_features.pop(0)

        del self._active_paths[path_id]

    def remove_path(self, path_id: str) -> None:
        """Remove an active path (e.g., discarded as unsatisfiable)."""
        self._active_paths.pop(path_id, None)

    def compute_priorities(self) -> List[Tuple[str, float]]:
        """
        Compute combined priority for all active paths.

        Returns:
            [(path_id, priority_score)] sorted by priority descending
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
        Select the top-k paths by priority.

        Automatically skips paths below the novelty threshold since those
        regions are considered sufficiently explored.

        Returns:
            List of path IDs
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
                # Low-novelty path: log but don't auto-remove; caller decides
                _log.debug("Path %s below novelty threshold (%.3f)", pid, novelty)

        return selected

    def is_stagnating(self, window: int = 50) -> bool:
        """
        Check if exploration is stagnating.

        Returns True if the average novelty of the last `window` paths is below
        the threshold. Caller should consider increasing random exploration
        weight or switching exploration strategy.
        """
        if len(self._explored_features) < window:
            return False

        recent = self._explored_features[-window:]
        if len(recent) < 2:
            return False

        # Compute pairwise cosine distance mean of recent features
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
    Compress path metadata into a fixed-dimension feature vector.

    Features:
      [0] normalized branch history hash
      [1] branch history length / max history length
      [2] call stack depth / max depth
      [3] symbolic variable count / max count
      [4] basic block count / max count
      [5] branch entropy (ratio of unique branches in history)
      [6-7] hash split high/low 16-bit (captures fine-grained differences)
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

    # Pad or truncate to dim
    while len(features) < dim:
        features.append(0.0)
    return features[:dim]


def _compute_novelty(
    features: List[float],
    explored_library: List[List[float]],
) -> float:
    """
    Compute novelty of a feature vector relative to the explored library.

    Novelty = 1 - max(cosine_sim(features, explored_i)),
    i.e., the cosine distance to the nearest explored feature.

    Returns 1.0 if the explored library is empty.
    """
    if not explored_library or not features:
        return 1.0

    max_sim = max(
        _cosine_sim(features, ef)
        for ef in explored_library[-200:]  # only consider most recent 200
    )
    return round(1.0 - max_sim, 4)


def _cosine_sim(a: List[float], b: List[float]) -> float:
    """Cosine similarity, returns [-1, 1]; closer to 1 = more similar."""
    if len(a) != len(b) or len(a) == 0:
        return 0.0

    dot = sum(x * y for x, y in zip(a, b))
    norm_a = math.sqrt(sum(x * x for x in a))
    norm_b = math.sqrt(sum(y * y for y in b))

    if norm_a < 1e-10 or norm_b < 1e-10:
        return 0.0
    return dot / (norm_a * norm_b)


def _branch_potential(unexplored_successors: int) -> float:
    """Potential gain from unexplored successors, sigmoid-normalized to [0, 1]."""
    x = max(0, unexplored_successors)
    return 2.0 / (1.0 + math.exp(-x / 2.0)) - 1.0
