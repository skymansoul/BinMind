"""Path diversity tracking for anti-explosion in symbolic execution.

Path explosion is constrained by selecting maximally dissimilar paths.
Pairwise similarity is computed across structural, semantic,
constraint, and coverage feature dimensions. Paths are clustered by a
similarity threshold, and representatives are selected from each cluster
to maximize exploration diversity.
"""

import logging
import time
import hashlib
import threading
import random
from typing import Dict, Any, List, Optional, Set
from dataclasses import dataclass, field
from collections import defaultdict

logger = logging.getLogger(__name__)


class DiversityStrategy:
    """Selection strategies for picking the next diverse path."""
    RANDOM = "random"
    ROUND_ROBIN = "round_robin"
    SIMILARITY_BASED = "similarity_based"
    COVERAGE_GUIDED = "coverage_guided"
    HYBRID = "hybrid"


class PathFeatureType:
    """Dimensions along which path similarity is measured."""
    STRUCTURAL = "structural"
    SEMANTIC = "semantic"
    CONSTRAINTS = "constraints"
    COVERAGE = "coverage"


@dataclass
class PathFeature:
    """Feature vector for one path, with a similarity cache for memoization."""
    path_id: str
    features: Dict = field(default_factory=dict)
    similarity_cache: Dict = field(default_factory=dict)
    timestamp: float = 0.0

    def compute_hash(self) -> str:
        """Deterministic hash from sorted feature items."""
        return hashlib.sha256(str(sorted(self.features.items())).encode()).hexdigest()[:16]


@dataclass
class PathNode:
    """A node in the path exploration tree."""
    path_id: str
    address: int
    constraints: List = field(default_factory=list)
    depth: int = 0
    visited: bool = False
    timestamp: float = 0.0
    parent_id: Optional[str] = None
    children: List = field(default_factory=list)
    feature: Optional[PathFeature] = None


@dataclass
class DiversityMetrics:
    """Aggregate diversity statistics for the current path set."""
    total_paths: int = 0
    unique_paths: int = 0
    avg_similarity: float = 0.0
    diversity_score: float = 0.0
    coverage_gain: float = 0.0
    exploration_efficiency: float = 0.0


class PathSimilarityCalculator:
    """Weighted multi-dimensional similarity between two PathFeatures.

    Weights (configurable):
      STRUCTURAL: 0.3  — depth, constraint count, path hash
      SEMANTIC:   0.3  — presence of comparisons, arithmetic, bitwise ops
      CONSTRAINTS:0.2  — raw constraint text
      COVERAGE:   0.2  — hit counts
    """

    def __init__(self, weights: Dict[PathFeatureType, float] = None):
        self._weights = weights or {
            PathFeatureType.STRUCTURAL: 0.3,
            PathFeatureType.SEMANTIC: 0.3,
            PathFeatureType.CONSTRAINTS: 0.2,
            PathFeatureType.COVERAGE: 0.2
        }

    def compute(self, feature1: PathFeature, feature2: PathFeature) -> float:
        """Weighted average similarity across all feature dimensions."""
        if not feature1.features or not feature2.features:
            return 0.0

        total_sim = 0.0
        weight_sum = 0.0

        for feature_type, weight in self._weights.items():
            key = feature_type.value
            f1 = feature1.features.get(key, {})
            f2 = feature2.features.get(key, {})
            sim = self._feature_similarity(f1, f2)
            total_sim += sim * weight
            weight_sum += weight

        return total_sim / max(1, weight_sum)

    def _feature_similarity(self, f1: Dict[str, Any], f2: Dict[str, Any]) -> float:
        """Per-dimension similarity: averages Jaccard for sets, prefix match
        for strings, and normalized distance for numerics."""
        if not f1 or not f2:
            return 0.0

        common_keys = set(f1.keys()) & set(f2.keys())
        if not common_keys:
            return 0.0

        total_sim = 0.0
        for key in common_keys:
            v1, v2 = f1[key], f2[key]
            if isinstance(v1, str) and isinstance(v2, str):
                total_sim += self._string_similarity(v1, v2)
            elif isinstance(v1, (int, float)) and isinstance(v2, (int, float)):
                total_sim += self._numeric_similarity(v1, v2)
            elif isinstance(v1, set) and isinstance(v2, set):
                total_sim += len(v1 & v2) / max(1, len(v1 | v2))

        return total_sim / len(common_keys)

    def _string_similarity(self, s1: str, s2: str) -> float:
        """Prefix character match ratio — a fast, crude string similarity."""
        if s1 == s2:
            return 1.0
        min_len = min(len(s1), len(s2))
        if min_len == 0:
            return 0.0
        matches = sum(c1 == c2 for c1, c2 in zip(s1, s2))
        return matches / min_len

    def _numeric_similarity(self, n1: float, n2: float) -> float:
        """1 - normalized absolute difference."""
        if n1 == n2:
            return 1.0
        return 1.0 - abs(n1 - n2) / max(1, abs(n1), abs(n2))


class PathDiversityTracker:
    """Maintains path clusters keyed by a representative. New paths are
    assigned to the cluster whose representative is most similar, or form
    a new cluster if below the similarity threshold."""

    def __init__(self, similarity_threshold: float = 0.8):
        self._paths: Dict[str, PathNode] = {}
        self._features: Dict[str, PathFeature] = {}
        self._similarity_calculator = PathSimilarityCalculator()
        self._similarity_threshold = similarity_threshold
        self._clusters: Dict[str, List[str]] = defaultdict(list)
        self._lock = threading.RLock()

    def add_path(self, path_id: str, address: int, constraints: List[str],
                 depth: int = 0, parent_id: Optional[str] = None):
        """Register a path, extract its features, and assign it to a cluster."""
        with self._lock:
            if path_id in self._paths:
                return

            feature = self._extract_features(path_id, constraints, depth)
            self._features[path_id] = feature

            node = PathNode(
                path_id=path_id,
                address=address,
                constraints=constraints,
                depth=depth,
                parent_id=parent_id,
                feature=feature,
                timestamp=time.time()
            )
            self._paths[path_id] = node

            if parent_id and parent_id in self._paths:
                self._paths[parent_id].children.append(path_id)

            self._update_clusters(path_id)

    def _extract_features(self, path_id: str, constraints: List[str], depth: int) -> PathFeature:
        """Build the four-dimensional feature vector for a path."""
        structural = {
            'depth': depth,
            'constraint_count': len(constraints),
            'path_hash': hashlib.sha256(str(constraints).encode()).hexdigest()
        }

        semantic = {
            'has_comparison': any(('>' in c or '<' in c or '==' in c) for c in constraints),
            'has_arithmetic': any(('+' in c or '-' in c or '*' in c) for c in constraints),
            'has_bitwise': any(('&' in c or '|' in c or '^' in c) for c in constraints)
        }

        return PathFeature(
            path_id=path_id,
            features={
                PathFeatureType.STRUCTURAL.value: structural,
                PathFeatureType.SEMANTIC.value: semantic,
                PathFeatureType.CONSTRAINTS.value: {'constraints': constraints},
                PathFeatureType.COVERAGE.value: {'hits': 1}
            },
            timestamp=time.time()
        )

    def _update_clusters(self, path_id: str):
        """Assign path to the nearest cluster, or create a new one."""
        new_feature = self._features[path_id]
        assigned = False

        for cluster_id, members in self._clusters.items():
            if not members:
                continue
            representative = self._features.get(members[0])
            if representative:
                sim = self._similarity_calculator.compute(new_feature, representative)
                if sim >= self._similarity_threshold:
                    self._clusters[cluster_id].append(path_id)
                    assigned = True
                    break

        if not assigned:
            self._clusters[path_id] = [path_id]

    def find_diverse_paths(self, count: int = 5) -> List[str]:
        """Return one representative from each of `count` random clusters."""
        with self._lock:
            cluster_representatives = [members[0] for members in self._clusters.values() if members]
            return random.sample(cluster_representatives, min(count, len(cluster_representatives)))

    def is_path_diverse(self, path_id: str) -> bool:
        """True if this path's similarity to every other path is below the threshold."""
        with self._lock:
            if path_id not in self._features:
                return True

            target_feature = self._features[path_id]
            for other_id, other_feature in self._features.items():
                if other_id == path_id:
                    continue
                sim = self._similarity_calculator.compute(target_feature, other_feature)
                if sim >= self._similarity_threshold:
                    return False
            return True

    def get_similar_paths(self, path_id: str, threshold: float = 0.7) -> List[str]:
        """Return all paths similar to the given one, sorted by similarity descending."""
        with self._lock:
            if path_id not in self._features:
                return []

            target_feature = self._features[path_id]
            similar = []
            for other_id, other_feature in self._features.items():
                if other_id == path_id:
                    continue
                sim = self._similarity_calculator.compute(target_feature, other_feature)
                if sim >= threshold:
                    similar.append((other_id, sim))

            return [p[0] for p in sorted(similar, key=lambda x: -x[1])]

    def get_metrics(self) -> DiversityMetrics:
        """Compute aggregate diversity statistics for the current path set."""
        with self._lock:
            if not self._features:
                return DiversityMetrics()

            total_paths = len(self._paths)
            unique_paths = len(self._clusters)

            similarities = []
            features = list(self._features.values())
            for i in range(len(features)):
                for j in range(i + 1, len(features)):
                    sim = self._similarity_calculator.compute(features[i], features[j])
                    similarities.append(sim)

            avg_similarity = sum(similarities) / max(1, len(similarities)) if similarities else 0.0
            diversity_score = 1.0 - avg_similarity

            return DiversityMetrics(
                total_paths=total_paths,
                unique_paths=unique_paths,
                avg_similarity=avg_similarity,
                diversity_score=diversity_score,
                coverage_gain=unique_paths / max(1, total_paths),
                exploration_efficiency=diversity_score * (unique_paths / max(1, total_paths))
            )


class DiversityAwarePathSelector:
    """Selects the next path to explore using a configured diversity strategy.
    Delegates to DiversityStrategy variants: random, round-robin,
    similarity-based, coverage-guided, or hybrid (adaptive switching)."""

    def __init__(self, strategy: DiversityStrategy = DiversityStrategy.HYBRID):
        self._strategy = strategy
        self._diversity_tracker = PathDiversityTracker()
        self._path_queue: List[str] = []
        self._visited: Set[str] = set()
        self._lock = threading.RLock()
        self._round_robin_index = 0

    def add_path(self, path_id: str, address: int, constraints: List[str],
                 depth: int = 0, parent_id: Optional[str] = None):
        """Register a path candidate for future selection."""
        with self._lock:
            self._diversity_tracker.add_path(path_id, address, constraints, depth, parent_id)
            if path_id not in self._path_queue:
                self._path_queue.append(path_id)

    def select_next(self) -> Optional[str]:
        """Pick the next path according to the active strategy."""
        with self._lock:
            if not self._path_queue:
                return None

            candidates = [p for p in self._path_queue if p not in self._visited]
            if not candidates:
                return None

            if self._strategy == DiversityStrategy.RANDOM:
                return self._select_random(candidates)
            elif self._strategy == DiversityStrategy.ROUND_ROBIN:
                return self._select_round_robin(candidates)
            elif self._strategy == DiversityStrategy.SIMILARITY_BASED:
                return self._select_similarity_based(candidates)
            elif self._strategy == DiversityStrategy.COVERAGE_GUIDED:
                return self._select_coverage_guided(candidates)
            else:
                return self._select_hybrid(candidates)

    def _select_random(self, candidates: List[str]) -> str:
        """Uniform random selection from unvisited candidates."""
        path = random.choice(candidates)
        self._visited.add(path)
        return path

    def _select_round_robin(self, candidates: List[str]) -> str:
        """Cyclic selection: each candidate gets a turn in order."""
        index = self._round_robin_index % len(candidates)
        self._round_robin_index += 1
        path = candidates[index]
        self._visited.add(path)
        return path

    def _select_similarity_based(self, candidates: List[str]) -> str:
        """Select a path from the most diverse cluster representatives."""
        diverse = self._diversity_tracker.find_diverse_paths(len(candidates))
        if diverse:
            path = random.choice(diverse)
            self._visited.add(path)
            return path
        return self._select_random(candidates)

    def _select_coverage_guided(self, candidates: List[str]) -> str:
        """Select the shallowest (least-depth) path first."""
        depths = [(p, self._diversity_tracker._paths[p].depth) for p in candidates]
        depths.sort(key=lambda x: x[1])
        path = depths[0][0]
        self._visited.add(path)
        return path

    def _select_hybrid(self, candidates: List[str]) -> str:
        """Adaptive: use similarity-based when diversity is low,
        coverage-guided when coverage gain is low, otherwise round-robin."""
        metrics = self._diversity_tracker.get_metrics()

        if metrics.diversity_score < 0.5:
            return self._select_similarity_based(candidates)
        elif metrics.coverage_gain < 0.7:
            return self._select_coverage_guided(candidates)
        else:
            return self._select_round_robin(candidates)

    def mark_visited(self, path_id: str):
        """Mark a path as visited without selecting it."""
        with self._lock:
            self._visited.add(path_id)

    def get_diversity_metrics(self) -> DiversityMetrics:
        """Return current diversity metrics from the tracker."""
        return self._diversity_tracker.get_metrics()

    def get_stats(self) -> Dict[str, Any]:
        """Return selector-level statistics."""
        metrics = self.get_diversity_metrics()
        return {
            'strategy': self._strategy.value,
            'pending_paths': len(self._path_queue) - len(self._visited),
            'visited_paths': len(self._visited),
            'total_paths': len(self._path_queue),
            'diversity_score': metrics.diversity_score,
            'avg_similarity': metrics.avg_similarity,
            'unique_clusters': metrics.unique_paths
        }


class DynamicPathExplorator:
    """Top-level exploration driver. Accepts path candidates, selects them
    via a DiversityAwarePathSelector, and simulates exploration."""

    def __init__(self, strategy: str = "hybrid"):
        try:
            self._strategy = DiversityStrategy(strategy.lower())
        except ValueError:
            self._strategy = DiversityStrategy.HYBRID

        self._selector = DiversityAwarePathSelector(self._strategy)
        self._running = False
        self._exploration_count = 0
        self._max_explorations = 1000

    def add_path_candidate(self, path_id: str, address: int, constraints: List[str],
                           depth: int = 0, parent_id: Optional[str] = None):
        """Feed a path into the selector's candidate pool."""
        self._selector.add_path(path_id, address, constraints, depth, parent_id)

    def explore(self, iterations: int = 50) -> Dict[str, Any]:
        """Run the exploration loop for a fixed number of iterations."""
        explored = []
        for _ in range(iterations):
            if self._exploration_count >= self._max_explorations:
                break

            path_id = self._selector.select_next()
            if path_id is None:
                break

            result = self._explore_path(path_id)
            explored.append(result)
            self._exploration_count += 1

        return {
            'success': True,
            'explored_paths': len(explored),
            'total_explorations': self._exploration_count,
            'stats': self._selector.get_stats()
        }

    def _explore_path(self, path_id: str) -> Dict[str, Any]:
        """Simulate exploring a single path."""
        time.sleep(random.uniform(0.05, 0.2))
        return {
            'path_id': path_id,
            'status': 'explored',
            'new_constraints': random.randint(0, 5),
            'new_branches': random.randint(0, 3)
        }

    def get_stats(self) -> Dict[str, Any]:
        """Return exploration-level statistics."""
        return {
            'explorations': self._exploration_count,
            **self._selector.get_stats()
        }


def run_path_diversity_exploration(
    strategy: str = "hybrid",
    iterations: int = 50,
    path_count: int = 20
) -> Dict[str, Any]:
    """One-shot: generate a synthetic path population, explore with the chosen
    diversity strategy, return stats."""
    explorator = DynamicPathExplorator(strategy=strategy)

    for i in range(path_count):
        explorator.add_path_candidate(
            path_id=f"path_{i}",
            address=0x1000 + i * 0x10,
            constraints=[f"x{i} > 0", f"y{i} < 100"],
            depth=i % 5,
            parent_id=f"path_{i-1}" if i > 0 else None
        )

    result = explorator.explore(iterations=iterations)
    result['final_stats'] = explorator.get_stats()
    return result
