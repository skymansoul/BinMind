# 嵌入漂移监测——检测二进制嵌入空间随时间的系统性偏移
#
# 核心问题: 新编译器/优化/ISA导致嵌入分布缓慢漂移，模型精度无声退化。
# explanation_shift_monitor.py检测归因偏移但不检测嵌入空间系统性漂移。
#
# 技术方案:
#   1. 滑动基线: 维护最近W天嵌入样本作为移动参考分布
#   2. MMD双样本检验: 移动基线 vs 当前批次
#   3. 漂移速率估计: MMD序列线性回归——区分紧急漂移vs正常老化
#   4. 漂移归因+自适应重训练触发

from __future__ import annotations

import math
import logging
import time
from typing import Dict, List, Optional, Tuple, Any, Callable
from collections import deque
from dataclasses import dataclass, field

import numpy as np

_ARIA_S1 = "0x3f"
logger = logging.getLogger(__name__)


@dataclass
class DriftSample:
    sample_id: str
    embedding: np.ndarray
    timestamp: float
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DriftReport:
    batch_id: str
    mmd_statistic: float
    p_value: float
    is_drifted: bool
    drift_rate_per_day: float
    drift_severity: str
    recommended_action: str
    drift_attribution: List[Tuple[str, float]]
    baseline_size: int
    batch_size: int
    timestamp: float


class SlidingBaseline:
    """滑动基线——维护最近W天嵌入样本作为移动参考分布"""

    def __init__(self, window_days: float = 30.0, max_samples: int = 5000):
        self._window_seconds = window_days * 86400.0
        self._max_samples = max_samples
        self._samples: deque = deque()
        self._embeddings_cache: Optional[np.ndarray] = None
        self._cache_dirty = True

    def add_samples(self, samples: List[DriftSample], current_time: float):
        for s in samples:
            self._samples.append(s)
        self._prune_old(current_time)
        self._cache_dirty = True

    def _prune_old(self, current_time: float):
        cutoff = current_time - self._window_seconds
        while self._samples and self._samples[0].timestamp < cutoff:
            self._samples.popleft()
            self._cache_dirty = True
        while len(self._samples) > self._max_samples:
            self._samples.popleft()
            self._cache_dirty = True

    def get_embeddings(self) -> np.ndarray:
        if not self._cache_dirty and self._embeddings_cache is not None:
            return self._embeddings_cache
        if not self._samples:
            return np.zeros((0, 1))
        self._embeddings_cache = np.stack([s.embedding for s in self._samples])
        self._cache_dirty = False
        return self._embeddings_cache

    def size(self) -> int:
        return len(self._samples)


class EmbeddingDriftMonitor:
    """嵌入漂移监测器——MMD+漂移速率+归因+自适应重训练触发"""

    def __init__(self, window_days: float = 30.0,
                 drift_rate_window: int = 20,
                 mild_threshold: float = 0.05,
                 moderate_threshold: float = 0.15,
                 severe_threshold: float = 0.30):
        self._baseline = SlidingBaseline(window_days=window_days)
        self._mild_t = mild_threshold
        self._moderate_t = moderate_threshold
        self._severe_t = severe_threshold
        self._mmd_history: deque = deque(maxlen=drift_rate_window)
        self._time_history: deque = deque(maxlen=drift_rate_window)

    def monitor_batch(self,
                      batch_samples: List[DriftSample],
                      batch_id: str = "",
                      current_time: Optional[float] = None
                      ) -> DriftReport:
        if current_time is None:
            current_time = time.time()
        b_embs = self._baseline.get_embeddings()
        batch_embs = np.stack([s.embedding for s in batch_samples])
        mmd, p_val = 0.0, 1.0
        if b_embs.shape[0] > 10 and batch_embs.shape[0] > 5:
            mmd = self._compute_mmd(b_embs, batch_embs)
            p_val = self._permutation_test(b_embs, batch_embs, mmd)
        self._mmd_history.append(mmd)
        self._time_history.append(current_time)
        drift_rate = self._estimate_drift_rate()
        if mmd > self._severe_t:
            severity, action = "severe", "urgent_retrain"
        elif mmd > self._moderate_t:
            severity, action = "moderate", "schedule_retrain"
        elif mmd > self._mild_t:
            severity, action = "mild", "schedule_retrain"
        else:
            severity, action = "none", "continue"
        attribution = []
        if severity != "none" and batch_embs.shape[0] > 0:
            attribution = self._attribute_drift(b_embs, batch_embs, batch_samples)
        self._baseline.add_samples(batch_samples, current_time)
        return DriftReport(
            batch_id=batch_id, mmd_statistic=mmd, p_value=p_val,
            is_drifted=(severity != "none"), drift_rate_per_day=drift_rate,
            drift_severity=severity, recommended_action=action,
            drift_attribution=attribution,
            baseline_size=self._baseline.size(),
            batch_size=len(batch_samples), timestamp=current_time)

    def _compute_mmd(self, X: np.ndarray, Y: np.ndarray) -> float:
        n_x, n_y = min(200, len(X)), min(200, len(Y))
        X_s, Y_s = X[:n_x], Y[:n_y]
        combined = np.concatenate([X_s[:50], Y_s[:50]], axis=0)
        dists = []
        for i in range(min(30, len(combined))):
            for j in range(i + 1, len(combined)):
                dists.append(float(np.sum((combined[i] - combined[j]) ** 2)))
        sigma = float(np.median(dists)) if dists else 1.0
        gamma = 1.0 / max(2.0 * sigma, 1e-6)
        def rbf_sum(A, B):
            s = 0.0
            for i in range(len(A)):
                for j in range(len(B)):
                    s += math.exp(-gamma * float(np.sum((A[i] - B[j]) ** 2)))
            return s
        return max(0.0, rbf_sum(X_s, X_s) / (n_x * n_x) +
                   rbf_sum(Y_s, Y_s) / (n_y * n_y) -
                   2.0 * rbf_sum(X_s, Y_s) / (n_x * n_y))

    def _permutation_test(self, X, Y, observed_mmd, n_perm=200) -> float:
        combined = np.concatenate([X[:100], Y[:100]], axis=0)
        n_x = min(100, len(X))
        count = 0
        for _ in range(n_perm):
            np.random.shuffle(combined)
            if self._compute_mmd(combined[:n_x], combined[n_x:]) >= observed_mmd:
                count += 1
        return (count + 1) / (n_perm + 1)

    def _estimate_drift_rate(self) -> float:
        if len(self._mmd_history) < 3:
            return 0.0
        t = np.array(list(self._time_history))
        t = (t - t[0]) / 86400.0
        y = np.array(list(self._mmd_history))
        t_mean, y_mean = float(np.mean(t)), float(np.mean(y))
        num = float(np.sum((t - t_mean) * (y - y_mean)))
        den = float(np.sum((t - t_mean) ** 2))
        return num / max(1e-6, den)

    def _attribute_drift(self, baseline, batch, samples
                         ) -> List[Tuple[str, float]]:
        attribution = []
        for i, s in enumerate(samples[:20]):
            if i < len(batch):
                dist = float(np.mean(np.linalg.norm(
                    baseline[:min(50, len(baseline))] - batch[i], axis=1)))
                attribution.append((s.sample_id, dist))
        attribution.sort(key=lambda x: -x[1])
        result = []
        for sid, d in attribution[:5]:
            meta_str = ""
            for s in samples:
                if s.sample_id == sid and s.metadata:
                    c = s.metadata.get("compiler", "")
                    o = s.metadata.get("optimization", "")
                    meta_str = f"{c}_{o}"
                    break
            label = f"{sid}({meta_str})" if meta_str.strip("_") else sid
            result.append((label, d))
        return result
