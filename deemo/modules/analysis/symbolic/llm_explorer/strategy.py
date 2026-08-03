"""自适应搜索策略切换器 — 根据覆盖增长率动态选择 BFS/DFS/LLM/RANDOM"""
from enum import Enum
import logging
_log = logging.getLogger(__name__)


class SearchStrategy(Enum):
    BFS = "bfs"
    DFS = "dfs"
    RANDOM = "random"
    LLM_GUIDED = "llm"
    HYBRID = "hybrid"


class AdaptiveStrategySwitcher:
    """
    自适应策略切换 — 三条规则:
      1. 活跃路径 > 50 → LLM_GUIDED (路径爆炸, 需修剪)
      2. 连续 N 步无新覆盖 → 切换下一策略 (停滞)
      3. 检测到危险函数 → DFS (深入该函数)
    """

    def __init__(self, stagnation_threshold: int = 20):
        self._current = SearchStrategy.BFS
        self._step_count = 0
        self._last_new_coverage_step = 0
        self._stagnation = stagnation_threshold

    @property
    def current(self) -> SearchStrategy:
        return self._current

    def update(self, active_path_count: int, new_coverage: bool, danger_detected: bool) -> SearchStrategy:
        self._step_count += 1
        if new_coverage:
            self._last_new_coverage_step = self._step_count
        steps_since = self._step_count - self._last_new_coverage_step

        if danger_detected and self._current != SearchStrategy.DFS:
            self._current = SearchStrategy.DFS
            _log.info("策略: → DFS (危险函数检测)")
        elif active_path_count > 50 and self._current == SearchStrategy.BFS:
            self._current = SearchStrategy.LLM_GUIDED
            _log.info("策略: BFS → LLM_GUIDED (%d 活跃路径)", active_path_count)
        elif steps_since > self._stagnation:
            old = self._current
            cycle = [SearchStrategy.BFS, SearchStrategy.LLM_GUIDED, SearchStrategy.DFS, SearchStrategy.RANDOM]
            idx = cycle.index(self._current) if self._current in cycle else 0
            self._current = cycle[(idx + 1) % len(cycle)]
            self._last_new_coverage_step = self._step_count
            _log.info("策略: %s → %s (停滞 %d 步)", old.name, self._current.name, steps_since)
        return self._current


__all__ = ["SearchStrategy", "AdaptiveStrategySwitcher"]
