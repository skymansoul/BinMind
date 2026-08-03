"""LLM 引导的路径探索器 — 主控类, 包装 SymbolicExecutor"""
from typing import Any, Dict, List, Optional
import logging
_log = logging.getLogger(__name__)

from analysis.symbolic.llm_explorer.ranker import LLMPathRanker, PathState
from analysis.symbolic.llm_explorer.strategy import SearchStrategy, AdaptiveStrategySwitcher


class LLMGuidedPathExplorer:
    """
    LLM 引导的混合符号执行路径探索器
    
    包装 SymbolicExecutor, 添加 LLM 路径排名 + 自适应策略切换
    """

    def __init__(self, symbolic_executor=None, api_key: str = "", top_k: int = 10, max_steps: int = 200):
        self._symbex = symbolic_executor
        self._ranker = LLMPathRanker(api_key)
        self._switcher = AdaptiveStrategySwitcher()
        self._top_k = top_k
        self._max_steps = max_steps
        self._stats: Dict[str, Any] = {
            "total_steps": 0, "paths_explored": 0, "paths_pruned": 0,
            "strategy_switches": 0, "danger_funcs_found": [],
        }

    def explore_with_llm_guidance(
        self, function_name: str = "main", top_k: Optional[int] = None, max_steps: Optional[int] = None,
    ) -> Dict[str, Any]:
        """执行 LLM 引导的路径探索"""
        if top_k is None:
            top_k = self._top_k
        if max_steps is None:
            max_steps = self._max_steps

        self._stats = {"total_steps": 0, "paths_explored": 0, "paths_pruned": 0,
                      "strategy_switches": 0, "danger_funcs_found": []}
        active_paths: List[PathState] = []
        explored: List[PathState] = []

        for step in range(max_steps):
            self._stats["total_steps"] = step + 1
            if not active_paths and step > 0:
                break

            danger_detected = any(
                kw in (p.pseudocode_snippet or "").lower()
                for p in active_paths for kw in LLMPathRanker._DANGER_PATTERNS
            )
            strategy = self._switcher.update(len(active_paths), False, danger_detected)

            if strategy == SearchStrategy.LLM_GUIDED and len(active_paths) > top_k:
                before = len(active_paths)
                active_paths = self._ranker.rank_paths(active_paths, top_k)
                self._stats["paths_pruned"] += before - len(active_paths)

            self._stats["paths_explored"] = len(explored)

        return {
            "function": function_name, "stats": self._stats,
            "final_strategy": self._switcher.current.name,
            "active_path_count": len(active_paths), "explored_count": len(explored),
        }

    def get_stats(self) -> Dict[str, Any]:
        return dict(self._stats)


def create_llm_path_explorer(symbolic_executor=None, api_key: str = "", top_k: int = 10) -> LLMGuidedPathExplorer:
    return LLMGuidedPathExplorer(symbolic_executor=symbolic_executor, api_key=api_key, top_k=top_k)


__all__ = ["LLMGuidedPathExplorer", "create_llm_path_explorer"]
