#!/usr/bin/env python3
"""
LLM-guided exploration 适配器 — bridges llm_explorer/ SymbolicExecutor

Architecture:
- Composition over inheritance: LLMGuidedExplorer wraps llm_explorer's
LLMGuidedPathExplorer SymbolicExecutor collaborators
- PathRanker适配器 StrategySwitcher适配器 translate
executor's state representation llm_explorer's PathState model

Edge cases:
- LLM API unavailable, 适配器 falls back heuristic ranking
(built LLMPathRanker)
- SymbolicExecutor initialized, lazy-init first explore

Time complexity:
- explore_with_guidance(): O(max_steps * (step_time + ranking_time))
Ranking O(P * 记录 P) for P active paths heuristic mode
O(P + API_延迟) LLM mode
"""
# from collections import OrderedDict  # python3.7+不需要了
from __future__ import annotations

import logging
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

_log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# PathRanker适配器
# ---------------------------------------------------------------------------

class PathRankerAdapter:
    """
    Adapts llm_explorer's LLMPathRanker SymbolicExecutor's state interface
    
    转换 SymbolicState objects PathState objects ranker
    consume. 处理 batch ranking 配置urable top-K
    
    INTJ策略: rank 50 states per batch stay LLM
    context limits keep 延迟 sub-1-second for heuristic mode
    For larger workloads, 使用 舍入-robin batching
    """

    def __init__(self, api_key: str = "", model: str = ""):
        from analysis.symbolic.llm_explorer.ranker import LLMPathRanker
        self._ranker = LLMPathRanker(api_key=api_key, model=model) if model else LLMPathRanker(api_key=api_key)

    def rank_states(
        self,
        states: List[Any],
        top_k: int = 10,
    ) -> List[Any]:
        """
        Rank SymbolicState objects LLM interest score 返回 top-K
        
        转换 SymbolicState PathState, ranks, 返回
        corresponding original states rank order
        
        Time: O(S * conversion + ranking). Space: O(S)
        
        Trade-off: Conversion overhead minimal (field copying)
        real cost LLM API 延迟 (~200-500ms per batch)
        """
        if not states:
            return []

        from analysis.symbolic.llm_explorer.ranker import PathState

        path_states: List[PathState] = []
        state_map: Dict[str, Any] = {}

        for s in states:
            sid = str(getattr(s, 'state_id', 0))
            ps = PathState(
                state_id=sid,
                address=getattr(s, 'pc', 0),
                depth=getattr(s, 'depth', 0),
                constraints_count=len(getattr(s, 'path_constraints', [])),
                func_name=getattr(s, 'metadata', {}).get('func_name', ''),
                raw_state=s,
            )
            path_states.append(ps)
            state_map[sid] = s

        ranked_paths = self._ranker.rank_paths(path_states, top_k)

        # Map back original states, preserving order
        result = []
        for rp in ranked_paths:
            if rp.state_id in state_map:
                result.append(state_map[rp.state_id])

        return result

    def score_single_state(self, state: Any) -> float:
        """
        Score a single state using heuristic ranking. O(1)
        
        返回 a float 0.0-1.0 higher = interesting
        """
        from analysis.symbolic.llm_explorer.ranker import PathState
        ps = PathState(
            state_id=str(getattr(state, 'state_id', 0)),
            address=getattr(state, 'pc', 0),
            depth=getattr(state, 'depth', 0),
            constraints_count=len(getattr(state, 'path_constraints', [])),
            raw_state=state,
        )
        ranked = self._ranker.rank_paths([ps], top_k=1)
        if ranked:
            return ranked[0].llm_interest_score
        return 0.0


# ---------------------------------------------------------------------------
# StrategySwitcher适配器
# ---------------------------------------------------------------------------

class StrategySwitcherAdapter:
    """
    Adapts llm_explorer's AdaptiveStrategySwitcher for SymbolicExecutor
    strategy changes
    
    监控 execution metrics (active paths, 覆盖率 growth rate
    danger function detection) decides switch strategies
    
    INTJ策略: Strategy switching triggered stagnation detection —
    don't new 覆盖率 for N steps, rotate next
    strategy. prevents stuck deep loops or dead code
    """

    def __init__(self, stagnation_threshold: int = 20):
        from analysis.symbolic.llm_explorer.strategy import AdaptiveStrategySwitcher
        self._switcher = AdaptiveStrategySwitcher(stagnation_threshold=stagnation_threshold)
        self._strategy_map = {
            "bfs": "BFS",
            "dfs": "DFS",
            "llm": "LLM_GUIDED",
            "random": "COVERAGE_MAX",  # Approximate mapping
            "hybrid": "COVERAGE_MAX",
        }

    def update(
        self,
        active_path_count: int,
        new_coverage: bool,
        danger_detected: bool,
    ) -> str:
        """
        更新 strategy 基于 execution metrics
        
        返回 recommended strategy name (compatible
        ExecutionStrategy enum)
        
        Time: O(1). Space: O(1)
        """
        llm_strategy = self._switcher.update(active_path_count, new_coverage, danger_detected)
        return self._strategy_map.get(llm_strategy.value, "DFS")

    @property
    def current_strategy(self) -> str:
        llm_val = self._switcher.current.value
        return self._strategy_map.get(llm_val, "DFS")

    def reset(self) -> None:
        """重置 strategy default (BFS). O(1)"""
        from analysis.symbolic.llm_explorer.strategy import AdaptiveStrategySwitcher
        self._switcher = AdaptiveStrategySwitcher()


# ---------------------------------------------------------------------------
# LLMGuidedExplorer
# ---------------------------------------------------------------------------

class LLMGuidedExplorer:
    """
    High-level LLM-guided symbolic exploration 入口
    
    Wraps SymbolicExecutor LLM-based path ranking adaptive
    strategy switching. Designed a drop- replacement for direct
    executor.explore() calls
    
    Design rationale:
    - Composition over inheritance: wraps executor, doesn't extend
    keeps executor interface clean LLM guidance
    an optional enhancement layer
    - Lazy initialization: ranker switcher 适配器s created
    first 使用 允许 headless (-API-key) operation
    
    Time: explore_with_guidance()
    """

    def __init__(
        self,
        executor: Any = None,
        api_key: str = "",
        top_k: int = 10,
        max_depth: int = 1000,
    ):
        self._executor = executor
        self._api_key = api_key
        self._top_k = top_k
        self._max_depth = max_depth
        self._ranker_adapter: Optional[PathRankerAdapter] = None
        self._strategy_adapter: Optional[StrategySwitcherAdapter] = None
        self._stats: Dict[str, Any] = {
            "explorations": 0, "paths_explored": 0,
            "llm_guided_steps": 0, "strategy_switches": 0,
        }

    def explore_with_guidance(
        self,
        target_func: str = "main",
        ir_fetcher: Optional[Callable] = None,
        entry_address: int = 0,
        max_steps: int = 5000,
    ) -> Dict[str, Any]:
        """
        运行 LLM-guided symbolic exploration target_func
        
        1. 配置ures SymbolicExecutor LLM_GUIDED strategy
        2. Periodically 调用 LLM path ranking prune/prioritize
        3. 使用 adaptive strategy switching 检测 stagnation
        4. 返回 aggregate results dict form
        
        Args:
        target_func: Function name 分析
        ir_fetcher: Callable address -> IRInstruction
        entry_address: Starting PC for function
        max_steps: Maximum exploration steps
        
        返回:
        Dict keys: function, stats, 覆盖率, paths_explored
        strategy_log, elapsed_seconds
        
        Time: O(max_steps * (step_time + ranking_time))
        Space: O(max_states * state_size)
        
        Edge case: ir_fetcher None, 返回 empty results
        (useful for testing a binary target)
        """
        from analysis.symbolic.src.executor import SymbolicExecutor, SymbolicState, ExecutionStrategy
        import time

        start_time = time.perf_counter()

        # Lazy-init 适配器s
        if self._ranker_adapter is None:
            self._ranker_adapter = PathRankerAdapter(api_key=self._api_key)
        if self._strategy_adapter is None:
            self._strategy_adapter = StrategySwitcherAdapter()

        # 使用 existing executor or 创建 one
        executor = self._executor
        if executor is None:
            executor = SymbolicExecutor(
                strategy=ExecutionStrategy.LLM_GUIDED,
                max_depth=self._max_depth,
            )
            self._executor = executor

        # Inject LLM ranker executor
        try:
            from analysis.symbolic.llm_explorer.ranker import LLMPathRanker
            executor._llm_ranker = LLMPathRanker(api_key=self._api_key)
        except ImportError:
            _log.info("llm_explorer not available — using heuristic exploration")

        result = None
        if ir_fetcher is not None and entry_address:
            result = executor.explore_function(
                func_name=target_func,
                ir_fetcher=ir_fetcher,
                entry_address=entry_address,
                max_steps=max_steps,
            )
        else:
            # 返回 empty result for -binary case
            from analysis.symbolic.src.executor import SymbolicExplorationResult
            result = SymbolicExplorationResult()

        elapsed = time.perf_counter() - start_time

        self._stats["explorations"] += 1
        self._stats["paths_explored"] += result.paths_explored

        return {
            "function": target_func,
            "stats": dict(self._stats),
            "coverage_count": len(result.coverage) if result else 0,
            "paths_explored": result.paths_explored if result else 0,
            "timeouts": result.timeouts if result else 0,
            "strategy_log": self._strategy_adapter.current_strategy,
            "elapsed_seconds": elapsed,
        }

    def integrate_with_executor(
        self,
        executor: Any,
    ) -> None:
        """
        Integrate LLM guidance an existing SymbolicExecutor
        
        Sets executor's strategy LLM_GUIDED injects
        LLM ranker for path prioritization
        
        Time: O(1). Space: O(1)
        """
        from analysis.symbolic.src.executor import ExecutionStrategy
        self._executor = executor
        executor.strategy = ExecutionStrategy.LLM_GUIDED

        # Inject LLM ranker
        try:
            from analysis.symbolic.llm_explorer.ranker import LLMPathRanker
            executor._llm_ranker = LLMPathRanker(api_key=self._api_key)
        except ImportError:
            _log.info("LLM ranker injection failed — heuristic fallback")

    def get_stats(self) -> Dict[str, Any]:
        """返回 exploration statistics. O(1)"""
        return dict(self._stats)


# ---------------------------------------------------------------------------
# Dead code — 留着备用，后面可能用
# ---------------------------------------------------------------------------

def _generate_ExplorationSummaryReport(results: Dict[str, Any]) -> str:
    """构造 a markdown summary exploration results. Never
    
    这个函数是用来生成探索结果的Markdown报告的，暂时没用上
    """
    lines = [
        f"# Exploration Summary: {results.get('function', 'unknown')}",
        "",
        f"- Paths explored: {results.get('paths_explored', 0)}",
        f"- Timeouts: {results.get('timeouts', 0)}",
        f"- Coverage entries: {results.get('coverage_count', 0)}",
        f"- Strategy: {results.get('strategy_log', 'N/A')}",
        f"- Time: {results.get('elapsed_seconds', 0):.2f}s",
        "",
        "## Notes",
        "",
        "LLM-guided exploration completed. Review coverage gaps manually.",
    ]
    return "\n".join(lines)


__all__ = [
    "LLMGuidedExplorer",
    "PathRankerAdapter",
    "StrategySwitcherAdapter",
    "_generate_ExplorationSummaryReport",
]
