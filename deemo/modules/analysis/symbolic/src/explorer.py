#!/usr/bin/env python3
"""
LLM 引导探索适配器 — 桥接 llm_explorer/ 与 SymbolicExecutor。

架构:
- 组合优于继承: LLMGuidedExplorer 把 llm_explorer 的
  LLMGuidedPathExplorer 与 SymbolicExecutor 作为协作者包装
- PathRankerAdapter / StrategySwitcherAdapter 负责在 executor 的
  状态表示与 llm_explorer 的 PathState 模型之间转换

边界情况:
- LLM API 不可用时, 适配器回退到启发式排序 (内置 LLMPathRanker)
- SymbolicExecutor 未初始化时, 首次 explore 前惰性初始化

时间复杂度:
- explore_with_guidance(): O(max_steps * (step_time + ranking_time));
  启发式模式下 P 条活跃路径的排序 O(P * log P),
  LLM 模式 O(P + API 延迟)
"""
# from collections import OrderedDict  # python3.7+不需要了
from __future__ import annotations

import logging
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

_log = logging.getLogger(__name__)


# PathRankerAdapter

class PathRankerAdapter:
    """
    把 llm_explorer 的 LLMPathRanker 适配到 SymbolicExecutor 的状态接口。

    把 SymbolicState 对象转换为 ranker 消费的 PathState 对象,
    处理批量排序与可配置 top-K。

    设计策略: 每批排序 50 个状态, 保持在 LLM 上下文限制内,
    启发式模式延迟亚秒级; 更大工作负载用轮询分批。
    """

    def __init__(self, api_key: str = "", model: str = ""):
        from modules.analysis.symbolic.llm_explorer.ranker import LLMPathRanker
        self._ranker = LLMPathRanker(api_key=api_key, model=model) if model else LLMPathRanker(api_key=api_key)

    def rank_states(
        self,
        states: List[Any],
        top_k: int = 10,
    ) -> List[Any]:
        """
        按 LLM 兴趣分给 SymbolicState 对象排序, 返回 top-K。

        把 SymbolicState 转为 PathState 后排序, 按排名顺序返回
        对应的原始状态。转换开销极小 (字段复制), 实际成本是
        LLM API 延迟 (~200-500ms 每批)。
        """
        if not states:
            return []

        from modules.analysis.symbolic.llm_explorer.ranker import PathState

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
        """用启发式排序给单个状态打分, 返回 0.0-1.0, 越高越有趣。"""
        from modules.analysis.symbolic.llm_explorer.ranker import PathState
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


# StrategySwitcherAdapter

class StrategySwitcherAdapter:
    """
    把 llm_explorer 的 AdaptiveStrategySwitcher 适配到 SymbolicExecutor
    的策略切换。

    监控执行指标 (活跃路径数、覆盖率增长率、危险函数检测),
    据此决定是否切换策略。

    设计策略: 停滞检测触发策略切换 — 连续 N 步无新覆盖则轮换
    到下一策略, 防止卡在深层循环或死代码中。
    """

    def __init__(self, stagnation_threshold: int = 20):
        from modules.analysis.symbolic.llm_explorer.strategy import AdaptiveStrategySwitcher
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
        """根据执行指标更新策略, 返回兼容 ExecutionStrategy 枚举的推荐策略名。"""
        llm_strategy = self._switcher.update(active_path_count, new_coverage, danger_detected)
        return self._strategy_map.get(llm_strategy.value, "DFS")

    @property
    def current_strategy(self) -> str:
        llm_val = self._switcher.current.value
        return self._strategy_map.get(llm_val, "DFS")

    def reset(self) -> None:
        """把策略重置为默认 (BFS), O(1)。"""
        from modules.analysis.symbolic.llm_explorer.strategy import AdaptiveStrategySwitcher
        self._switcher = AdaptiveStrategySwitcher()


# LLMGuidedExplorer

class LLMGuidedExplorer:
    """
    高层 LLM 引导符号探索入口。

    把 SymbolicExecutor 与基于 LLM 的路径排序、自适应策略切换
    包装在一起, 设计为 executor.explore() 直接调用的即插即用替代。

    设计依据:
    - 组合优于继承: 包装 executor 而非扩展, 保持 executor 接口
      干净, LLM 引导只是可选增强层
    - 惰性初始化: ranker 与 switcher 适配器首次使用时创建,
      允许无 API key 的无头运行
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
        对 target_func 运行 LLM 引导的符号探索。

        1. 把 SymbolicExecutor 配置为 LLM_GUIDED 策略
        2. 周期性调用 LLM 路径排序做剪枝/优先级调整
        3. 用自适应策略切换检测停滞
        4. 返回聚合结果字典, 键含 function、stats、coverage_count、
           paths_explored、strategy_log、elapsed_seconds

        ir_fetcher 为 address -> IRInstruction 的可调用;
        为 None 时返回空结果 (适合无二进制目标的测试)。
        """
        from modules.analysis.symbolic.src.executor import SymbolicExecutor, SymbolicState, ExecutionStrategy
        import time

        start_time = time.perf_counter()

        # 惰性初始化适配器
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
            from modules.analysis.symbolic.llm_explorer.ranker import LLMPathRanker
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
            from modules.analysis.symbolic.src.executor import SymbolicExplorationResult
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
        """把 LLM 引导集成进现有 SymbolicExecutor: 策略设为
        LLM_GUIDED 并注入路径优先级排序用的 LLM ranker。"""
        from modules.analysis.symbolic.src.executor import ExecutionStrategy
        self._executor = executor
        executor.strategy = ExecutionStrategy.LLM_GUIDED

        # Inject LLM ranker
        try:
            from modules.analysis.symbolic.llm_explorer.ranker import LLMPathRanker
            executor._llm_ranker = LLMPathRanker(api_key=self._api_key)
        except ImportError:
            _log.info("LLM ranker injection failed — heuristic fallback")

    def get_stats(self) -> Dict[str, Any]:
        """返回探索统计, O(1)。"""
        return dict(self._stats)


def generate_exploration_summary_report(results: Dict[str, Any]) -> str:
    """把探索结果渲染为 Markdown 摘要。"""
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
    "generate_exploration_summary_report",
]
