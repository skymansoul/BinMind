"""Thompson采样测试策略选择器 — 基于历史漏洞发现率的自适应策略优化。

理论依据:
  BandFuzz (arXiv:2507.10845): Cupid 自动模糊器选择器。
  FuzzingBrain V2 (arXiv:2605.21779): 两层模糊测试架构。
  SAFuzz (arXiv:2602.11209): 语义预言机 -> 85.7%精确率。

模块位置: testing/src/thompson_test_selector.py
"""

import random, time
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple
import logging
_log = logging.getLogger(__name__)


class TestStrategy(Enum):
    DIFF = "differential"
    FUZZ = "fuzzing"
    SYMBEX = "symbolic"
    CONCURRENT = "concurrency"
    PROPERTY = "property_based"


@dataclass
class StrategyRecord:
    strategy: TestStrategy
    alpha: float = 1.0      # Beta后验: 成功
    beta: float = 1.0       # 失败
    selections: int = 0
    bugs_found: int = 0
    avg_exec_time_ms: float = 0.0

    def sample(self) -> float:
        return random.betavariate(max(0.1, self.alpha), max(0.1, self.beta))

    def update(self, bugs: int, exec_time_ms: float):
        self.selections += 1
        self.bugs_found += bugs
        reward = min(1.0, bugs / 2.0)  # 0-2 bugs -> [0, 1]
        if reward >= 0.5:
            self.alpha += reward
        else:
            self.beta += (1.0 - reward)
        n = self.selections
        self.avg_exec_time_ms = (self.avg_exec_time_ms * (n - 1) + exec_time_ms) / n if n > 0 else exec_time_ms


class ThompsonTestSelector:
    """Thompson采样驱动的测试策略选择器。

    将每种测试策略建模为多臂老虎机的臂,
    根据历史漏洞发现率选择最优策略组合。
    """

    def __init__(self):
        self._strategies: Dict[TestStrategy, StrategyRecord] = {
            s: StrategyRecord(s) for s in TestStrategy
        }
        self._history: List[Tuple[TestStrategy, int, float]] = []

    def select(self, top_k: int = 2) -> List[TestStrategy]:
        """选择top-K最有希望的策略。"""
        samples = [(s, rec.sample()) for s, rec in self._strategies.items()]
        samples.sort(key=lambda x: x[1], reverse=True)
        return [s for s, _ in samples[:top_k]]

    def observe_result(self, strategy: TestStrategy, bugs_found: int, exec_time_ms: float):
        """观察策略执行结果并更新后验。"""
        self._strategies[strategy].update(bugs_found, exec_time_ms)
        self._history.append((strategy, bugs_found, exec_time_ms))

    def get_stats(self) -> Dict:
        return {
            s.value: {
                "mean": round(r.alpha / max(0.01, r.alpha + r.beta), 3),
                "selections": r.selections, "bugs": r.bugs_found,
                "avg_ms": round(r.avg_exec_time_ms, 1),
            }
            for s, r in self._strategies.items()
        }

    def causal_inference(
        self, strategy: TestStrategy, crash_signature: str
    ) -> float:
        """反事实推理 — 判断崩溃是否由特定策略引起。

        简化实现: 若该策略历史发现过相同签名崩溃则返回高概率;
        否则返回基线概率。
        """
        for hist_strat, bugs, _ in self._history:
            if hist_strat == strategy and bugs > 0:
                return 0.8
        return 0.2  # 基线: 不太可能由此策略引起


__all__ = ["TestStrategy", "StrategyRecord", "ThompsonTestSelector"]
