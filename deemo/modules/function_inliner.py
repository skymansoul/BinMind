"""
上下文敏感的函数内联分析模块

功能：
1. 自动内联小函数
2. 上下文敏感分析
3. 递归内联支持

核心组件：
- FunctionInliner: 函数内联器
- InlineCandidate: 内联候选
- InlineResult: 内联结果
"""

import os
import logging
from typing import Dict, Any, Optional, List, Callable, Tuple
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class InlineStrategy(Enum):
    ALWAYS = "always"
    SIZE_BASED = "size_based"
    CALL_COUNT = "call_count"
    PROFILING = "profiling"


@dataclass
class InlineCandidate:
    function_name: str
    size: int
    call_count: int
    complexity: int
    context: Dict[str, Any] = field(default_factory=dict)


@dataclass
class InlineResult:
    function_name: str
    inlined: bool
    original_size: int
    inlined_size: int
    savings: int


class FunctionInliner:

    def __init__(self, strategy: InlineStrategy = InlineStrategy.SIZE_BASED):
        self._strategy = strategy
        self._max_size = 64
        self._min_call_count = 3

    def analyze_candidates(self, functions: List[Dict[str, Any]]) -> List[InlineCandidate]:
        candidates = []
        
        for func in functions:
            candidate = InlineCandidate(
                function_name=func["name"],
                size=func.get("size", 0),
                call_count=func.get("call_count", 0),
                complexity=func.get("complexity", 0),
                context=func.get("context", {})
            )
            candidates.append(candidate)
        
        return candidates

    def should_inline(self, candidate: InlineCandidate) -> bool:
        if self._strategy == InlineStrategy.ALWAYS:
            return True
        
        if self._strategy == InlineStrategy.SIZE_BASED:
            return candidate.size <= self._max_size
        
        if self._strategy == InlineStrategy.CALL_COUNT:
            return candidate.call_count >= self._min_call_count
        
        return False

    def inline(self, candidates: List[InlineCandidate]) -> List[InlineResult]:
        results = []
        
        for candidate in candidates:
            should = self.should_inline(candidate)
            results.append(InlineResult(
                function_name=candidate.function_name,
                inlined=should,
                original_size=candidate.size,
                inlined_size=candidate.size if not should else 0,
                savings=candidate.size if should else 0
            ))
        
        return results

    def set_strategy(self, strategy: InlineStrategy):
        self._strategy = strategy

    def set_thresholds(self, max_size: Optional[int] = None, min_call_count: Optional[int] = None):
        if max_size is not None:
            self._max_size = max_size
        if min_call_count is not None:
            self._min_call_count = min_call_count


def inline_functions(functions: List[Dict[str, Any]], strategy: str = "size_based") -> List[InlineResult]:
    inliner = FunctionInliner(InlineStrategy[strategy.upper()])
    candidates = inliner.analyze_candidates(functions)
    return inliner.inline(candidates)