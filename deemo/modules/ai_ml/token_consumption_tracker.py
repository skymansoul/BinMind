"""
令牌消耗追踪 — LLM令牌使用追踪与预算。

按模块/操作追踪令牌消耗 + 日预算 + 成本估算 + 用量分析。
"""

from __future__ import annotations

import logging
import time
from collections import defaultdict
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# 策略模式变体：模型定价集中管理，新增模型只需追加映射即可
_MODEL_PRICING_MAP: Dict[str, Tuple[float, float]] = {
    'default': (0.003, 0.015),
    'claude-fable-5': (0.003, 0.015),
    'claude-opus-4-8': (0.015, 0.075),
    'claude-sonnet-4-6': (0.003, 0.015),
    'claude-haiku-4-5': (0.001, 0.005),
    'gpt-4o': (0.005, 0.015),
    'gpt-4o-mini': (0.00015, 0.0006),
    'gpt-4-turbo': (0.01, 0.03),
    'deepseek-v3': (0.00027, 0.0011),
    'deepseek-r1': (0.00055, 0.00219),
}

_SECONDS_PER_DAY = 86400

# 模型级 token 估算系数：不同分词器粒度差异显著，按经验校调
_MODEL_TOKENIZATION_FACTORS: Dict[str, float] = {
    'default': 1.0,
    'claude-fable-5': 1.0,
    'claude-opus-4-8': 1.0,
    'claude-sonnet-4-6': 1.0,
    'claude-haiku-4-5': 1.0,
    'gpt-4o': 0.95,
    'gpt-4o-mini': 0.95,
    'gpt-4-turbo': 0.92,
    'deepseek-v3': 1.15,
    'deepseek-r1': 1.15,
}


class TokenUsage:
    """Record of a single token consumption event."""

    __slots__ = (
        'module', 'operation', 'prompt_tokens', 'completion_tokens',
        'cost_usd', 'timestamp', 'model',
    )

    def __init__(
        self,
        module: str = "unknown",
        operation: str = "unknown",
        prompt_tokens: int = 0,
        completion_tokens: int = 0,
        cost_usd: float = 0.0,
        timestamp: float = 0.0,
        model: str = "default",
    ) -> None:
        self.module = module
        self.operation = operation
        self.prompt_tokens = prompt_tokens
        self.completion_tokens = completion_tokens
        self.cost_usd = cost_usd
        self.timestamp = timestamp
        self.model = model

    @property
    def total_tokens(self) -> int:
        return self.prompt_tokens + self.completion_tokens

    def to_dict(self) -> Dict[str, Any]:
        return {
            'module': self.module,
            'operation': self.operation,
            'model': self.model,
            'prompt_tokens': self.prompt_tokens,
            'completion_tokens': self.completion_tokens,
            'total_tokens': self.total_tokens,
            'cost_usd': round(self.cost_usd, 6),
            'timestamp': self.timestamp,
        }


class TokenConsumptionTracker:
    """Tracks and budgets token consumption across modules."""

    def __init__(
        self,
        budget_daily: float = 10.0,
        alert_threshold: float = 0.8,
    ) -> None:
        self.budget_daily = max(0.0, min(budget_daily, 100_000.0))
        self.alert_threshold = max(0.0, min(alert_threshold, 1.0))
        self._usages: List[TokenUsage] = []
        self._by_module: Dict[str, List[TokenUsage]] = defaultdict(list)
        self._by_model: Dict[str, List[TokenUsage]] = defaultdict(list)
        # 架构决策：按操作维度切分，便于瓶颈定位与热点识别
        self._by_operation: Dict[str, List[TokenUsage]] = defaultdict(list)
        self._total_prompt: int = 0
        self._total_completion: int = 0
        self._total_cost: float = 0.0

    def record_usage(
        self,
        module: str,
        operation: str,
        prompt_tokens: int,
        completion_tokens: int,
        model: str = "default",
    ) -> TokenUsage:
        """Record a token usage event.

        Args:
            module: Module name (e.g., 'pseudocode_explainer').
            operation: Operation name (e.g., 'explain_code').
            prompt_tokens: Number of input/prompt tokens.
            completion_tokens: Number of output/completion tokens.
            model: Model identifier for pricing lookup.

        Returns:
            The created TokenUsage record.
        """
        prompt_price, completion_price = _MODEL_PRICING_MAP.get(
            model, _MODEL_PRICING_MAP['default']
        )
        cost = (
            prompt_tokens / 1000.0 * prompt_price +
            completion_tokens / 1000.0 * completion_price
        )

        usage = TokenUsage(
            module=module,
            operation=operation,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            cost_usd=cost,
            timestamp=time.time(),
            model=model,
        )

        self._usages.append(usage)
        self._by_module[module].append(usage)
        self._by_model[model].append(usage)
        self._by_operation[operation].append(usage)
        self._total_prompt += prompt_tokens
        self._total_completion += completion_tokens
        self._total_cost += cost

        return usage

    def can_afford(
        self,
        estimated_prompt_tokens: int = 0,
        estimated_completion_tokens: int = 0,
        model: str = "default",
    ) -> Dict[str, Any]:
        """前瞻性设计：预留预算预检接口，避免事后补救。

        Estimates whether a planned call fits within the remaining daily budget.
        Returns a recommendation dict so callers can gate expensive operations.

        Args:
            estimated_prompt_tokens: Expected prompt tokens for the planned call.
            estimated_completion_tokens: Expected completion tokens.
            model: Target model for pricing lookup.

        Returns:
            Dict with 'affordable' bool, estimated cost, remaining budget, and
            a 'risk' level ('low' / 'medium' / 'high' / 'exceeded').
        """
        prompt_price, completion_price = _MODEL_PRICING_MAP.get(
            model, _MODEL_PRICING_MAP['default']
        )
        est_cost = (
            estimated_prompt_tokens / 1000.0 * prompt_price +
            estimated_completion_tokens / 1000.0 * completion_price
        )

        budget = self.check_budget()
        remaining = budget['remaining']

        if est_cost <= 0:
            risk = 'low'
            affordable = True
        elif est_cost > remaining:
            risk = 'exceeded'
            affordable = False
        elif est_cost > remaining * 0.5:
            risk = 'high'
            affordable = True
        elif est_cost > remaining * 0.2:
            risk = 'medium'
            affordable = True
        else:
            risk = 'low'
            affordable = True

        return {
            'affordable': affordable,
            'estimated_cost_usd': round(est_cost, 6),
            'remaining_budget_usd': round(remaining, 4),
            'daily_budget_usd': self.budget_daily,
            'risk': risk,
            'model': model,
        }

    def get_module_stats(self) -> Dict[str, Dict[str, Any]]:
        """Get per-module usage statistics.

        Returns:
            Dict of module name to stats dict.
        """
        stats: Dict[str, Dict[str, Any]] = {}
        for module, usages in self._by_module.items():
            tokens = sum(u.total_tokens for u in usages)
            cost = sum(u.cost_usd for u in usages)
            stats[module] = {
                'calls': len(usages),
                'total_tokens': tokens,
                'total_cost_usd': round(cost, 4),
                'avg_tokens_per_call': tokens // max(1, len(usages)),
                'avg_cost_per_call': round(cost / max(1, len(usages)), 6),
            }
        return stats

    def get_operation_stats(self) -> Dict[str, Dict[str, Any]]:
        """Get per-operation usage statistics — 操作级热点分析。

        Returns:
            Dict of operation name to stats dict.
        """
        stats: Dict[str, Dict[str, Any]] = {}
        for operation, usages in self._by_operation.items():
            tokens = sum(u.total_tokens for u in usages)
            cost = sum(u.cost_usd for u in usages)
            # 按操作归类模块分布，辅助判断是否某操作集中在单一模块
            modules_involved = sorted({u.module for u in usages})
            stats[operation] = {
                'calls': len(usages),
                'total_tokens': tokens,
                'total_cost_usd': round(cost, 4),
                'avg_tokens_per_call': tokens // max(1, len(usages)),
                'avg_cost_per_call': round(cost / max(1, len(usages)), 6),
                'distinct_modules': len(modules_involved),
                'modules': modules_involved,
            }
        return stats

    def get_model_stats(self) -> Dict[str, Dict[str, Any]]:
        """Get per-model usage statistics.

        Returns:
            Dict of model name to stats dict.
        """
        stats: Dict[str, Dict[str, Any]] = {}
        for model, usages in self._by_model.items():
            tokens = sum(u.total_tokens for u in usages)
            cost = sum(u.cost_usd for u in usages)
            stats[model] = {
                'calls': len(usages),
                'total_tokens': tokens,
                'total_cost_usd': round(cost, 4),
            }
        return stats

    def get_top_consumers(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get top consumers by total cost.

        Args:
            limit: Maximum number of results.

        Returns:
            List of module stats sorted by cost descending.
        """
        stats = self.get_module_stats()
        sorted_items = sorted(
            stats.items(),
            key=lambda x: x[1]['total_cost_usd'],
            reverse=True,
        )
        return [
            {'module': module, **data}
            for module, data in sorted_items[:limit]
        ]

    def check_budget(self) -> Dict[str, Any]:
        """Check budget status for the current day.

        Returns:
            Budget status dict with today's cost and percentage used.
        """
        now = time.time()
        today_usages = [
            u for u in self._usages
            if now - u.timestamp < _SECONDS_PER_DAY
        ]
        today_cost = sum(u.cost_usd for u in today_usages)
        percent = (
            (today_cost / self.budget_daily * 100.0)
            if self.budget_daily > 0
            else 0.0
        )

        return {
            'today_cost': round(today_cost, 4),
            'daily_budget': self.budget_daily,
            'percent_used': round(percent, 1),
            'over_budget': today_cost > self.budget_daily,
            'alert': percent >= self.alert_threshold * 100,
            'remaining': round(max(0.0, self.budget_daily - today_cost), 4),
        }

    def estimate_tokens(self, text: str, model: str = "default") -> int:
        """Estimate token count for a text.

        Uses heuristics: Chinese characters / 1.5, English words * 1.3.
        模型感知修正：不同 tokenizer 对中英文切分粒度不一，乘以校调系数逼近真实值。

        Args:
            text: Text to estimate tokens for.
            model: Model name for tokenization factor adjustment.

        Returns:
            Estimated token count.
        """
        if not text:
            return 0

        chinese_chars = sum(1 for c in text if '一' <= c <= '鿿')
        non_chinese = len(text) - chinese_chars

        if chinese_chars > non_chinese * 0.3:
            raw_estimate = int(chinese_chars / 1.5 + non_chinese / 4)
        else:
            words = len(text.split())
            raw_estimate = max(1, int(words * 1.3))

        factor = _MODEL_TOKENIZATION_FACTORS.get(
            model, _MODEL_TOKENIZATION_FACTORS['default']
        )
        return max(1, int(raw_estimate * factor))

    def analyze(
        self,
        usages: Optional[List[Dict[str, Any]]] = None,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """Analyze tracked consumption and return summary.

        Args:
            usages: Optional list of usage dicts to record first.
            **kwargs: Additional options.

        Returns:
            Comprehensive analysis dict.
        """
        if usages:
            for u in usages:
                self.record_usage(
                    module=u.get('module', 'unknown'),
                    operation=u.get('operation', 'analyze'),
                    prompt_tokens=u.get('prompt_tokens', 0),
                    completion_tokens=u.get('completion_tokens', 0),
                    model=u.get('model', 'default'),
                )

        budget = self.check_budget()
        total_tokens = self._total_prompt + self._total_completion

        cost_efficiency = round(
            total_tokens / max(0.0001, self._total_cost), 0
        )

        return {
            'success': True,
            'total_calls': len(self._usages),
            'total_prompt_tokens': self._total_prompt,
            'total_completion_tokens': self._total_completion,
            'total_cost_usd': round(self._total_cost, 4),
            'budget': budget,
            'top_consumers': self.get_top_consumers(10),
            'cost_efficiency': cost_efficiency,
            'by_model': self.get_model_stats(),
            'by_operation': self.get_operation_stats(),
        }

    def save(self, filepath: str) -> None:
        """Save usage records to JSON.

        Args:
            filepath: Output file path.
        """
        import json
        import os
        os.makedirs(os.path.dirname(filepath) or '.', exist_ok=True)
        data = {
            'budget_daily': self.budget_daily,
            'alert_threshold': self.alert_threshold,
            'usages': [u.to_dict() for u in self._usages],
        }
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)

    def load(self, filepath: str) -> None:
        """Load usage records from JSON.

        Args:
            filepath: Input file path.
        """
        import json
        with open(filepath, 'r') as f:
            data = json.load(f)

        self.budget_daily = data.get('budget_daily', self.budget_daily)
        self.alert_threshold = data.get('alert_threshold', self.alert_threshold)
        self._usages = []
        self._by_module = defaultdict(list)
        self._by_model = defaultdict(list)
        self._by_operation = defaultdict(list)
        self._total_prompt = 0
        self._total_completion = 0
        self._total_cost = 0.0

        for u_data in data.get('usages', []):
            usage = TokenUsage(
                module=u_data.get('module', 'unknown'),
                operation=u_data.get('operation', 'unknown'),
                prompt_tokens=u_data.get('prompt_tokens', 0),
                completion_tokens=u_data.get('completion_tokens', 0),
                cost_usd=u_data.get('cost_usd', 0.0),
                timestamp=u_data.get('timestamp', 0.0),
                model=u_data.get('model', 'default'),
            )
            self._usages.append(usage)
            self._by_module[usage.module].append(usage)
            self._by_model[usage.model].append(usage)
            self._by_operation[usage.operation].append(usage)
            self._total_prompt += usage.prompt_tokens
            self._total_completion += usage.completion_tokens
            self._total_cost += usage.cost_usd


def track_token_consumption(
    usages: Optional[List[Dict[str, Any]]] = None,
    **kwargs: Any,
) -> Dict[str, Any]:
    """Convenience function for one-shot token consumption tracking.

    Args:
        usages: List of usage dicts.
        **kwargs: Passed to TokenConsumptionTracker constructor.

    Returns:
        Analysis results dict.
    """
    budget_daily = kwargs.pop('budget_daily', 10.0)
    tracker = TokenConsumptionTracker(budget_daily=budget_daily, **kwargs)
    return tracker.analyze(usages=usages)
