"""状态感知协议 Fuzzer — 入口模块。

拆分结构:
- _types: 数据类型与枚举 (ProtocolState, StateTransition, FuzzBudget, FuzzingPlan, FuzzPhase)
- _budget: 预算规划逻辑 (plan_budget_core, plan_budget_spectral)
- _core: 核心类 StateAwareFuzzer

本文件仅做 re-export，保持外部导入路径不变。
"""

from ._types import FuzzBudget, FuzzPhase, FuzzingPlan, ProtocolState, StateTransition
from ._core import StateAwareFuzzer

__all__ = [
    "ProtocolState",
    "StateTransition",
    "FuzzBudget",
    "FuzzingPlan",
    "FuzzPhase",
    "StateAwareFuzzer",
]
