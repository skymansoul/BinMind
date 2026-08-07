# 创建: 2026-06-22 15:12
# 修改: 2026-06-22 — 8 种突变策略闭包 + 策略状态定义
"""对抗性遗憾最小化的策略定义和辅助数据类型.

与 regret_minimizing_ensemble.py 分离以减少单文件体积,
主逻辑在 RegretMinimizingEnsemble 类中。
"""

import random
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Tuple


_DEFAULT_LR = 0.1
_ENTROPY_LAMBDA = 0.01
_REGRET_WINDOW = 200
_SURPRISE_THRESHOLD = 1.8
_RESET_REGRET_RATIO = 0.35

MutatorFn = Callable[[bytes], Tuple[bytes, List[int]]]


@dataclass
class StrategyState:
    """单个突变策略的对抗性状态."""
    name: str
    weight: float = 1.0
    prob: float = 0.0
    cumulative_reward: float = 0.0
    calls: int = 0
    success_count: int = 0
    reward_ema: float = 0.0
    surprise_count: int = 0
    context_stats: Dict[str, Tuple[int, int]] = field(
        default_factory=lambda: defaultdict(lambda: (0, 0))
    )


@dataclass
class RegretSnapshot:
    """一次遗憾快照."""
    timestamp: float
    cumulative_regret: float
    per_step_regret: float
    best_fixed_strategy: str
    best_fixed_reward: float


def build_strategies() -> Dict[str, MutatorFn]:
    """构建 8 种默认突变策略的闭包集合."""
    strategies: Dict[str, MutatorFn] = {}

    def bitflip(data: bytes):
        if not data: return data, []
        raw = bytearray(data); p = random.randint(0, len(raw) - 1)
        raw[p] ^= (1 << random.randint(0, 7))
        return bytes(raw), [p]

    def byteflip(data: bytes):
        if not data: return data, []
        pos = random.randint(0, len(data) - 1)
        arr = bytearray(data); arr[pos] ^= 0xFF
        return bytes(arr), [pos]

    def arith(data: bytes):
        if not data: return data, []
        p = random.randint(0, len(data) - 1)
        arr = bytearray(data)
        arr[p] = (arr[p] + random.choice([-35, -1, 1, 35])) & 0xFF
        return bytes(arr), [p]

    def interesting(data: bytes):
        if not data: return data, []
        raw = bytearray(data)
        idx = random.randint(0, len(raw) - 1)
        candidates = [v for v in [0, 1, 0x7F, 0x80, 0xFF, 0xFE] if v != raw[idx]]
        if candidates: raw[idx] = random.choice(candidates)
        return bytes(raw), [idx]

    def havoc(data: bytes):
        if not data: return data, []
        raw = bytearray(data); positions: List[int] = []
        for _ in range(random.randint(1, min(16, len(raw)))):
            pos = random.randint(0, len(raw) - 1)
            op = random.randint(0, 3)
            if op == 0: raw[pos] ^= (1 << random.randint(0, 7))
            elif op == 1: raw[pos] = random.randint(0, 255)
            elif op == 2: raw[pos] = (raw[pos] + random.randint(-35, 35)) & 0xFF
            else: raw[pos] = random.choice([0, 1, 0x7F, 0x80, 0xFF])
            positions.append(pos)
        return bytes(raw), positions

    def splice(data: bytes):
        if len(data) < 4: return data, []
        raw = bytearray(data); cs = max(1, len(raw) // 4)
        src = random.randint(0, max(0, len(raw) - cs))
        dst = random.randint(0, max(0, len(raw) - cs))
        raw[dst:dst+cs] = raw[src:src+cs]
        return bytes(raw), list(range(dst, dst+cs))

    def delete(data: bytes):
        if len(data) < 2: return data, []
        raw = bytearray(data)
        chunk = random.randint(1, max(1, len(raw) // 8))
        start = random.randint(0, max(0, len(raw) - chunk))
        del raw[start:start+chunk]; return bytes(raw), [start]

    def insert(data: bytes):
        if len(data) < 2: return data, []
        raw = bytearray(data)
        chunk = random.randint(1, max(1, len(raw) // 8))
        src = random.randint(0, max(0, len(raw) - chunk))
        dst = random.randint(0, len(raw))
        raw[dst:dst] = raw[src:src+chunk]
        return bytes(raw), list(range(dst, dst+chunk))

    for name, fn in [("bitflip", bitflip), ("byteflip", byteflip),
                      ("arith", arith), ("interesting", interesting),
                      ("havoc", havoc), ("splice", splice),
                      ("delete", delete), ("insert", insert)]:
        strategies[name] = fn
    return strategies
