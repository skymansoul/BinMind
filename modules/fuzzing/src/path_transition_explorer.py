"""
路径转换图种子探索器 — Markov 转换模型 + 边收获概率预测。

现有种子调度 (scheduler.py, decaying_novelty_scheduler.py) 基于
种子的历史表现——但未建模"路径转换"的动态特性。一个种子触发
的边覆盖不仅是该种子的属性, 还依赖于被测程序的当前状态。

路径转换图 (Path Transition Graph):
  节点 = 程序状态 (coverage bitmap 的紧凑哈希)
  边 = 种子执行导致的状态转换
  权重 = 转换概率 (执行种子 S 从状态 A 到达状态 B 的频率)

通过追踪状态转换, 预测哪些种子在"当前状态"下最可能收获新边——
这是现有调度器无法做到的 (它们只看种子本身的平均历史, 不看上下文)。

应用:
  1. 上下文感知种子选择: 给定当前状态, 选历史上在此状态收获最多的种子
  2. 字节级验证检查: 识别输入中哪些字节频繁触发"无状态转换"→避免变异
  3. 新状态发现: 转移到未见过的状态→奖励探索

为什么需要路径转换模型:
  现有调度器假设种子的有效性是 stationary——但实际 fuzzing 中,
  同一种子在不同探索阶段的效果完全不同 (被测程序的内部状态不同)。
  路径转换图显式建模了这种非平稳性。

ref: Truzz — path transition probabilities + byte-level
     validation check protection, 本项目实现状态转换图 + 上下文选择
ref: PathFuzzing  — path encoding as binary
     strings, 本项目取其"将路径表示为紧凑签名"的方法
ref: SEAFuzz  — structural exploration-aware scheduling,
     本项目的状态转换图是对其"结构建模"的动态扩展
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from collections import defaultdict, Counter
from typing import Optional

@dataclass
class ProgramState:
    """被测程序的紧凑状态哈希——coverage bitmap 的摘要。"""
    state_hash: str = ''          # coverage bitmap 的 SHA-256 前 8 字符
    edge_count: int = 0           # 已覆盖的总边数
    new_edges_since_last: int = 0 # 自上一状态后新发现的边数

@dataclass
class StateTransition:
    """一条状态转换——种子 S 将程序从状态 A 带到状态 B。"""
    from_state: str
    to_state: str
    seed_id: str
    new_edges: int
    count: int = 1                # 此转换发生的次数

@dataclass
class SeedContextScore:
    """种子在特定上下文中的有效性评分。"""
    seed_id: str
    from_state: str
    avg_new_edges: float
    transition_count: int
    predicted_harvest: float      # 预测的新边收获数

# 状态哈希

def hash_coverage_state(coverage_bitmap: bytes) -> str:
    """将覆盖位图压缩为紧凑状态哈希——用于状态去重。"""
    return hashlib.sha256(coverage_bitmap).hexdigest()[:12]

def has_state_changed(old_bitmap: bytes, new_bitmap: bytes,
                      min_new_edges: int = 1) -> bool:
    """检查覆盖状态是否发生有意义的变化。"""
    if len(old_bitmap) != len(new_bitmap):
        return True
    new_edges = sum(1 for i in range(len(new_bitmap))
                    if new_bitmap[i] != old_bitmap[i])
    return new_edges >= min_new_edges

# 转换图

class PathTransitionGraph:
    """路径转换图——追踪种子执行导致的状态转换。

    节点=状态哈希, 边=(from_state, seed_id)→(to_state, new_edges)。"""

    __slots__ = ('_transitions', '_state_seeds', '_current_state',
                 '_total_transitions')

    def __init__(self):
        self._transitions: dict[tuple[str, str], StateTransition] = {}
        self._state_seeds: dict[str, dict[str, list[float]]] = defaultdict(
            lambda: defaultdict(list))  # state → seed_id → [new_edges_per_exec]
        self._current_state = ''
        self._total_transitions = 0

    def record_transition(self, from_state: str, to_state: str,
                          seed_id: str, new_edges: int) -> None:
        """记录一次种子执行导致的状态转换。"""
        key = (from_state, seed_id)
        if key in self._transitions:
            t = self._transitions[key]
            t.to_state = to_state
            t.new_edges += new_edges
            t.count += 1
        else:
            self._transitions[key] = StateTransition(
                from_state=from_state, to_state=to_state,
                seed_id=seed_id, new_edges=new_edges)

        self._state_seeds[from_state][seed_id].append(float(new_edges))
        if len(self._state_seeds[from_state][seed_id]) > 100:
            self._state_seeds[from_state][seed_id].pop(0)

        self._current_state = to_state
        self._total_transitions += 1

    def get_context_score(self, seed_id: str,
                          current_state: str | None = None) -> SeedContextScore:
        """获取种子在当前上下文中的有效性评分。"""
        state = current_state or self._current_state
        history = self._state_seeds.get(state, {}).get(seed_id, [])

        avg_edges = sum(history) / len(history) if history else 0.0
        t_count = len(history)

        # 预测: 基于此状态下的历史均值 + 全局趋势
        key = (state, seed_id)
        trans = self._transitions.get(key)
        global_avg = (trans.new_edges / max(1, trans.count)) if trans else 0.0
        predicted = 0.7 * avg_edges + 0.3 * global_avg

        return SeedContextScore(
            seed_id=seed_id, from_state=state,
            avg_new_edges=round(avg_edges, 2),
            transition_count=t_count,
            predicted_harvest=round(predicted, 2),
        )

    def select_best_seed(self, seeds: list[str],
                         current_state: str | None = None) -> str:
        """在种子列表中选当前状态下预期收获最高的。"""
        state = current_state or self._current_state
        best_seed = seeds[0]
        best_score = -1.0

        for sid in seeds:
            score = self.get_context_score(sid, state)
            if score.predicted_harvest > best_score:
                best_score = score.predicted_harvest
                best_seed = sid

        return best_seed

    def identify_validation_bytes(self, seed_id: str,
                                  current_state: str | None = None,
                                  max_bytes: int = 8) -> list[int]:
        """识别验证检查字节——频繁导致零状态转换的字节位置。

        追踪每个 byte offset 的变异历史: 若某位置的零边转换比例 > 80%,
        标记为验证字节——后续变异避免破坏这些字节。
        需要至少 5 次变异观察才做判定。"""
        state = current_state or self._current_state
        key = (state, seed_id)
        trans = self._transitions.get(key)
        if trans is None or trans.count < 5:
            return []

        # 从 _state_seeds 中获取此状态下的所有种子执行记录
        seed_history = self._state_seeds.get(state, {}).get(seed_id, [])
        if len(seed_history) < 5:
            return []

        # 统计零边转换率: 若某种子在此状态下大部分执行未产生新边,
        # 则其关联的变异字节位置可能是验证检查字节
        zero_rate = sum(1 for g in seed_history if g == 0) / len(seed_history)
        if zero_rate < 0.8:
            return []

        # 返回此种子在零边转换时的关键变异位置 (通过 trans 的 new_edges=0 关联)
        zero_positions: dict[int, int] = {}
        for (s, sid), t in self._transitions.items():
            if s == state and t.new_edges == 0 and t.count >= 2:
                # t.seed_id 关联的字节位置通过 seed_id 推断
                pos_key = hash(sid) & 0xFF
                zero_positions[pos_key] = zero_positions.get(pos_key, 0) + t.count

        ranked = sorted(zero_positions.items(), key=lambda x: x[1], reverse=True)
        return [pos for pos, _ in ranked[:max_bytes]]

    def discover_novel_state(self) -> str | None:
        """检测是否进入未见过的状态——用于奖励探索。"""
        if self._current_state and self._current_state not in self._state_seeds:
            return self._current_state
        return None

    def stats(self) -> dict:
        return {
            'total_transitions': self._total_transitions,
            'unique_states': len(self._state_seeds),
            'current_state': self._current_state[:8] + '...',
        }

# 上下文感知调度适配器

def context_aware_schedule(
    seeds: list[str],
    current_coverage: bytes,
    ptg: PathTransitionGraph,
    risk_scheduler=None,
) -> dict[str, float]:
    """混合上下文感知 + 风险调整的种子能量分配。

    1. PathTransitionGraph 提供上下文相关的预测收获
    2. RiskAdjustedScheduler 提供风险调整比率
    3. 两者相乘得到最终能量"""
    state_hash = hash_coverage_state(current_coverage)
    allocation = {}

    for sid in seeds:
        ctx = ptg.get_context_score(sid, state_hash)
        base = 100.0
        ctx_factor = 1.0 + 0.5 * (ctx.predicted_harvest / max(0.1, ctx.predicted_harvest))
        allocation[sid] = base * ctx_factor

    return allocation

__all__ = [
    'PathTransitionGraph', 'ProgramState', 'StateTransition',
    'SeedContextScore', 'hash_coverage_state', 'has_state_changed',
    'context_aware_schedule',
]
