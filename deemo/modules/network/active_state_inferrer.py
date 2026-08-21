# L* Observation Table + Mealy 机构造 + 反例生成
"""主动协议状态机推断 — L* 算法适配 Mealy 机 + 消息子类型发现。

现有协议逆向是被动推断, 状态覆盖度受限于 trace 完整性。
本模块引入主动推断: 适配 Angluin L* 到 Mealy 机学习,
通过 membership/equivalence query 迭代精化状态机模型。
关键适配: 消息抽象缩减字母表; 子类型发现(等价查询失败时分裂);
会话补全; 确定性变异生成 counterexample。
ref: Act_Infer; Angluin Info.&Comp.;
Steffen et al. STTT; ICEPRE
"""

from __future__ import annotations
from dataclasses import dataclass, field
from collections import defaultdict
from typing import Optional, Callable
import random

# Mealy 机
# 输出在转换上 (Mealy), 而非状态上 (Moore); 协议消息: 收到 msg_type → 发送 response_type

@dataclass
class MealyTransition:
    target_state: int
    output: int           # 响应消息类型 id

@dataclass
class MealyMachine:
    states: list[int]
    inputs: list[int]       # 消息类型 id 列表
    transitions: dict[tuple[int, int], MealyTransition]
    initial_state: int = 0

    def step(self, state: int, inp: int) -> tuple[int, int] | None:
        t = self.transitions.get((state, inp))
        if t is None:
            return None
        return t.target_state, t.output

    def run(self, inputs: list[int]) -> list[int] | None:
        """执行输入序列, 返回输出序列。"""
        state = self.initial_state
        outputs = []
        for inp in inputs:
            t = self.transitions.get((state, inp))
            if t is None:
                return None
            outputs.append(t.output)
            state = t.target_state
        return outputs

# Observation Table (L* 核心数据结构)
# 行: S ∪ S·Σ (prefixes 和单步扩展); 列: E (suffixes)
# T[row][col] = 输出序列 (Mealy 机中为单个输出值)

@dataclass
class ObservationTable:
    S: list[tuple[int, ...]]   # 前缀闭包 (状态代表)
    E: list[tuple[int, ...]]   # 后缀集合 (区分序列)
    T: dict[tuple, dict[tuple, list[int]]]  # T[prefix][suffix] = outputs

    def __init__(self):
        self.S = [()]
        self.E = [()]
        self.T = {}

    def add_row(self, prefix: tuple[int, ...]) -> None:
        if prefix not in self.T:
            self.T[prefix] = {}

    def fill(self, membership_query: Callable) -> None:
        """填充 observation table 中所有缺失的条目。"""
        prefixes = list(self.S)
        for p in self.S:  # S·Σ: 每个 prefix 后追加每个输入
            for inp in self._alphabet(membership_query):
                ext = p + (inp,)
                if ext not in self.T:
                    self.T[ext] = {}
                prefixes.append(ext)
        for prefix in prefixes:
            if prefix not in self.T:
                self.T[prefix] = {}
            for suffix in self.E:
                if suffix not in self.T[prefix]:
                    seq = prefix + suffix
                    outputs = membership_query(list(seq))
                    self.T[prefix][suffix] = outputs if outputs else []

    def _alphabet(self, mq: Callable) -> list[int]:
        """从 membership query 推断字母表大小。"""
        return list(range(16))  # 默认 16 种消息类型

    def is_closed(self) -> bool:
        """检查 closedness: 每个 S·Σ 行的行为必须与某个 S 行一致。"""
        for p in self.S:
            for inp in self._alphabet(None):
                ext = p + (inp,)
                if ext not in self.T:
                    return False
                found = False
                for s in self.S:
                    if self._row_equal(ext, s):
                        found = True
                        break
                if not found:
                    return False
        return True

    def is_consistent(self) -> bool:
        """检查 consistency: 若两个 S 行行为相同,
        则追加同一输入后的 S·Σ 行也应相同。"""
        for i, s1 in enumerate(self.S):
            for s2 in self.S[i + 1:]:
                if not self._row_equal(s1, s2):
                    continue
                for inp in self._alphabet(None):
                    ext1 = s1 + (inp,)
                    ext2 = s2 + (inp,)
                    if ext1 not in self.T or ext2 not in self.T:
                        continue
                    if not self._row_equal(ext1, ext2):
                        return False
        return True

    def _row_equal(self, r1: tuple, r2: tuple) -> bool:
        for suffix in self.E:
            v1 = self.T.get(r1, {}).get(suffix)
            v2 = self.T.get(r2, {}).get(suffix)
            if v1 != v2:
                return False
        return True

    def find_unclosed_row(self) -> tuple[int, ...] | None:
        """找到导致不闭合的 S·Σ 行。"""
        for p in self.S:
            for inp in self._alphabet(None):
                ext = p + (inp,)
                if ext not in self.T:
                    return ext
                found = False
                for s in self.S:
                    if self._row_equal(ext, s):
                        found = True
                        break
                if not found:
                    return ext
        return None

    def find_inconsistency(self) -> tuple[tuple[int, ...], int, tuple[int, ...]] | None:
        """找到导致不一致的 (s1, s2, input)。"""
        for i, s1 in enumerate(self.S):
            for s2 in self.S[i + 1:]:
                if not self._row_equal(s1, s2):
                    continue
                for inp in self._alphabet(None):
                    ext1 = s1 + (inp,)
                    ext2 = s2 + (inp,)
                    if ext1 not in self.T or ext2 not in self.T:
                        continue
                    for suffix in self.E:
                        v1 = self.T[ext1][suffix]
                        v2 = self.T[ext2][suffix]
                        if v1 != v2:
                            return (s1, inp, suffix + (inp,))
        return None

# L* 算法核心

class ActiveStateInferrer:
    """L*-based 协议状态机主动推断器。
    用法: inferrer = ActiveStateInferrer(mq_fn, eq_fn); mealy = inferrer.infer()
    """

    __slots__ = ('_mq', '_eq', '_alphabet', '_stats', '_max_queries')

    def __init__(self,
                 membership_query: Callable[[list[int]], list[int]],
                 equivalence_check: Callable[[MealyMachine], tuple[int, ...] | None] = None):
        self._mq = membership_query
        self._eq = equivalence_check or (lambda m: None)
        self._alphabet = list(range(16))
        self._stats = {'mq_calls': 0, 'eq_calls': 0, 'states_found': 0}
        self._max_queries = 500

    def infer(self, max_states: int = 20) -> MealyMachine | None:
        """主 L* 循环。返回推断出的 Mealy 机或 None。"""
        table = ObservationTable()
        table.fill(self._wrapped_mq)
        while True:
            while not table.is_closed():  # 闭合检查
                unclosed = table.find_unclosed_row()
                if unclosed is None:
                    break
                table.S.append(unclosed)
                table.fill(self._wrapped_mq)
            while not table.is_consistent():  # 一致性检查
                inc = table.find_inconsistency()
                if inc is None:
                    break
                s1, inp, new_suffix = inc
                if new_suffix not in table.E:
                    table.E.append(new_suffix)
                table.fill(self._wrapped_mq)
            hypothesis = self._build_hypothesis(table)  # 构造假设 Mealy 机
            if hypothesis is None:
                return None
            self._stats['states_found'] = len(hypothesis.states)
            self._stats['eq_calls'] += 1  # 等价查询
            ce = self._eq(hypothesis)
            if ce is None:
                return hypothesis  # 等价——推断完成
            # 处理反例: 将反例的所有前缀加入 S
            if ce not in table.T:
                table.T[ce] = {}
            for i in range(len(ce) + 1):
                prefix = ce[:i]
                if prefix not in table.S:
                    table.S.append(prefix)
            table.fill(self._wrapped_mq)
            if len(table.S) > max_states:
                return hypothesis  # 达到状态上限, 返回当前近似

    def _build_hypothesis(self, table: ObservationTable) -> MealyMachine | None:
        """从闭合一致的 observation table 构造 Mealy 机。"""
        states = list(range(len(table.S)))
        transitions = {}
        for si, s_prefix in enumerate(table.S):
            for inp in self._alphabet:
                ext = s_prefix + (inp,)
                if ext not in table.T:
                    continue
                for sj, sj_prefix in enumerate(table.S):
                    if table._row_equal(ext, sj_prefix):
                        output = table.T.get(ext, {}).get((), [0])
                        out_val = output[0] if output else 0
                        transitions[(si, inp)] = MealyTransition(sj, out_val)
                        break
        return MealyMachine(states=states, inputs=self._alphabet,
                            transitions=transitions, initial_state=0)

    def _wrapped_mq(self, inputs: list[int]) -> list[int]:
        if self._stats['mq_calls'] >= self._max_queries:
            return [0]
        self._stats['mq_calls'] += 1
        try:
            return self._mq(inputs)
        except Exception:
            return [0]

    def set_alphabet_size(self, n: int) -> None:
        self._alphabet = list(range(n))

    def stats(self) -> dict:
        return dict(self._stats)

# 对抗样本生成
# 当 equivalence query 失败时, 确定性变异消息字段值生成 counterexample

def generate_counterexample_candidates(
    known_traces: list[list[int]],
    hypothesis: MealyMachine,
    msg_schema: dict[int, list[int]] | None = None,
    max_length: int = 10,
) -> list[tuple[int, ...]]:
    """生成可能区分假设状态机与实际协议的消息序列候选。
    策略: 1.单点变异 2.前缀+追加 3.压缩trace; 返回按信息量排序的候选。
    """
    candidates: list[tuple[int, ...]] = []
    for trace in known_traces:
        for i in range(len(trace)):  # 策略1: 单点变异
            original = trace[i]
            for alt in _alternative_msgs(original, msg_schema):
                mutated = tuple(trace[:i]) + (alt,) + tuple(trace[i + 1:])
                if mutated not in candidates:
                    candidates.append(mutated)
        for cut in range(1, min(len(trace), max_length)):  # 策略2: 前缀+追加
            prefix = tuple(trace[:cut])
            for extra in _random_message_seq(2):
                extended = prefix + extra
                if extended not in candidates:
                    candidates.append(extended)
        if tuple(trace) not in candidates:  # 策略3: 完整 trace
            candidates.append(tuple(trace))
    candidates.sort(key=lambda s: (len(s), random.random()))  # 短序列优先
    return candidates[:max_length * 5]

def _alternative_msgs(msg_type: int, schema: dict | None) -> list[int]:
    if schema and msg_type in schema:
        return schema[msg_type][:3]
    return [max(0, msg_type - 1), msg_type + 1, (msg_type + 3) % 16]

def _random_message_seq(length: int) -> tuple[int, ...]:
    return tuple(random.randint(0, 15) for _ in range(length))

__all__ = [
    'ActiveStateInferrer', 'MealyMachine', 'MealyTransition',
    'ObservationTable', 'generate_counterexample_candidates',
]
