# 分层马尔可夫Fuzzer — 字节→字段→消息的三级Markov模型
#
# 核心问题:
#   markov_fuzz.py 用单层Markov模型学习 P(byte_i | byte_{i-1})——这是"平层"的:
#   将输入视为无结构的字节流。对结构化格式 (protobuf, ASN.1, TLS, DNS),
#   字节间的依赖关系跨越字段边界: 长度字段的值影响后续数据字段的大小,
#   type字段的值影响后续字段的解析方式。
#   平层Markov无法捕获这些跨字段依赖——因为相邻字节可能属于不同字段。
#
# 本模块的方法 — 三级分层Markov:
#   Level 1 (字节): P(byte_i | byte_{i-1}) ——与markov_fuzz.py相同
#   Level 2 (字段): P(field_k | field_{k-1}) ——字段级别的转移
#     每个字段由其"角色模式"表示: magic→固定, length→值分布, data→熵
#   Level 3 (消息): P(msg_type | prev_msg_type) ——消息类型级别的转移
#     适用于有状态协议 (如TLS握手序列: ClientHello→ServerHello→Certificate...)
#
# 生成时三层级联合采样:
#   1. Level 3 决定消息类型
#   2. Level 2 为该消息类型生成字段序列
#   3. Level 1 为每个字段生成字节内容
#
# 文献:
#   ChatFuMe / FUME — 双Markov模型做协议fuzzing;
#     本项目取其双层Markov思想但扩展到三层并适配二进制格式
#   — 分层序列生成在协议fuzzing中是通用设计模式,
#     本模块以三级Markov实现, 不依赖外部语言模型

from __future__ import annotations

import math
import random
from collections import defaultdict, Counter
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class FieldRole:
    """字段角色模板——用于Level 2字段级建模"""
    role: str = "data"           # magic | length | type | data | checksum
    typical_size: int = 4
    value_distribution: Counter = field(default_factory=Counter)


@dataclass
class MessageTemplate:
    """消息模板——Level 3用"""
    msg_type: str = ""
    field_sequence: List[str] = field(default_factory=list)


class HierarchicalMarkovModel:
    """三级分层Markov模型。

    典型用法:
        hmm = HierarchicalMarkovModel()
        # 学习阶段:
        for sample in corpus:
            hmm.learn_byte_level(sample)
            hmm.learn_field_level(fields_from_sample)
        hmm.learn_message_level(message_type_sequences)

        # 生成阶段:
        msg_type = hmm.sample_message_type()
        fields = hmm.sample_field_sequence(msg_type)
        data = hmm.sample_bytes(fields)
    """

    def __init__(self, max_fields: int = 64):
        self._max_fields = max_fields

        # Level 1: 字节级转移: position → (prev_byte → Counter[next_byte])
        self._byte_transitions: Dict[int, Dict[int, Counter]] = defaultdict(
            lambda: defaultdict(Counter))
        self._byte_marginal: Dict[int, Counter] = defaultdict(Counter)

        # Level 2: 字段级转移: prev_role → Counter[next_role]
        self._field_transitions: Dict[str, Counter] = defaultdict(Counter)
        # 二阶转移: (role_{k-2}, role_{k-1}) → Counter[role_k]
        self._field_transitions_2nd: Dict[Tuple[str, str], Counter] = defaultdict(Counter)
        self._field_start: Dict[str, Counter] = defaultdict(Counter)  # role→Counter[pos]
        # 字段大小分布: role → List[sizes]
        self._field_sizes: Dict[str, List[int]] = defaultdict(list)

        # Level 3: 消息级转移: prev_msg_type → Counter[next_msg_type]
        self._msg_transitions: Dict[str, Counter] = defaultdict(Counter)
        self._msg_start: Counter = Counter()

        self._samples_learned = 0

    # 学习

    def learn_byte_level(self, data: bytes) -> None:
        """Level 1: 学习逐字节转移概率"""
        for i in range(1, len(data)):
            prev, curr = data[i - 1], data[i]
            self._byte_transitions[i][prev][curr] += 1
            self._byte_marginal[i][curr] += 1

    def learn_field_level(self, fields: List[Tuple[int, int, str]]) -> None:
        """Level 2: 学习字段级转移+大小分布。
        fields: [(start, end, role), ...] 如 [(0,4,'magic'), (4,8,'length'), ...]
        """
        roles = [r for _, _, r in fields]
        for k in range(1, len(roles)):
            self._field_transitions[roles[k - 1]][roles[k]] += 1
        # 二阶转移
        for k in range(2, len(roles)):
            self._field_transitions_2nd[(roles[k-2], roles[k-1])][roles[k]] += 1
        # 记录每种角色在输入中的位置分布和大小
        for start, end, role in fields:
            self._field_start[role][start] += 1
            self._field_sizes[role].append(end - start)

    def learn_message_level(self, msg_sequences: List[List[str]]) -> None:
        """Level 3: 学习消息类型转移序列"""
        for seq in msg_sequences:
            if not seq:
                continue
            self._msg_start[seq[0]] += 1
            for k in range(1, len(seq)):
                self._msg_transitions[seq[k - 1]][seq[k]] += 1

        self._samples_learned += len(msg_sequences)

    # 生成

    def sample_message_type(self, rng: Optional[random.Random] = None) -> str:
        """Level 3: 采样下一个消息类型"""
        r = rng or random
        if not self._msg_start:
            return "unknown"
        return self._weighted_choice(self._msg_start, r)

    def sample_field_sequence(self, msg_type: str,
                               rng: Optional[random.Random] = None,
                               ) -> List[Tuple[int, int, str]]:
        """Level 2: 采样字段序列——使用学习的大小分布和二阶转移。

        转移优先级: 二阶 > 一阶 > uniform fallback.
        大小采样: 从该角色历史大小中按频率采样, 无历史时用中位数4.
        """
        r = rng or random
        roles: List[str] = []
        # 选起始角色 (最常见于位置0的)
        candidates = [(role, self._field_start[role].get(0, 0))
                       for role in self._field_start]
        candidates = [(ro, c) for ro, c in candidates if c > 0]
        if candidates:
            roles.append(max(candidates, key=lambda x: x[1])[0])
        else:
            roles.append("data")

        # 链式采样——优先二阶转移, 回退一阶
        for _ in range(self._max_fields - 1):
            if len(roles) >= 2:
                key2 = (roles[-2], roles[-1])
                dist2 = self._field_transitions_2nd.get(key2)
                if dist2 and sum(dist2.values()) >= 3:
                    roles.append(self._weighted_choice(dist2, r))
                    continue
            prev = roles[-1]
            next_dist = self._field_transitions.get(prev)
            if not next_dist:
                break
            roles.append(self._weighted_choice(next_dist, r))

        # 分配位置——从学习的大小分布采样
        fields: List[Tuple[int, int, str]] = []
        pos = 0
        for role in roles:
            size_samples = self._field_sizes.get(role, [])
            if len(size_samples) >= 3:
                # 从历史大小中按频率采样
                size_counter = Counter(size_samples)
                size = self._weighted_choice(size_counter, r)
            else:
                # 无足够样本时用中位数4（常见字段宽度的合理默认值）
                size = 4
            fields.append((pos, pos + size, role))
            pos += size

        return fields

    def sample_bytes(self, fields: List[Tuple[int, int, str]],
                      total_size: Optional[int] = None,
                      rng: Optional[random.Random] = None,
                      ) -> bytes:
        """Level 1: 为字段序列生成字节内容"""
        r = rng or random
        if total_size is None:
            total_size = max(e for _, e, _ in fields) if fields else 64
        data = bytearray(total_size)

        for start, end, role in fields:
            for i in range(start, min(end, total_size)):
                if i == 0:
                    data[i] = r.randint(0, 255)
                else:
                    prev = data[i - 1]
                    dist = self._byte_transitions.get(i, {}).get(prev)
                    if dist:
                        data[i] = self._weighted_choice(dist, r)
                    else:
                        # fallback: 位置i的边际分布
                        marg = self._byte_marginal.get(i)
                        if marg:
                            data[i] = self._weighted_choice(marg, r)
                        else:
                            data[i] = r.randint(0, 255)
        return bytes(data)

    def generate(self, rng_seed: Optional[int] = None) -> bytes:
        """一站式生成: 消息类型→字段序列→字节"""
        r = random.Random(rng_seed)
        msg = self.sample_message_type(r)
        fields = self.sample_field_sequence(msg, r)
        return self.sample_bytes(fields, rng=r)

    @staticmethod
    def _weighted_choice(counter: Counter, rng: random.Random) -> Any:
        total = sum(counter.values())
        if total == 0:
            return rng.choice(list(counter.keys())) if counter else None
        r = rng.randint(1, total)
        cum = 0
        for item, count in counter.items():
            cum += count
            if r <= cum:
                return item
        return list(counter.keys())[0]

    def stats(self) -> Dict[str, Any]:
        return {
            "samples_learned": self._samples_learned,
            "byte_positions": len(self._byte_transitions),
            "field_roles": len(self._field_transitions),
            "message_types": len(self._msg_start),
        }
