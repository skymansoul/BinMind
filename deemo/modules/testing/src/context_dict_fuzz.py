# 上下文感知的字典Fuzzer — 基于字段角色的位置感知字典token插入
#
# 核心问题:
#   dictionary_builder.py 提取字典token但标记为全局——任何位置都可插入。
#   这导致大量无效输入: 在magic字段位置插入字符串, 在长度字段位置插入
#   随机token。AFL/AFL++的字典模式有同样问题: token无位置约束。
#
# 本模块的方法 — 字段位置约束的字典:
#   1. 从 taint_field_segmenter 获取字段边界和角色
#   2. 每个字典token关联到"它出现在哪个字段角色中"
#   3. 变异时仅在与token来源字段相同角色的位置插入token
#   4. 跨角色token: 观测到同一token出现在多种角色中→标记为通用token
#
# 字典条目结构:
#   {token, source_field_role, source_offset, frequency, is_universal}
#
# 文献:
#   AFL/AFL++ dictionary — 全局字典, 无位置感知;
#   ChatAFL — LLM提取语法token; 本项目取其结构化思想

from __future__ import annotations

import struct
from collections import defaultdict, Counter
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

# 桥接 dictionary_builder.py: ContextDictBuilder.ingest() 替代
# TokenExtractor.extract_strings() 等静态提取——增加字段上下文。
# 桥接 taint_field_segmenter.py: ingest() 的 fields 参数格式与
# FieldSegmentation.fields 兼容 (start/end/role 三元组)。


@dataclass
class ContextualToken:
    """带上下文约束的字典token"""
    token: bytes
    # 来源字段角色 (如 magic, length, type, data)
    source_role: str = "unknown"
    # 在来源输入中的偏移
    source_offset: int = 0
    # 观测频率
    frequency: int = 1
    # 是否为通用token (出现在≥2种不同角色中)
    is_universal: bool = False
    # token类型
    is_string: bool = False
    is_integer: bool = False
    is_binary: bool = False


@dataclass
class ContextDict:
    """上下文感知字典——按角色索引"""
    # role → list of tokens
    by_role: Dict[str, List[ContextualToken]] = field(
        default_factory=lambda: defaultdict(list))
    # 通用token (可插入任何位置)
    universal: List[ContextualToken] = field(default_factory=list)
    # 统计
    total_tokens: int = 0


class ContextDictBuilder:
    """上下文感知字典构建器。

    典型用法:
        builder = ContextDictBuilder()
        # 从样本+字段分割构建:
        for sample, fields in zip(samples, field_segmentations):
            builder.ingest(sample, fields)
        cd = builder.build()
        # 变异时:
        token = cd.sample_for_position(offset, role, rng)
    """

    def __init__(self, min_token_len: int = 2,
                  max_token_len: int = 32,
                  universal_threshold: int = 2):
        self._min_len = min_token_len
        self._max_len = max_token_len
        self._universal_thresh = universal_threshold
        # token → set of roles it appears in
        self._token_roles: Dict[bytes, Set[str]] = defaultdict(set)
        # role → Counter[token → frequency]
        self._role_token_freq: Dict[str, Counter] = defaultdict(Counter)

    def ingest(self, data: bytes,
                fields: List[Tuple[int, int, str]]) -> None:
        """从一份样本+其字段分割中提取上下文token"""
        for start, end, role in fields:
            if start >= len(data):
                continue
            chunk = data[start:min(end, len(data))]

            # 提取子token: 滑动窗口 n-gram
            for win_len in range(self._min_len,
                                  min(self._max_len, len(chunk)) + 1):
                for i in range(len(chunk) - win_len + 1):
                    token = chunk[i:i + win_len]
                    if self._is_meaningful(token):
                        self._token_roles[token].add(role)
                        self._role_token_freq[role][token] += 1

    def build(self) -> ContextDict:
        """构建最终的上下文感知字典"""
        cd = ContextDict()

        for token, roles in self._token_roles.items():
            is_univ = len(roles) >= self._universal_thresh
            for role in roles:
                freq = self._role_token_freq.get(role, Counter()).get(token, 1)
                ct = ContextualToken(
                    token=token, source_role=role,
                    frequency=freq, is_universal=is_univ,
                    is_string=self._looks_like_string(token),
                    is_integer=self._looks_like_integer(token),
                    is_binary=not (self._looks_like_string(token)
                                    or self._looks_like_integer(token)),
                )
                cd.by_role[role].append(ct)
                if is_univ:
                    cd.universal.append(ct)
                cd.total_tokens += 1

        # 去重universal
        seen = set()
        cd.universal = [t for t in cd.universal
                         if not (t.token in seen or seen.add(t.token))]

        return cd

    @staticmethod
    def _is_meaningful(token: bytes) -> bool:
        if len(token) < 2:
            return False
        # 排除全零/全FF (常见填充)
        if token == b'\x00' * len(token) or token == b'\xFF' * len(token):
            return False
        return True

    @staticmethod
    def _looks_like_string(token: bytes) -> bool:
        return all(0x20 <= b <= 0x7E for b in token)

    @staticmethod
    def _looks_like_integer(token: bytes) -> bool:
        return len(token) in (1, 2, 4, 8)


class ContextDictMutator:
    """上下文感知字典变异器。

    对给定输入和字段分割, 在对应位置插入匹配的字典token。
    """

    def __init__(self, context_dict: ContextDict):
        self._dict = context_dict

    def mutate(self, data: bytes,
                fields: List[Tuple[int, int, str]],
                rng_seed: Optional[int] = None) -> bytes:
        """执行上下文感知变异——在匹配位置插入/替换字典token"""
        import random as _rnd
        rng = _rnd.Random(rng_seed)
        buf = bytearray(data)

        for start, end, role in fields:
            if start >= len(buf):
                continue

            # 50%概率: 从该角色的字典中选token
            candidates = self._dict.by_role.get(role, [])
            if not candidates and self._dict.universal:
                candidates = self._dict.universal
            if not candidates:
                continue

            token = rng.choice(candidates).token
            if rng.random() < 0.5:
                # 替换模式: 用token覆盖该字段
                for i, b in enumerate(token):
                    if start + i < len(buf):
                        buf[start + i] = b
            else:
                # 插入模式: 在字段起始处插入token
                buf[start:start] = token

        return bytes(buf)

    def plan_mutations(self, data: bytes,
                        fields: List[Tuple[int, int, str]],
                        count: int = 5) -> List[Tuple[int, bytes, str]]:
        """生成变异计划—— [(offset, token, role), ...]"""
        import random as _rnd
        rng = _rnd.Random()
        plans: List[Tuple[int, bytes, str]] = []

        for start, _, role in fields:
            candidates = self._dict.by_role.get(role, [])
            if not candidates:
                candidates = self._dict.universal
            if not candidates or len(plans) >= count:
                continue
            token = rng.choice(candidates).token
            plans.append((start, token, role))

        return plans
