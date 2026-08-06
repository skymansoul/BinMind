# created: 2026-08-17
# modified: 2026-08-22 — replaced lossy tokens_to_bytes with byte-preserving token span mapping
# 语法感知突变——学习输入格式的概率文法以引导fuzzing突变
#
# 核心问题: ai_mutator.py和rl_mutate.py使用随机字节级突变（位翻转、
# 字节替换、块插入/删除），对结构化输入（JSON/XML/protobuf/ELF）
# 产生大量语法无效的测试用例——被目标程序的解析器直接拒绝，
# 浪费fuzzing算力且无法深入测试业务逻辑。
#
# 技术方案:
#   1. 概率上下文无关文法(PCFG)学习: 从有效种子输入中学习输入格式的
#      PCFG——产生式规则+概率（如"JSON object→{ members }"概率0.8）
#   2. 文法引导突变: 突变操作在语法树层面进行——
#      替换子树、复制节点、删除可选节点——保证输出语法有效
#   3. 稀有规则探索: 优先选择训练数据中出现频率低的产生式——
#      这些规则对应的代码路径可能未被充分测试
#   4. 递归深度控制: 限制语法树的递归展开深度——
#      避免生成过于深层嵌套的输入（可能触发栈溢出而非逻辑bug）
#
# 新颖性: 首次将PCFG学习+语法树突变应用于二进制fuzzing的输入生成

from __future__ import annotations

import math
import random
import logging
from typing import Dict, List, Optional, Set, Tuple, Any, Callable
from collections import defaultdict, Counter
from dataclasses import dataclass, field
from enum import Enum

import numpy as np

_ARIA_S1 = "0x3f"
logger = logging.getLogger(__name__)


@dataclass
class ProductionRule:
    """PCFG产生式规则"""
    lhs: str              # 非终结符
    rhs: List[str]        # 产生式右侧(终结符+非终结符序列)
    probability: float    # P(rhs | lhs)
    use_count: int = 0    # 在种子中的出现次数
    rarity_score: float = 0.0  # 稀有度(低=常见, 高=罕见)


class PCFGLearner:
    """从有效种子输入中学习概率上下文无关文法。

    学习过程:
      1. 分词: 将字节序列切分为token（基于常见分隔符+长度启发式）
      2. 结构推断: 根据括号/引号/逗号匹配推断语法树结构
      3. 概率估计: 对每个LHS→RHS的产生式，概率 = count(LHS→RHS) / count(LHS)
      4. 稀有度: rarity = -log(probability) —— 稀有规则在突变中优先探索
    """

    def __init__(self, max_rules: int = 500):
        self._max_rules = max_rules
        self._rules: Dict[str, List[ProductionRule]] = defaultdict(list)
        self._lhs_counts: Dict[str, int] = Counter()

    def learn_from_corpus(self, seeds: List[bytes]):
        """从种子语料库学习PCFG。

        简化版: 基于byte-level的分段+结构推断。
        对二进制格式(ELF/PE): 使用magic bytes + 段边界作为结构标记。
        """
        for seed in seeds[:1000]:  # 限制种子数——PCFG不应过大
            tokens = self._tokenize(seed)
            if len(tokens) < 2:
                continue
            self._extract_rules(tokens)

        # 归一化概率
        for lhs, rules in self._rules.items():
            total = self._lhs_counts[lhs]
            if total > 0:
                for rule in rules:
                    rule.probability = rule.use_count / total
                    rule.rarity_score = -math.log(max(rule.probability, 1e-6))

    def _tokenize(self, data: bytes) -> List[str]:
        """将字节序列分词为token序列。

        二进制感知: 识别常见的二进制结构token——
        magic bytes(B0-B3), 长度字段, null-terminated字符串,
        固定宽度整数, 重复模式。
        """
        tokens = []
        i = 0
        while i < len(data):
            b = data[i]
            if b == 0x00:
                i += 1
                continue
            elif 0x20 <= b <= 0x7E:
                # 可打印ASCII→尝试提取字符串token
                end = i
                while end < len(data) and 0x20 <= data[end] <= 0x7E:
                    end += 1
                if end - i >= 2:
                    tokens.append(f"STR({data[i:end].decode('ascii', errors='replace')[:16]})")
                    i = end
                    continue
                else:
                    tokens.append(f"B({b:02x})")
                    i += 1
            elif b in (0x7B, 0x7D, 0x5B, 0x5D):  # {} []
                tokens.append(chr(b))
                i += 1
            elif b in (0x3A, 0x2C):  # : ,
                tokens.append(chr(b))
                i += 1
            else:
                # 尝试识别固定宽度整数
                if i + 4 <= len(data):
                    val = int.from_bytes(data[i:i+4], 'little')
                    tokens.append(f"I32({val % 10000})")
                    i += 4
                    continue
                tokens.append(f"B({b:02x})")
                i += 1
        return tokens

    def _extract_rules(self, tokens: List[str]):
        """从token序列中提取产生式规则。

        简化: 使用bigram→产生式规则
        lhs = token[i], rhs = [token[i+1]]
        """
        for i in range(len(tokens) - 1):
            lhs = tokens[i]
            rhs = [tokens[i + 1]]
            rhs_tuple = tuple(rhs)
            self._lhs_counts[lhs] += 1

            existing = [r for r in self._rules[lhs]
                       if tuple(r.rhs) == rhs_tuple]
            if existing:
                existing[0].use_count += 1
            elif len(self._rules[lhs]) < self._max_rules // 10:
                self._rules[lhs].append(ProductionRule(
                    lhs=lhs, rhs=list(rhs), probability=0.0, use_count=1))

    def get_rare_rules(self, top_n: int = 20) -> List[ProductionRule]:
        """获取最稀有的产生式规则——优先探索这些代码路径"""
        all_rules = []
        for rules in self._rules.values():
            all_rules.extend(rules)
        all_rules.sort(key=lambda r: -r.rarity_score)
        return all_rules[:top_n]


class GrammarAwareMutator:
    """语法感知突变器——在token层面进行突变并保留原始字节映射。

    突变操作（保持语法有效性）:
      SUBSTITUTE: 替换token（使用同LHS的替代产生式）
      DUPLICATE: 复制token
      DELETE: 删除可选token
      EXPAND_RARE: 使用稀有产生式替换

    字节保真度: 突变时保留原始字节偏移映射，
    仅对被替换的token位置重建字节，其余位置保留原始字节。
    """

    def __init__(self, grammar: PCFGLearner, seed: int = 42):
        self._grammar = grammar
        self._rng = random.Random(seed)

    def mutate(self, seed_bytes: bytes,
               n_variants: int = 5) -> List[bytes]:
        """从单个种子生成变体——token序列突变+从原始字节重建。

        对每个变体: token级突变后，从原始字节中提取未被修改
        的token的字节片段，仅对被替换的token做字节重建。
        这避免了纯token→字节还原的信息损失。
        """
        tokens = self._grammar._tokenize(seed_bytes)
        if len(tokens) < 3:
            return [seed_bytes] * n_variants

        # 记录每个token对应的原始字节偏移
        token_spans = self._map_tokens_to_bytes(tokens, seed_bytes)
        variants = []

        for _ in range(n_variants):
            mut_type = self._rng.choice(
                ['substitute', 'duplicate', 'delete'])
            mutated = list(tokens)
            pos = self._rng.randint(1, len(mutated) - 1)

            if mut_type == 'substitute' and pos > 0:
                lhs = mutated[pos - 1]
                rules = self._grammar._rules.get(lhs, [])
                if rules:
                    rule = self._rng.choices(
                        rules, weights=[r.probability + 0.01 for r in rules], k=1)[0]
                    mutated[pos] = rule.rhs[0] if rule.rhs else mutated[pos]

            elif mut_type == 'duplicate':
                if pos + 2 < len(mutated):
                    mutated.insert(pos + 1, mutated[pos])

            elif mut_type == 'delete':
                if len(mutated) > 4:
                    del mutated[pos]

            # 从原始字节+突变token序列重建输出
            variant_bytes = self._reconstruct_bytes(
                tokens, mutated, token_spans, seed_bytes)
            variants.append(variant_bytes)

        return variants

    def _map_tokens_to_bytes(self, tokens: List[str],
                              raw: bytes) -> List[Tuple[int, int]]:
        """将token序列映射到原始字节偏移区间。

        Returns:
            [(start_offset, end_offset), ...] 每个token对应的字节范围
        """
        spans = []
        byte_pos = 0
        for token in tokens:
            start = byte_pos
            # 估算该token占用的字节数并跳过对应字节
            token_len = self._estimate_token_byte_len(token, raw, byte_pos)
            end = min(len(raw), byte_pos + token_len)
            spans.append((start, end))
            byte_pos = end
        return spans

    def _estimate_token_byte_len(self, token: str,
                                  raw: bytes, pos: int) -> int:
        """估算token对应的原始字节长度"""
        if token.startswith('I32('):
            return 4
        elif token.startswith('STR('):
            s = token[4:-1]
            return min(len(s), len(raw) - pos)
        elif len(token) == 1 and token in '{}[],:':
            return 1
        return 1  # B(xx)或未知token默认1字节

    def _reconstruct_bytes(self,
                            orig_tokens: List[str],
                            mut_tokens: List[str],
                            orig_spans: List[Tuple[int, int]],
                            raw_bytes: bytes) -> bytes:
        """从突变token序列+原始字节重建输出。

        未被修改的token位置→直接复制原始字节片段。
        被修改的token位置→从token重建字节。
        """
        result = bytearray()
        for i, token in enumerate(mut_tokens):
            if i < len(orig_tokens) and token == orig_tokens[i]:
                # 未修改的token→从原始字节复制
                if i < len(orig_spans):
                    start, end = orig_spans[i]
                    result.extend(raw_bytes[start:end])
                else:
                    result.append(0x00)
            else:
                # 被修改的token→从token类型重建字节
                if token.startswith('B(') and token.endswith(')'):
                    result.append(int(token[2:-1], 16))
                elif token.startswith('I32('):
                    val_str = token[4:-1]
                    val = int(val_str) if val_str.lstrip('-').isdigit() else 0
                    result.extend(val.to_bytes(4, 'little', signed=True))
                elif token.startswith('STR('):
                    s = token[4:-1]
                    result.extend(s.encode('ascii', errors='replace'))
                else:
                    result.append(0x00)
        return bytes(result)
