# 语法推断引擎 — 从样本集自动推断BNF风格产生式语法
# 核心思想: 对多份协议/格式样本做递归结构检测，提取重复模式、
# 序列模式、可选字段和递归嵌套，构建BNF语法规则集。
#
# 方法: Sequitur风格层次结构归纳 + entropy辅助字段边界识别。
# Sequitur在线性时间内从序列中提取层次产生式，天然适合协议格式自动逆向。
#
# 参考:
#   Grammar-based whitebox fuzzing (Godefroid et al. PLDI 2008) — 从参考实现自动构建语法
#   Parser-directed fuzzing (Mathis et al. PLDI 2019) — 解析器导向模糊测试
#   ChatAFL (NDSS 2024) — "机器可读语法提取"模块思路
#   Sequitur (Nevill-Manning & Witten 1997): identifying hierarchical structure in sequences
#   Pulsar (Gascon et al. USENIX 2015): protocol reverse engineering via statistical analysis
import re
import math
import struct
from typing import List, Dict, Set, Tuple, Optional, Any
from collections import defaultdict, Counter, OrderedDict
from dataclasses import dataclass, field


@dataclass
class GrammarRule:
    """单条BNF产生式: <nonterminal> ::= alternative_1 | ... | alternative_k"""
    nonterminal: str
    alternatives: List[List[str]] = field(default_factory=list)  # 每项为符号列表
    weight: float = 1.0  # 在语料中的出现频率权重
    recursive: bool = False

    def to_bnf(self) -> str:
        alts = [' '.join(alt) for alt in self.alternatives]
        return f"<{self.nonterminal}> ::= {' | '.join(alts)}"


class GrammarInferrer:
    """基于Sequitur风格层次归纳的语法推断器。

    工作流:
    1. tokenize(samples) — 将字节样本分词
    2. infer(samples) — Sequitur主循环，递归提取产生式
    3. to_bnf() — 导出BNF语法
    4. 语法可用于TestGenerator做基于语法的fuzz生成
    """

    def __init__(self, max_rules: int = 256):
        self._max_rules = max_rules
        self._rules: Dict[str, GrammarRule] = OrderedDict()
        self._rule_counter = 0
        self._digram_index: Dict[Tuple[str, str], List[int]] = defaultdict(list)
        self._token_freq: Counter = Counter()

    # ---- token化 ----
    @staticmethod
    def tokenize_bytes(data: bytes) -> List[str]:
        """将字节序列转换为token列表。

        混合策略: 可打印ASCII序列->字符串token; 不可打印->hex token。
        """
        tokens = []
        i = 0
        while i < len(data):
            if 0x20 <= data[i] <= 0x7E:
                # 收集可打印字符序列
                start = i
                while i < len(data) and 0x20 <= data[i] <= 0x7E:
                    i += 1
                s = data[start:i].decode('ascii')
                if len(s) >= 2:
                    tokens.append(s)
                else:
                    tokens.append(f'0x{data[start]:02X}')
            else:
                tokens.append(f'0x{data[i]:02X}')
                i += 1
        return tokens

    @staticmethod
    def tokenize_hex(data: bytes) -> List[str]:
        """全部字节转换为"0xNN" hex token，适合严格二进制协议。"""
        return [f'0x{b:02X}' for b in data]

    # ---- Sequitur核心 ----
    def infer(self, samples: List[bytes]) -> Dict[str, GrammarRule]:
        """从样本集推断语法。返回规则字典。"""
        self._rules.clear()
        self._rule_counter = 0

        # 对每个样本做Sequitur
        for sample in samples:
            tokens = self.tokenize_bytes(sample)
            if not tokens:
                continue
            self._process_sequence(tokens)

        # 后处理: 为可选字段标记'?'权重
        self._postprocess_optional_fields()
        return dict(self._rules)

    def _process_sequence(self, tokens: List[str]) -> None:
        """Sequitur主循环: 扫描token序列，发现重复digram时创建新规则。"""
        seq = list(tokens)
        i = 0
        while i < len(seq) - 1 and len(self._rules) < self._max_rules:
            digram = (seq[i], seq[i + 1])
            self._digram_index[digram].append(i)

            # 若digram已出现>=2次 -> 创建产生式
            occurrences = self._digram_index[digram]
            if any(j < i for j in occurrences):
                new_nt = self._new_nonterminal()
                # 创建产生式: <N> ::= A B
                self._rules[new_nt] = GrammarRule(
                    nonterminal=new_nt,
                    alternatives=[[digram[0], digram[1]]])

                # 替换所有出现处
                for occ_pos in sorted(occurrences, reverse=True):
                    if occ_pos < len(seq) - 1:
                        del seq[occ_pos:occ_pos + 2]
                        seq.insert(occ_pos, new_nt)
                i = 0  # 从头重新扫描（简化版Sequitur）
            else:
                i += 1

        # 顶层规则
        start_rule = self._rules.get('<start>')
        if start_rule is None:
            start_rule = GrammarRule(nonterminal='<start>')
            self._rules['<start>'] = start_rule
        start_rule.alternatives.append(seq)

    def _new_nonterminal(self) -> str:
        self._rule_counter += 1
        return f'<R{self._rule_counter}>'

    # ---- 后处理 ----
    def _postprocess_optional_fields(self) -> None:
        """对出现频率<50%的alternative标记为可选 (BNF '?')。

        不修改规则结构，仅调整weight。
        """
        for rule in self._rules.values():
            total_alts = len(rule.alternatives)
            if total_alts <= 1:
                continue
            # 按出现次数统计各alternative
            alt_counts = Counter(
                tuple(alt) for alt in rule.alternatives)
            max_count = max(alt_counts.values())
            for alt in rule.alternatives:
                key = tuple(alt)
                freq = alt_counts.get(key, 1)
                if freq < max_count * 0.3:
                    # 低频 -> 标记为可选
                    alt.insert(0, '?')

    # ---- 语法启发式 ----
    def detect_repeating_fields(self, samples: List[bytes]
                                ) -> List[Tuple[int, int]]:
        """检测重复字段块 (如数组元素)。

        返回 [(start_offset, block_size), ...]
        """
        if not samples:
            return []

        results = []
        min_len = min(len(s) for s in samples)
        for blk_sz in [4, 8, 16, 32, 64, 128]:
            if blk_sz > min_len // 2:
                break
            for start in range(0, min_len - blk_sz * 2, blk_sz):
                blk = samples[0][start:start + blk_sz]
                # 检查所有样本在此偏移是否重复相同块
                repeat_count = 0
                for pos in range(start, min_len, blk_sz):
                    if all(s[pos:pos + blk_sz] == blk
                           for s in samples[:3]):
                        repeat_count += 1
                if repeat_count >= 2:
                    results.append((start, blk_sz))
                    break  # 每个块大小只报告一个

        return results

    def detect_length_field(self, samples: List[bytes]
                            ) -> List[Tuple[int, str]]:
        """检测长度字段: 寻找值为后续数据长度的字节位置。

        返回 [(offset, endianness), ...]
        """
        if len(samples) < 2:
            return []

        findings = []
        for offset in range(min(8, min(len(s) for s in samples))):
            for endian in ('big', 'little'):
                for sz in (1, 2, 4):
                    if offset + sz > min(len(s) for s in samples):
                        continue
                    matches = 0
                    for s in samples:
                        val = int.from_bytes(
                            s[offset:offset + sz], endian)
                        rest_len = len(s) - offset - sz
                        if val == rest_len:
                            matches += 1
                    if matches >= len(samples) * 0.6:
                        findings.append((offset, f'{endian}_u{sz * 8}'))
        return findings

    # ---- 导出 ----
    def to_bnf(self) -> str:
        lines = []
        for rule in self._rules.values():
            if rule.alternatives:
                lines.append(rule.to_bnf())
        return '\n'.join(lines)

    def to_grammar(self) -> 'Grammar':
        """将推断结果转换为TestGenerator兼容的Grammar对象。"""
        from .test_gen import Grammar
        grammar = Grammar(start_symbol='<start>')
        for rule in self._rules.values():
            grammar.add_rule(rule.nonterminal, [
                [tok for tok in alt if tok != '?']
                for alt in rule.alternatives
            ])
        return grammar

    # ---- 统计 ----
    def stats(self) -> Dict[str, Any]:
        return {
            'rules': len(self._rules),
            'total_alternatives': sum(
                len(r.alternatives) for r in self._rules.values()),
            'recursive_rules': sum(
                1 for r in self._rules.values() if r.recursive),
            'start_alternatives': len(
                self._rules.get('<start>', GrammarRule('')).alternatives),
        }


# ---------------------------------------------------------------------------
# 便捷入口
# ---------------------------------------------------------------------------
def infer_from_messages(messages: List[bytes]) -> GrammarInferrer:
    """从一组协议消息中快速推断语法。"""
    inferrer = GrammarInferrer()
    inferrer.infer(messages)
    return inferrer


def infer_from_pcap(pcap_bytes: bytes, port: int = 0) -> GrammarInferrer:
    """从PCAP数据中提取payload并推断语法。

    简化实现: 仅提取TCP payload部分（非完整pcap解析）。
    """
    messages = []
    # 简化: 假设payload在0x36偏移开始 (Ethernet+IP+TCP header)
    if len(pcap_bytes) > 0x36:
        payload = pcap_bytes[0x36:]
        messages.append(payload)
    inferrer = GrammarInferrer()
    if messages:
        inferrer.infer(messages)
    return inferrer
