# CFG感知跨度掩码生成器 + 汇编分词器
# 用于 span_corruption_pretrain.py 的二进制跨度损坏预训练

import random
import logging
from typing import Dict, List, Optional, Set, Tuple
from collections import defaultdict
from dataclasses import dataclass

import numpy as np

logger = logging.getLogger(__name__)


class AssemblyTokenizer:
    """汇编指令分词-归一化立即数和地址到特殊token。

    指令 mov eax, 0x1234 → ['mov', 'eax', '<HEX>']
    地址访问 [rbp-0x10] → '<MEM>'
    """

    def tokenize_instructions(self, instructions: List[str]
                              ) -> List[List[str]]:
        tokenized = []
        for instr in instructions:
            tokens = self._tokenize_single(instr)
            if tokens:
                tokenized.append(tokens)
        return tokenized

    def _tokenize_single(self, instr: str) -> List[str]:
        stripped = instr.strip()
        if not stripped or stripped.startswith(';') or stripped.startswith('#'):
            return []
        parts = stripped.replace(',', ' ').split()
        tokens = []
        for part in parts:
            if part.startswith('0x') or part.startswith('-0x'):
                tokens.append('<HEX>')
            elif part.lstrip('-').isdigit():
                tokens.append('<NUM>')
            elif '[' in part or ']' in part:
                tokens.append('<MEM>')
            else:
                tokens.append(part.lower())
        return tokens


@dataclass
class SpanMask:
    start_instr_idx: int
    length: int
    block_id: int

    @property
    def end_instr_idx(self) -> int:
        return self.start_instr_idx + self.length


class CFGSpanCorrupter:
    """CFG感知的跨度掩码。

    掩码策略:
      1. 总掩码比例: 15%指令
      2. 跨度长度: 几何分布(p=0.4, 均值≈2.5)
      3. 基本块联合掩码概率: 20%
      4. 分支保护: 分支指令不掩码
    """

    def __init__(self, mask_ratio: float = 0.15,
                 geometric_p: float = 0.4,
                 block_mask_prob: float = 0.2):
        self.mask_ratio = mask_ratio
        self.geo_p = geometric_p
        self.block_mask_prob = block_mask_prob

    def generate_spans(self,
                       n_instructions: int,
                       cfg_blocks: Optional[List[Tuple[int, int]]] = None,
                       branch_indices: Optional[Set[int]] = None
                       ) -> List[SpanMask]:
        if cfg_blocks is None:
            cfg_blocks = [(i, min(i + 5, n_instructions))
                         for i in range(0, n_instructions, 5)]
        if branch_indices is None:
            branch_indices = set()

        target_masked = int(n_instructions * self.mask_ratio)
        masked_count = 0
        spans = []
        masked_per_instr = [False] * n_instructions

        # 相位1: 基本块级掩码
        for block_id, (bs, be) in enumerate(cfg_blocks):
            blen = be - bs
            if blen < 2:
                continue
            if random.random() < self.block_mask_prob:
                actual = []
                for i in range(bs, be):
                    if (i not in branch_indices and
                        not masked_per_instr[i] and
                        masked_count < target_masked):
                        actual.append(i)
                        masked_per_instr[i] = True
                        masked_count += 1
                if actual:
                    spans.append(SpanMask(actual[0], len(actual), block_id))

        # 相位2: 指令级跨度掩码
        while masked_count < target_masked:
            available = [i for i in range(n_instructions)
                        if not masked_per_instr[i] and i not in branch_indices]
            if not available:
                break
            start = random.choice(available)
            span_len = np.random.geometric(self.geo_p)
            span_len = min(span_len, n_instructions - start)

            for bid, (bs, be) in enumerate(cfg_blocks):
                if bs <= start < be:
                    span_len = min(span_len, be - start)
                    break

            actual = []
            for i in range(start, start + span_len):
                if (i < n_instructions and not masked_per_instr[i]
                    and i not in branch_indices
                    and masked_count < target_masked):
                    actual.append(i)
                    masked_per_instr[i] = True
                    masked_count += 1
            if actual:
                spans.append(SpanMask(actual[0], len(actual), -1))
        return spans

    def apply_masks(self,
                    tokenized_instrs: List[List[str]],
                    spans: List[SpanMask],
                    mask_token: str = "<MASK>",
                    sentinel_prefix: str = "<S_"
                    ) -> Tuple[List[List[str]], List[List[str]], List[List[str]]]:
        n_instrs = len(tokenized_instrs)
        masked_indices: Set[int] = set()
        for span in spans:
            for i in range(span.start_instr_idx,
                          min(span.start_instr_idx + span.length, n_instrs)):
                masked_indices.add(i)

        corrupted = []
        targets: List[List[str]] = []
        current_target: List[str] = []
        in_span = False
        sentinel_idx = 0

        for i in range(n_instrs):
            if i in masked_indices:
                if not in_span:
                    sentinel = f"{sentinel_prefix}{sentinel_idx}>"
                    corrupted.append([sentinel])
                    sentinel_idx += 1
                    in_span = True
                current_target.extend(tokenized_instrs[i])
                corrupted.append([mask_token] * len(tokenized_instrs[i]))
            else:
                if in_span and current_target:
                    targets.append(current_target)
                    current_target = []
                    sentinel = f"{sentinel_prefix}{sentinel_idx}>"
                    corrupted.append([sentinel])
                    sentinel_idx += 1
                    in_span = False
                corrupted.append(tokenized_instrs[i][:])
        if in_span and current_target:
            targets.append(current_target)
        return corrupted, tokenized_instrs, targets
