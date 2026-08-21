# 跨度损坏预训练-面向二进制代码的CFG感知跨度掩码语言模型
#
# 核心问题: mlm_pretrain.py使用token级随机掩码-一条指令的助记符和操作数
# 被分别掩码，模型通过部分操作数即可推断掩码内容（捷径学习）。
#
# 技术方案:
#   1. 指令跨度掩码: 整条指令作为不可分跨度被掩码
#   2. CFG感知: 基本块内连续指令联合掩码（模拟编译器变换）
#   3. 几何分布跨度长度: 短跨度多，长跨度少
#   4. 控制流保护: 分支指令不掩码
#
# 掩码生成器实现在 src/pretrain/span_masker.py

from __future__ import annotations

import math
import logging
from typing import Dict, List, Optional, Set, Tuple, Any

import numpy as np

from .src.pretrain.span_masker import (
    AssemblyTokenizer, SpanMask, CFGSpanCorrupter,
)

logger = logging.getLogger(__name__)


class SpanCorruptionTrainer:
    """跨度损坏预训练-二进制代码的CFG感知掩码语言模型。

    训练目标: 给定corrupted序列+哨兵token，预测被掩码的token序列。
    此目标迫使模型理解指令语义和控制流上下文，而非token共现。
    """

    def __init__(self,
                 vocab_size: int = 10000,
                 embedding_dim: int = 128,
                 hidden_dim: int = 256,
                 learning_rate: float = 0.001):
        self.vocab_size = vocab_size
        self.embed_dim = embedding_dim
        self.hidden_dim = hidden_dim
        self.lr = learning_rate
        self._tokenizer = AssemblyTokenizer()
        self._corrupter = CFGSpanCorrupter()

        rng = np.random.RandomState(42)
        s = math.sqrt(2.0 / embedding_dim)
        self.token_embed = rng.randn(vocab_size, embedding_dim) * s
        self.pos_embed = rng.randn(512, embedding_dim) * s
        self.W_enc = rng.randn(hidden_dim, embedding_dim) * s
        self.b_enc = np.zeros(hidden_dim)
        self.W_dec = rng.randn(vocab_size, hidden_dim) * s
        self.b_dec = np.zeros(vocab_size)

    def pretrain_step(self,
                      instructions: List[str],
                      cfg_blocks: Optional[List[Tuple[int, int]]] = None
                      ) -> float:
        tokenized = self._tokenizer.tokenize_instructions(instructions)
        n_instrs = len(tokenized)
        if n_instrs < 3:
            return 0.0

        # 分支检测
        branch_idx = {i for i, t in enumerate(tokenized)
                      if t and t[0] in ('jmp', 'je', 'jne', 'jz', 'jnz',
                                        'jg', 'jl', 'jge', 'jle', 'ja',
                                        'jb', 'call', 'ret', 'syscall')}

        spans = self._corrupter.generate_spans(n_instrs, cfg_blocks, branch_idx)
        corrupted, _, targets = self._corrupter.apply_masks(tokenized, spans)
        if not targets:
            return 0.0

        # 上下文编码: 最近50个token的平均嵌入
        all_tokens = []
        for instr_tokens in corrupted:
            all_tokens.extend(instr_tokens)

        total_loss = 0.0
        for target_tokens in targets:
            if not target_tokens:
                continue
            encoding = np.zeros(self.embed_dim, dtype=np.float64)
            count = 0
            for tok in all_tokens[-50:]:
                tid = hash(tok) % self.vocab_size
                encoding += self.token_embed[tid]
                count += 1
            if count > 0:
                encoding /= count

            h = np.maximum(0, encoding @ self.W_enc.T + self.b_enc)
            for tok in target_tokens:
                tid = hash(tok) % self.vocab_size
                logits = h @ self.W_dec.T + self.b_dec
                logits -= logits.max()
                probs = np.exp(logits) / np.exp(logits).sum()
                total_loss += -math.log(probs[tid] + 1e-12)

        return float(total_loss / max(1, sum(len(t) for t in targets)))

    def encode_function(self,
                        instructions: List[str],
                        cfg_blocks: Optional[List[Tuple[int, int]]] = None
                        ) -> np.ndarray:
        """将二进制函数编码为密集嵌入-用于下游漏洞检测等任务。"""
        tokenized = self._tokenizer.tokenize_instructions(instructions)
        all_tokens = []
        for instr_tokens in tokenized:
            all_tokens.extend(instr_tokens)
        if not all_tokens:
            return np.zeros(self.embed_dim, dtype=np.float64)

        encoding = np.zeros(self.embed_dim, dtype=np.float64)
        for pos, tok in enumerate(all_tokens[:512]):
            tid = hash(tok) % self.vocab_size
            encoding += self.token_embed[tid] + self.pos_embed[pos]
        encoding /= max(1, len(all_tokens))
        norm = np.linalg.norm(encoding)
        return encoding / norm if norm > 1e-12 else encoding
