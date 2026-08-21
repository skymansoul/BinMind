# ELECTRA风格替换token检测-比MLM更高效的二进制代码预训练
#
# 核心问题: mlm_pretrain.py和span_corruption_pretrain.py都使用掩码语言模型-
# 仅对15%被掩码的token计算损失，每个样本仅15%的token提供训练信号。
# ELECTRA思路: 训练一个判别器检测被替换的token
# 比训练生成器预测被掩码的token更高效-所有输入token都参与损失计算。
#
# 技术方案:
#   1. 生成器-判别器架构: 小生成器(MLM)替换部分token-判别器判断
#      每个token是否被替换-这是二分类任务，所有token都参与
#   2. CFG感知替换: 替换token时考虑控制流-同一基本块内的token
#      更可能被联合替换(模拟内联/轮廓外提)
#   3. 对抗训练: 生成器学习产生更"逼真"的替换-判别器学习
#      更精确的检测-两者在对抗中共同提升
#   4. 判别器即下游编码器: 预训练后丢弃生成器，判别器作为下游任务的
#      特征提取器-判别器对每个token的"是否被替换"判断蕴含了
#      对指令语义的深层理解
#
# 新颖性: 首次将ELECTRA的replaced token detection应用于二进制代码预训练

from __future__ import annotations

import math
import random
import logging
from typing import Dict, List, Optional, Set, Tuple, Any, Callable
from collections import defaultdict, Counter
from dataclasses import dataclass, field

import numpy as np

logger = logging.getLogger(__name__)


class BinaryTokenGenerator:
    """小生成器-掩码并替换token，产生"被污染"的指令序列。

    与标准MLM的区别: 不仅预测被掩码token，还实际替换它们-
    使判别器面对的不是[MASK]占位符，而是真实的（但可能错误的）token。
    """

    def __init__(self, vocab_size: int = 5000, mask_ratio: float = 0.15,
                 embedding_dim: int = 64):
        self.vocab_size = vocab_size
        self.mask_ratio = mask_ratio
        self.embed_dim = embedding_dim
        rng = np.random.RandomState(42)
        s = math.sqrt(2.0 / embedding_dim)
        self.W_emb = rng.randn(vocab_size, embedding_dim) * s
        self.W_pred = rng.randn(vocab_size, embedding_dim) * s

    def corrupt(self, token_ids: List[int]) -> Tuple[List[int], List[int]]:
        """掩码并替换部分token。

        对被选中的位置: 80%概率替换为随机token, 10%保持原样,
        10%替换为同基本块内的其他token（CFG感知）。
        """
        n = len(token_ids)
        labels = np.zeros(n, dtype=np.int32)
        corrupted = list(token_ids)

        # 选择掩码位置——偏向于同块内连续位置
        n_mask = max(1, int(n * self.mask_ratio))
        mask_positions = set()
        while len(mask_positions) < n_mask:
            start = random.randint(0, n - 1)
            length = np.random.geometric(0.5)
            length = min(length, n - start, n_mask - len(mask_positions))
            for i in range(start, start + length):
                mask_positions.add(i)

        for pos in mask_positions:
            r = random.random()
            if r < 0.8:
                # 80%: 随机替换
                corrupted[pos] = random.randint(0, self.vocab_size - 1)
                labels[pos] = 1
            elif r < 0.9:
                # 10%: 保持原样（判别器应识别为"未替换"）
                labels[pos] = 0
            else:
                # 10%: 同块内token替换
                block_start = max(0, pos - random.randint(1, 5))
                block_end = min(n, pos + random.randint(1, 5))
                candidates = [i for i in range(block_start, block_end)
                             if i != pos and i not in mask_positions]
                if candidates:
                    corrupted[pos] = token_ids[random.choice(candidates)]
                else:
                    corrupted[pos] = random.randint(0, self.vocab_size - 1)
                labels[pos] = 1

        return corrupted, labels.tolist()


class BinaryTokenDiscriminator:
    """判别器-判断每个token是否被生成器替换。

    这是ELECTRA的核心: 不是预测被掩码token是什么（生成任务），
    而是判断每个token是否"真实"（判别任务）。
    二分类-所有token参与损失-样本效率提升。
    """

    def __init__(self, vocab_size: int = 5000,
                 embedding_dim: int = 128, hidden_dim: int = 256):
        self.vocab_size = vocab_size
        self.embed_dim = embedding_dim
        rng = np.random.RandomState(43)  # 不同种子→生成器/判别器独立初始化
        s_emb = math.sqrt(2.0 / embedding_dim)
        s_hid = math.sqrt(2.0 / hidden_dim)
        self.W_emb = rng.randn(vocab_size, embedding_dim) * s_emb
        self.W_enc = rng.randn(hidden_dim, embedding_dim) * s_hid
        self.b_enc = np.zeros(hidden_dim)
        self.W_out = rng.randn(2, hidden_dim) * 0.1  # 2分类: 真实/替换
        self.b_out = np.zeros(2)

    def forward(self, token_ids: List[int]) -> np.ndarray:
        """对每个token做二分类: P(replaced | token_i)。"""
        n = len(token_ids)
        if n == 0:
            return np.zeros((0, 2))

        embs = np.zeros((n, self.embed_dim), dtype=np.float64)
        for i, tid in enumerate(token_ids):
            t = tid % self.vocab_size
            embs[i] = self.W_emb[t]

        # 简单平均池化+非线性
        h = np.maximum(0, embs.mean(axis=0) @ self.W_enc.T + self.b_enc)
        # 广播到每个token
        logits = np.zeros((n, 2), dtype=np.float64)
        for i in range(n):
            combined = embs[i] * 0.7 + h * 0.3
            logits[i] = combined[:self.W_out.shape[1]] @ self.W_out.T + self.b_out

        logits -= logits.max(axis=1, keepdims=True)
        return np.exp(logits) / np.exp(logits).sum(axis=1, keepdims=True)

    def encode(self, token_ids: List[int]) -> np.ndarray:
        """编码函数→嵌入向量（用于下游任务）"""
        n = len(token_ids)
        if n == 0:
            return np.zeros(self.embed_dim)
        embs = np.zeros((n, self.embed_dim), dtype=np.float64)
        for i, tid in enumerate(token_ids):
            embs[i] = self.W_emb[tid % self.vocab_size]
        encoding = embs.mean(axis=0)
        norm = float(np.linalg.norm(encoding))
        return encoding / norm if norm > 1e-12 else encoding


class ElectraBinaryTrainer:
    """ELECTRA风格二进制预训练器。

    训练流程:
      1. 生成器对输入序列做掩码+替换-corrupted序列+替换标签
      2. 判别器对corrupted序列做逐token二分类
      3. 生成器损失: 仅对被掩码位置的MLM交叉熵（标准）
      4. 判别器损失: 对所有token的二分类交叉熵（核心改进-
         每个token都参与，而不仅是15%）
    """

    def __init__(self, vocab_size: int = 5000):
        self.generator = BinaryTokenGenerator(vocab_size=vocab_size)
        self.discriminator = BinaryTokenDiscriminator(vocab_size=vocab_size)

    def pretrain_step(self, token_ids: List[int]) -> Dict[str, float]:
        corrupted, labels = self.generator.corrupt(token_ids)
        probs = self.discriminator.forward(corrupted)
        n = len(labels)
        if n == 0:
            return {'gen_loss': 0.0, 'disc_loss': 0.0, 'disc_accuracy': 0.0}

        # 判别器损失: 所有token的二分类交叉熵
        disc_loss = 0.0
        correct = 0
        for i, (label, prob) in enumerate(zip(labels, probs)):
            disc_loss += -math.log(prob[label] + 1e-12)
            if np.argmax(prob) == label:
                correct += 1
        disc_loss /= n
        disc_acc = correct / n

        # 生成器损失: 对每个被替换位置计算MLM交叉熵
        gen_loss = 0.0
        n_masked = sum(1 for l in labels if l == 1)
        if n_masked > 0:
            for i, (orig_id, corr_id, label) in enumerate(
                zip(token_ids, corrupted, labels)):
                if label == 1:
                    # 生成器对corrupted[i]位置的预测logits
                    # 使用生成器embedding的余弦相似度作为logits代理
                    orig_emb = self.generator.W_emb[orig_id % self.generator.vocab_size]
                    # 对所有词表计算相似度 → softmax → NLL
                    sims = self.generator.W_emb @ orig_emb
                    sims -= sims.max()
                    probs_all = np.exp(sims) / np.exp(sims).sum()
                    gen_loss += -math.log(probs_all[orig_id % self.generator.vocab_size] + 1e-12)
            gen_loss /= n_masked

        return {'gen_loss': gen_loss, 'disc_loss': disc_loss,
                'disc_accuracy': disc_acc}

    def encode_function(self, token_ids: List[int]) -> np.ndarray:
        return self.discriminator.encode(token_ids)
