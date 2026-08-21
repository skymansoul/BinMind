# 神经分支预测模型 + 种子特征提取
# 用于 neural_branch_predictor.py 的模糊测试种子优先级排序
#
# 模型架构: 2层MLP（~300维→64→n_branches），参数量~25K
# 适合在线学习-每batch单步SGD更新

import math
import logging
from typing import Dict, List, Optional, Tuple, Any, Callable
from collections import Counter
from dataclasses import dataclass

import numpy as np

logger = logging.getLogger(__name__)


@dataclass
class SeedFeatures:
    """模糊测试种子的字节级特征。

    特征选择理由:
      byte_histogram: 捕获结构（文本vs二进制、magic bytes）
      entropy_per_16byte: 高熵=压缩/加密数据（难以影响控制流）
      ngram_features: 捕获字符串常量和协议头
      printable/null/high_byte: 字节类分布
    """
    seed_id: str
    size: int
    byte_histogram: np.ndarray
    entropy_per_16byte: np.ndarray
    ngram_features: np.ndarray
    printable_ratio: float
    null_ratio: float
    high_byte_ratio: float
    branch_coverage: Optional[np.ndarray] = None

    def to_input_vector(self) -> np.ndarray:
        parts = [self.byte_histogram / max(1, self.size)]
        ent = self.entropy_per_16byte
        if len(ent) > 32:
            ent = np.array([np.mean(ent[i::32]) for i in range(32)])
        elif len(ent) < 32:
            ent = np.pad(ent, (0, 32 - len(ent)), mode='constant')
        parts.append(ent[:32])
        parts.append(self.ngram_features[:32])
        parts.append(np.array([
            self.printable_ratio, self.null_ratio, self.high_byte_ratio,
            min(1.0, self.size / 10000.0), math.log(1 + self.size) / 10.0,
        ]))
        return np.concatenate(parts)


class SeedFeatureExtractor:
    """从模糊测试种子中提取字节级统计特征"""

    NGRAM_TOP = 32
    ENTROPY_BLOCK = 16

    def extract(self, seed_bytes: bytes, seed_id: str = "") -> SeedFeatures:
        size = len(seed_bytes)
        if size == 0:
            return SeedFeatures(seed_id=seed_id, size=0,
                byte_histogram=np.zeros(256),
                entropy_per_16byte=np.zeros(1),
                ngram_features=np.zeros(self.NGRAM_TOP),
                printable_ratio=0.0, null_ratio=0.0, high_byte_ratio=0.0)

        hist = np.zeros(256, dtype=np.float64)
        for b in seed_bytes:
            hist[b] += 1.0

        n_blocks = max(1, (size + self.ENTROPY_BLOCK - 1) // self.ENTROPY_BLOCK)
        entropies = np.zeros(n_blocks, dtype=np.float64)
        for i in range(n_blocks):
            start = i * self.ENTROPY_BLOCK
            end = min(start + self.ENTROPY_BLOCK, size)
            block = seed_bytes[start:end]
            if len(block) > 1:
                bc = Counter(block)
                ent = -sum((c/len(block)) * math.log(c/len(block) + 1e-12)
                          for c in bc.values())
                entropies[i] = ent

        bigram_counts = Counter()
        for i in range(size - 1):
            bigram_counts[(seed_bytes[i], seed_bytes[i+1])] += 1
        top_bigrams = sorted(bigram_counts.items(), key=lambda x: -x[1])
        ngram_vec = np.zeros(self.NGRAM_TOP, dtype=np.float64)
        for idx, (_, count) in enumerate(top_bigrams[:self.NGRAM_TOP]):
            ngram_vec[idx] = count / max(1, size - 1)

        printable = sum(1 for b in seed_bytes if 0x20 <= b <= 0x7E)
        nulls = sum(1 for b in seed_bytes if b == 0x00)
        high_bytes = sum(1 for b in seed_bytes if b >= 0x80)

        return SeedFeatures(
            seed_id=seed_id, size=size,
            byte_histogram=hist, entropy_per_16byte=entropies,
            ngram_features=ngram_vec,
            printable_ratio=printable / size,
            null_ratio=nulls / size,
            high_byte_ratio=high_bytes / size,
        )


class NeuralBranchModel:
    """轻量神经分支预测模型。

    架构: INPUT_DIM→HIDDEN_DIM→n_branches (2层MLP, sigmoid输出)
    输出: 每个分支被触发的概率
    参数量: 300*64 + 64 + 64*n_branches + n_branches ≈ 25K

    在线更新: 每轮用BCE损失的SGD单步更新
    不确定性: 预测概率的熵-高熵=未充分探索的输入区域
    """

    INPUT_DIM = 325
    HIDDEN_DIM = 64

    def __init__(self, n_branches: int = 256, learning_rate: float = 0.01):
        self.n_branches = n_branches
        self.lr = learning_rate
        rng = np.random.RandomState(42)
        s1 = math.sqrt(2.0 / self.INPUT_DIM)
        s2 = math.sqrt(2.0 / self.HIDDEN_DIM)
        self.W1 = rng.randn(self.HIDDEN_DIM, self.INPUT_DIM) * s1
        self.b1 = np.zeros(self.HIDDEN_DIM)
        self.W2 = rng.randn(n_branches, self.HIDDEN_DIM) * s2
        self.b2 = np.zeros(n_branches)
        self._trained = False

    def predict(self, input_vec: np.ndarray) -> np.ndarray:
        x = input_vec[:self.INPUT_DIM]
        if len(x) < self.INPUT_DIM:
            x = np.pad(x, (0, self.INPUT_DIM - len(x)), mode='constant')
        h = np.maximum(0, x @ self.W1.T + self.b1)
        logits = h @ self.W2.T + self.b2
        return 1.0 / (1.0 + np.exp(-np.clip(logits, -20, 20)))

    def update(self, input_vec: np.ndarray, observed_coverage: np.ndarray,
               lr_decay: float = 0.99):
        x = input_vec[:self.INPUT_DIM]
        if len(x) < self.INPUT_DIM:
            x = np.pad(x, (0, self.INPUT_DIM - len(x)), mode='constant')
        h = np.maximum(0, x @ self.W1.T + self.b1)
        logits = h @ self.W2.T + self.b2
        preds = 1.0 / (1.0 + np.exp(-np.clip(logits, -20, 20)))
        eps = 1e-8
        d_logits = (preds - observed_coverage) / max(1, len(observed_coverage))
        d_W2 = np.outer(d_logits, h)
        d_h = d_logits @ self.W2
        d_h[h <= 0] = 0
        d_W1 = np.outer(d_h, x)

        lr = self.lr * lr_decay
        self.W2 -= lr * d_W2
        self.b2 -= lr * d_logits
        self.W1 -= lr * d_W1
        self.b1 -= lr * d_h
        self._trained = True

    def prediction_uncertainty(self, input_vec: np.ndarray) -> float:
        probs = self.predict(input_vec)
        eps = 1e-12
        entropy = -(probs * np.log(probs + eps) +
                   (1 - probs) * np.log(1 - probs + eps))
        return float(np.mean(entropy))

    def byte_attribution(self, seed_bytes: bytes,
                         extractor) -> Dict[int, float]:
        """逐字节消融归因: 屏蔽每个字节，观察预测变化量"""
        baseline_vec = extractor.extract(seed_bytes).to_input_vector()
        baseline_pred = self.predict(baseline_vec)
        attributions = {}
        step = max(1, len(seed_bytes) // 50)
        for offset in range(0, len(seed_bytes), step):
            modified = bytearray(seed_bytes)
            modified[offset] = 0x00
            mod_pred = self.predict(
                extractor.extract(bytes(modified)).to_input_vector())
            attributions[offset] = float(
                np.mean(np.abs(baseline_pred - mod_pred)))
        return attributions
