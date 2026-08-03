"""原始字节级嵌入 — 从二进制文件的十六进制表示学习函数表示"""
# 依据: ContraBin [Zhang et al. TMLR 2025] 的三模态对比学习 (源代码+二进制+注释)
# DiffBCE [Zhang & Cheng, IST 2025] 的差分对比学习
# 核心: 绕过反汇编需求, 直接从raw bytes提取语义信息
# 用途: 处理无法反汇编的混淆/加壳代码; 作为CFG/GNN嵌入的多模态补充

from __future__ import annotations
import math
import random
import hashlib
import logging
from typing import Dict, List, Optional, Tuple, Any
from collections import defaultdict, Counter
from dataclasses import dataclass

logger = logging.getLogger(__name__)


# ========== 辅助 ==========

def _hb_dot(a: List[float], b: List[float]) -> float:
    return sum(x * y for x, y in zip(a, b))

def _hb_l2_norm(v: List[float]) -> List[float]:
    n = math.sqrt(sum(x * x for x in v))
    if n < 1e-12:
        return v[:]
    return [x / n for x in v]

def _hb_zeros(n: int) -> List[float]:
    return [0.0] * n


# ========== 字节嵌入器 ==========

class ByteSequenceEmbedder:
    """原始字节序列嵌入器

    设计: 将字节流视为一种"语言", 通过n-gram哈希 + 局部上下文窗口
    产生固定维度的嵌入向量。类似于 ContraBin 的二进制模态分支。

    不需要反汇编 — 直接对原始二进制字节工作。
    对加壳/混淆代码仍然有效 (尽管语义可能被遮蔽)。
    """

    def __init__(self, embed_dim: int = 256, ngram_sizes: List[int] = None,
                 window_size: int = 16, stride: int = 4):
        self.dim = embed_dim
        self.ngrams = ngram_sizes or [1, 2, 3, 4]
        self.window = window_size
        self.stride = stride

    def embed_bytes(self, data: bytes) -> List[float]:
        """将字节序列嵌入到固定维度向量"""
        if len(data) == 0:
            return _hb_zeros(self.dim)

        # 单字节频率分布 (1-gram)
        byte_hist = [0.0] * 256
        for b in data:
            byte_hist[b] += 1.0
        total = max(len(data), 1)
        byte_hist = [h / total for h in byte_hist]

        # n-gram哈希嵌入
        ngram_embed = _hb_zeros(self.dim)
        for ng in self.ngrams:
            if ng > len(data):
                continue
            for i in range(len(data) - ng + 1):
                gram = data[i:i + ng]
                # 确定性哈希到维度
                h = hashlib.sha256(gram).digest()
                idx = int.from_bytes(h[:4], 'little') % self.dim
                # 符号由哈希最高位决定
                sign = 1.0 if h[0] < 128 else -1.0
                ngram_embed[idx] += sign

        # 局部上下文窗口嵌入 (类似word2vec的CBOW)
        context_embed = _hb_zeros(self.dim)
        n_windows = 0
        for start in range(0, len(data) - self.window, self.stride):
            window = data[start:start + self.window]
            # 窗口内每字节的哈希嵌入
            for b in window:
                h = hashlib.sha256(bytes([b, start % 256])).digest()
                idx = int.from_bytes(h[:4], 'little') % self.dim
                context_embed[idx] += 1.0
            n_windows += 1

        if n_windows > 0:
            context_embed = [c / (n_windows * self.window) for c in context_embed]

        # 融合: [字节直方图 (256) | n-gram嵌入 (dim) | 上下文嵌入 (dim)]
        # 最终压缩到 dim 维
        combined = _hb_zeros(self.dim)

        # 第一段: 字节直方图降维 (256 -> dim)
        for i in range(256):
            combined[i % self.dim] += byte_hist[i] * 0.3

        # 第二段: n-gram
        for i in range(self.dim):
            combined[i] += ngram_embed[i] * 0.35

        # 第三段: 上下文
        for i in range(self.dim):
            combined[i] += context_embed[i] * 0.35

        return _hb_l2_norm(combined)

    def embed_function_bytes(self, func_bytes: bytes,
                             func_offset: int = 0) -> List[float]:
        """嵌入单个函数的字节范围"""
        return self.embed_bytes(func_bytes)


class HexDumpEmbedder:
    """十六进制dump嵌入 — 从binwalk/objdump风格的hex dump提取特征

    对无法解析为结构化指令的二进制区域特别有用。
    """

    def __init__(self, embed_dim: int = 128):
        self.dim = embed_dim

    def embed_hexdump(self, hexdump_text: str) -> List[float]:
        """从hex dump文本生成嵌入"""
        # 解析hex dump行: "00401000: 55 48 89 E5 48 83 EC 20 ..."
        import re
        byte_values = []
        ascii_text = []

        for line in hexdump_text.split('\n'):
            # 提取十六进制部分
            hex_match = re.findall(r'\b([0-9a-fA-F]{2})\b', line)
            byte_values.extend([int(h, 16) for h in hex_match])

            # 提取ASCII表示
            ascii_match = re.search(r'\s{2,}([!-~ ]{1,16})', line)
            if ascii_match:
                ascii_text.append(ascii_match.group(1))

        if not byte_values:
            return _hb_zeros(self.dim)

        # 字节频率
        hist = [0.0] * 256
        for b in byte_values:
            hist[b] += 1.0
        total = max(len(byte_values), 1)
        hist = [h / total for h in hist]

        # 可打印字符比例 (指示数据 vs 代码)
        printable = sum(1 for b in byte_values if 0x20 <= b <= 0x7E)
        printable_ratio = printable / total

        # 嵌入构建
        embed = _hb_zeros(self.dim)
        for i in range(256):
            embed[i % self.dim] += hist[i] * 0.5

        # 可打印性信号
        embed[0] = printable_ratio
        embed[1] = 1.0 - printable_ratio

        # ASCII文本统计
        if ascii_text:
            all_ascii = ' '.join(ascii_text)
            for ch in all_ascii:
                if ch.isalpha():
                    embed[2] += 1.0
                elif ch.isdigit():
                    embed[3] += 1.0
                elif ch in '.,;:!?':
                    embed[4] += 1.0

            scale = max(len(all_ascii), 1)
            embed[2] /= scale
            embed[3] /= scale
            embed[4] /= scale

        return _hb_l2_norm(embed)


# ========== ContraBin风格的三模态对齐 ==========

class TriModalBinaryEmbedder:
    """三模态二进制嵌入 — ContraBin [TMLR 2025] 风格

    三个模态:
      1. raw_bytes: 原始字节级嵌入 (ByteSequenceEmbedder)
      2. structural: CFG结构特征
      3. semantic: 指令序列语义特征

    通过对比学习对齐三个模态到共享空间。
    """

    def __init__(self, embed_dim: int = 256):
        self.dim = embed_dim
        self.byte_embedder = ByteSequenceEmbedder(embed_dim=embed_dim)
        # 模态投影矩阵 (将对齐后的各模态投影到共享空间)
        rng = random.Random(1001)
        lim = math.sqrt(6.0 / (embed_dim * 2))
        self.proj_bytes = [[rng.uniform(-lim, lim) for _ in range(embed_dim)]
                           for _ in range(embed_dim)]
        self.proj_struct = [[rng.uniform(-lim, lim) for _ in range(embed_dim)]
                            for _ in range(embed_dim)]
        self.proj_semantic = [[rng.uniform(-lim, lim) for _ in range(embed_dim)]
                               for _ in range(embed_dim)]

    def embed_multimodal(self, raw_bytes: bytes,
                         node_features: List[List[float]],
                         instruction_tokens: List[str]) -> Dict[str, List[float]]:
        """生成三模态嵌入"""
        byte_emb = self.byte_embedder.embed_bytes(raw_bytes)

        # 结构嵌入: 节点特征的均值池化
        if node_features:
            d = len(node_features[0])
            struct_emb = _hb_zeros(d)
            for nf in node_features:
                for j in range(d):
                    struct_emb[j] += nf[j]
            n = len(node_features)
            struct_emb = [s / n for s in struct_emb]
        else:
            struct_emb = _hb_zeros(self.dim)

        # 语义嵌入: 指令token的简单哈希
        sem_emb = _hb_zeros(self.dim)
        for token in instruction_tokens:
            h = hashlib.md5(token.encode()).digest()
            idx = int.from_bytes(h[:4], 'little') % self.dim
            sem_emb[idx] += 1.0

        # 投影到共享空间
        byte_proj = [_hb_dot(self.proj_bytes, byte_emb) for _ in [0]]  # fixme
        byte_proj = [_hb_dot(row, byte_emb) for row in self.proj_bytes]
        struct_proj = [_hb_dot(row, struct_emb) for row in self.proj_struct]
        sem_proj = [_hb_dot(row, sem_emb) for row in self.proj_semantic]

        return {
            'bytes': _hb_l2_norm(byte_proj),
            'structural': _hb_l2_norm(struct_proj),
            'semantic': _hb_l2_norm(sem_proj),
            'fused': _hb_l2_norm([
                (byte_proj[i] + struct_proj[i] + sem_proj[i]) / 3.0
                for i in range(self.dim)
            ]),
        }

    def contrastive_loss(self, emb_a: List[float], emb_b: List[float],
                         temperature: float = 0.07) -> float:
        """计算跨模态对比损失 (InfoNCE)"""
        sim = _hb_dot(_hb_l2_norm(emb_a), _hb_l2_norm(emb_b))
        return -math.log(max(1e-12, math.exp(sim / temperature) /
                             (math.exp(sim / temperature) + 1.0)))


def create_byte_embedder(embed_dim: int = 256) -> ByteSequenceEmbedder:
    return ByteSequenceEmbedder(embed_dim=embed_dim)


def create_trimodal_embedder(embed_dim: int = 256) -> TriModalBinaryEmbedder:
    return TriModalBinaryEmbedder(embed_dim=embed_dim)
