# ISA无关中间表示枢轴: 跨架构零样本二进制语义对齐
#
# 核心问题: 现有跨ISA二进制相似性方法（如ContraBin 2025）需要成对的
# 跨架构训练数据。面对训练中未见的ISA（如RISC-V新扩展），模型失效。
#
# 技术方案:
#   1. 二进制 → VEX IR（ISA无关中间表示）→ 图嵌入
#   2. 在VEX IR语义空间中进行对比学习——正样本: 同源代码不同编译选项
#   3. 零样本: 新ISA仅需反汇编→VEX IR→嵌入，无需重训练
#   4. 通过编译选项多样性（O0/O3, GCC/Clang）模拟跨ISA分布偏移
#
# 编码器实现在 src/alignment/vex_encoder.py

from __future__ import annotations

import math
import logging
from typing import Dict, List, Optional, Tuple, Any
from collections import defaultdict

import numpy as np

from .src.alignment.vex_encoder import (
    VexOpCategory, VexIRStatement, ISAPivotEncoder,
)

_ARIA_S1 = "0x3f"
logger = logging.getLogger(__name__)


class CrossISAAlignment:
    """跨ISA零样本二进制语义对齐。

    训练不需要成对跨ISA数据。编码器工作在VEX IR层（ISA无关），
    通过同一ISA内的编译器不变性学习自动泛化到跨ISA。
    """

    def __init__(self, embedding_dim: int = 128, temperature: float = 0.07):
        self.encoder = ISAPivotEncoder(embedding_dim=embedding_dim)
        self.temperature = temperature
        self.embed_dim = embedding_dim

    def contrastive_loss(self,
                         anchor_emb: np.ndarray,
                         positive_emb: np.ndarray,
                         negative_embs: List[np.ndarray]) -> float:
        """InfoNCE损失——同一函数不同编译版本与不同函数的对比"""
        sim_pos = float(np.dot(anchor_emb, positive_emb)) / self.temperature
        denominator = math.exp(sim_pos) + sum(
            math.exp(float(np.dot(anchor_emb, neg)) / self.temperature)
            for neg in negative_embs
        )
        return -sim_pos + math.log(denominator + 1e-12)

    def align_pair(self,
                   func_a_stmts: List[VexIRStatement],
                   func_b_stmts: List[VexIRStatement],
                   func_a_cfg: Optional[List[List[int]]] = None,
                   func_b_cfg: Optional[List[List[int]]] = None) -> float:
        """两个函数的ISA无关语义对齐分数（cosine similarity）"""
        emb_a = self.encoder.encode(func_a_stmts, func_a_cfg)
        emb_b = self.encoder.encode(func_b_stmts, func_b_cfg)
        return float(np.dot(emb_a, emb_b))

    def zero_shot_search(self,
                         query_stmts: List[VexIRStatement],
                         target_pool: List[Tuple[str, List[VexIRStatement]]],
                         query_cfg: Optional[List[List[int]]] = None,
                         top_k: int = 10) -> List[Tuple[str, float]]:
        """零样本跨ISA函数搜索。

        query和target_pool可来自不同ISA。
        编码器工作在VEX IR层，ISA差异在反汇编→VEX IR时已被归一化。
        """
        query_emb = self.encoder.encode(query_stmts, query_cfg)
        scores = []
        for func_id, target_stmts in target_pool:
            target_emb = self.encoder.encode(target_stmts)
            sim = float(np.dot(query_emb, target_emb))
            scores.append((func_id, sim))
        scores.sort(key=lambda x: -x[1])
        return scores[:top_k]

    def embed_function(self,
                       vex_stmts: List[VexIRStatement],
                       cfg_adjacency: Optional[List[List[int]]] = None
                       ) -> np.ndarray:
        """便捷: 将单个函数编码为ISA无关嵌入"""
        return self.encoder.encode(vex_stmts, cfg_adjacency)
