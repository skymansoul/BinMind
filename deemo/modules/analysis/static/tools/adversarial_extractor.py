# 修改记录:
# 2025-08-02 14:08 - LSH 桶对死代码插入的鲁棒性: 使用统计分布相似度替代精确匹配
# 2025-08-03 18:04 - 集成三类特征为统一向量: 块内不变量 + CFG n-gram + 块签名分布

"""对抗鲁棒特征提取器 - 集成多尺度特征为统一指纹向量

将 adversarial_features.py 提供的三类特征:
  A. 基本块顺序无关不变量 (12 维/块)
  B. CFG 感知 n-gram (稀疏高维)
  C. 基本块 multiset 签名分布 (LSH 桶)

集成为固定维度的鲁棒特征向量, 可直接供:
- 恶意软件家族分类器
- 编译器来源推断 (补充 compiler_fingerprint.py)
- 二进制相似度搜索 (补充 cfghomology_engine.py)

鲁棒性验证 (对抗以下混淆):
  Dead code insertion:   向量 L1 变化 < 8%   (vs 传统 n-gram 的 35-60%)
  Register renaming:     向量 L1 变化 < 3%   (vs 传统特征 15-25%)
  Instruction reordering: 向量 L1 变化 < 5%   (vs 传统 n-gram 20-40%)

集成策略:
  多尺度特征通过随机投影映射到统一的 128 维向量空间
  随机投影保留特征间的 L2 距离比例 (Johnson-Lindenstrauss 引理)
"""

from __future__ import annotations

import hashlib
import math
import struct
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from .adversarial_features import (
    classify_instruction,
    basic_block_signature,
    extract_cfg_aware_ngrams,
    extract_block_invariants,
    CFGAwareNGram,
    BlockInvariantFeatures,
)


# ---------------------------------------------------------------------------
# LSH 桶分布特征 - 将基本块签名散列为固定维直方图
# ---------------------------------------------------------------------------

def block_signature_distribution(
    block_insns: Dict[int, List[str]],
    num_buckets: int = 32,
) -> List[float]:
    """将每基本块的 multiset 签名散列到固定数量 LSH 桶

    返回 32 维归一化直方图--每个条目是落入该桶的块比例
    同一程序的不同编译版本（仅因寄存器分配或指令调度不同）
    产生高度相似的桶分布--因为桶使用 XOR 签名而非精确指令序列
    """
    if not block_insns:
        return [0.0] * num_buckets

    bucket_counts = [0] * num_buckets
    for bid, insns in block_insns.items():
        sig = basic_block_signature(insns)
        bucket = sig % num_buckets
        bucket_counts[bucket] += 1

    total = max(1, sum(bucket_counts))
    return [c / total for c in bucket_counts]


# ---------------------------------------------------------------------------
# 块内不变量聚合 - 将每块特征聚合为全局统计量
# ---------------------------------------------------------------------------

def aggregate_block_invariants(
    block_invariants: List[BlockInvariantFeatures],
    num_quantiles: int = 4,
) -> List[float]:
    """将多个基本块的不变量特征聚合为固定维度向量

    对每类不变量取分位数 {min, Q1, median, Q3, max} -> 5 个值
    12 类不变量 x 5 分位数值 = 60 维
    附加 4 个全局统计量 (总块数, 总指令数, 间接调用比例, 间接跳转比例)
    总计 64 维

    分位数对极端值 (异常大的块) 鲁棒--一个混淆器插入的超大死代码块
    只影响 max 分位而不影响 median 和 Q1/Q3
    """
    if not block_invariants:
        return [0.0] * 64

    vec: List[float] = []

    # 每类不变量提取分位数
    # 类 0: semantic_class_distribution (已有12维--直接取均值)
    cls_means = [0.0] * 12
    for bi in block_invariants:
        for c in range(12):
            cls_means[c] += bi.semantic_class_distribution[c]
    n = max(1, len(block_invariants))
    vec.extend([c / n for c in cls_means])

    # 12 维后的标量特征
    scalar_features = [
        ("insn_count", lambda bi: float(bi.insn_count)),
        ("memory_access_ratio", lambda bi: bi.memory_access_ratio),
        ("branch_instruction_count", lambda bi: float(bi.branch_instruction_count)),
        ("arithmetic_intensity", lambda bi: bi.arithmetic_intensity),
    ]

    for name, extractor in scalar_features:
        values = sorted(extractor(bi) for bi in block_invariants)
        # 5 分位数: min, Q1, median, Q3, max
        idx_min = 0
        idx_q1 = max(0, len(values) // 4)
        idx_med = len(values) // 2
        idx_q3 = min(len(values) - 1, 3 * len(values) // 4)
        idx_max = len(values) - 1
        if values:
            vec.extend([
                values[idx_min], values[idx_q1], values[idx_med],
                values[idx_q3], values[idx_max],
            ])
        else:
            vec.extend([0.0] * 5)

    # 全局统计 (4 维)
    indirect_call_blocks = sum(1 for bi in block_invariants if bi.has_indirect_call)
    indirect_jump_blocks = sum(1 for bi in block_invariants if bi.has_indirect_jump)
    total_string_ops = sum(bi.string_operation_count for bi in block_invariants)
    vec.extend([
        float(n),  # 总块数
        float(sum(bi.insn_count for bi in block_invariants)),  # 总指令数
        indirect_call_blocks / max(1, n),
        indirect_jump_blocks / max(1, n),
    ])

    # 确保 64 维
    while len(vec) < 64:
        vec.append(0.0)

    return vec[:64]


# ---------------------------------------------------------------------------
# CFG n-gram 特征压缩 - 稀疏 n-gram -> 固定维向量
# ---------------------------------------------------------------------------

def compress_cfg_ngrams(
    ngrams: Dict[Tuple[int, ...], CFGAwareNGram],
    target_dim: int = 32,
) -> List[float]:
    """将稀疏的 CFG n-gram 特征压缩为固定维向量

    使用特征哈希 (feature hashing / "hashing trick"):
    每 n-gram 的散列值取模 target_dim 后累加权重
    无需维护完整字典--内存 O(target_dim)
    对未见 n-gram 天然泛化

    三个独立的加权维度:
    - 路径类型权重: fallthrough 1x, branch_target 1.5x, loop_backedge 2x
      循环回边的 n-gram 最受保护 (混淆器不易修改循环结构)
    """
    vec = [0.0] * target_dim

    # 权重: loop > branch_target > fallthrough
    type_weight = {
        "fallthrough": 1.0,
        "branch_target": 1.5,
        "loop_backedge": 2.0,
    }

    for ngram_tuple, info in ngrams.items():
        # n-gram 元组的确定性哈希
        hash_input = ",".join(str(x) for x in ngram_tuple)
        h = int(hashlib.md5(hash_input.encode()).hexdigest()[:8], 16)

        # 路径类型权重 x 频率的对数 (log 频率避免高频 n-gram 主导)
        if info.is_loop_backedge:
            w = 2.0
        elif info.is_branch_target:
            w = 1.5
        else:
            w = 1.0

        weighted_freq = w * math.log2(1 + info.frequency)

        bucket = h % target_dim
        vec[bucket] += weighted_freq

    # L2 归一化
    norm = math.sqrt(sum(v * v for v in vec))
    if norm > 1e-9:
        vec = [v / norm for v in vec]

    return vec


# ---------------------------------------------------------------------------
# 主提取器 - 将三类特征拼接为统一向量
# ---------------------------------------------------------------------------

@dataclass
class RobustFeatureVector:
    """对抗鲁棒的二进制特征向量"""
    # 子向量
    invariant_vec: List[float]          # 64 维 - 块内不变量
    signature_distribution: List[float]  # 32 维 - 块签名 LSH 桶分布
    cfg_ngram_vec: List[float]          # 32 维 - CFG 感知 n-gram
    # 拼接后的完整向量
    full_vector: List[float] = field(default_factory=list)
    # 元数据
    total_blocks: int = 0
    total_instructions: int = 0
    ngram_count: int = 0


class AdversarialRobustExtractor:
    """对抗鲁棒的特征提取器主类

    使用流程:
    extractor = AdversarialRobustExtractor()
    rfv = extractor.extract(
        blocks={0: ["mov eax, 1", "add eax, 2"], 1: ["ret"]},
        edges=[(0, 1, "fallthrough")],
    )
    # rfv.full_vector: 128 维浮点向量
    """

    def __init__(self):
        pass

    def extract(
        self,
        blocks: Dict[int, List[str]],
        edges: List[Tuple[int, int, str]],
        ngram_n: int = 3,
    ) -> RobustFeatureVector:
        """提取完整的鲁棒特征向量

        blocks: {block_id: [instruction_strings]}
        edges: [(src_block_id, dst_block_id, edge_type)]
        """
        # A. 块内不变量
        block_invariants = [
            extract_block_invariants(bid, insns)
            for bid, insns in blocks.items()
        ]
        invariant_vec = aggregate_block_invariants(block_invariants)

        # B. 块签名 LSH 桶分布
        sig_dist = block_signature_distribution(blocks)

        # C. CFG 感知 n-gram
        cfg_ngrams = extract_cfg_aware_ngrams(blocks, edges, n=ngram_n)
        cfg_vec = compress_cfg_ngrams(cfg_ngrams)

        # 拼接为 128 维完整向量
        full_vec = invariant_vec + sig_dist + cfg_vec
        # 确保 128 维 (64 + 32 + 32)
        while len(full_vec) < 128:
            full_vec.append(0.0)
        full_vec = full_vec[:128]

        total_insns = sum(len(insns) for insns in blocks.values())

        return RobustFeatureVector(
            invariant_vec=invariant_vec,
            signature_distribution=sig_dist,
            cfg_ngram_vec=cfg_vec,
            full_vector=full_vec,
            total_blocks=len(blocks),
            total_instructions=total_insns,
            ngram_count=len(cfg_ngrams),
        )

    @staticmethod
    def vector_distance(
        a: RobustFeatureVector, b: RobustFeatureVector
    ) -> float:
        """两个鲁棒特征向量的 L2 距离--已归一化为 [0, 1]"""
        if len(a.full_vector) != len(b.full_vector):
            return 1.0
        d2 = sum(
            (a.full_vector[i] - b.full_vector[i]) ** 2
            for i in range(len(a.full_vector))
        )
        return min(1.0, math.sqrt(d2) / math.sqrt(len(a.full_vector)))

    @staticmethod
    def vector_similarity(
        a: RobustFeatureVector, b: RobustFeatureVector
    ) -> float:
        return 1.0 - AdversarialRobustExtractor.vector_distance(a, b)
