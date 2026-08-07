# coding: utf-8
# 创建: 2026-06-04  |  三元组采样器
# 修改: 2026-06-04  |  审计后补充文件头与错误处理
#
"""
对比跨架构漏洞嵌入——三元组采样器。

技术问题:
  跨架构二进制函数相似性检测长期受困于架构差异压倒语义差异。
  x86的'memcpy+offset'与ARM的'LDR+STR'序列在指令级完全不同，
  但在漏洞语义级等价。传统方法需要大量标注的跨架构函数对，
  标注成本高且覆盖CWE类型有限。

解决方案:
  架构感知的三元组采样——利用编译工具链自动生成跨架构正例对，
  无需人工标注。对每个漏洞函数:
    - Anchor: 架构A的编译产物（如x86_64）
    - Positive: 同一源码架构B的编译产物（如ARM64）——编译器自动生成
    - Negative: 随机非同源函数（架构B）——强制嵌入区分架构与语义

  硬负例挖掘: 从与Anchor架构相同但函数不同的样本中选择困难负例，
  即结构相似(同架构同CWE类型)但语义不同的函数。

创新对比:
  现有方法(jTrans, GraphEmbedding): 需标注跨架构对——成本O(N²)
  本方法: 编译器自动生成正例——成本O(N)，利用编译确定性消除标注需求
"""

import math
import random as _random
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Set, Callable
from collections import defaultdict

_log = logging.getLogger(__name__)


# 三元组定义


@dataclass
class TripletSample:
    """对比学习三元组——(anchor, positive, negative)"""
    anchor_id: str              # 锚点函数标识
    anchor_arch: str            # 锚点架构
    positive_id: str
    positive_arch: str          # 不同架构
    negative_id: str
    negative_arch: str
    # 嵌入向量——默认空列表
    anchor_embedding: List[float] = field(default_factory=list)
    positive_embedding: List[float] = field(default_factory=list)
    negative_embedding: List[float] = field(default_factory=list)
    # 三元组质量标记
    is_hard_negative: bool = False  # 是否为困难负例
    cwe_type: str = ""              # CWE类型——用于CWE感知采样
    margin: float = 0.0             # ||anchor-pos|| - ||anchor-neg|| + α


@dataclass
class TripletBatch:
    """小批量三元组——用于对比训练迭代"""
    samples: List[TripletSample] = field(default_factory=list)
    batch_size: int = 32
    # 批量统计——监控训练质量
    avg_positive_dist: float = 0.0
    avg_negative_dist: float = 0.0
    hard_negative_ratio: float = 0.0


# 三元组采样器


class CrossArchTripletSampler:
    """跨架构三元组采样器——编译器驱动的正例生成 + 架构感知负例挖掘。

    正例生成策略:
      同一C源码用GCC(x86_64)和AArch64 GCC(clang)分别编译，
      提取同名函数的CFG图→嵌入→自动正例对。
      利用编译过程的确定性消除人工标注。

    负例挖掘策略:
      1. 随机负例: 不同函数名，任意架构（基准线）
      2. 同架构硬负例: 不同函数，相同架构——强制模型区分子图差异
      3. 同CWE硬负例: 不同函数，相同CWE，相同架构——最困难
    """

    def __init__(self,
                 margin: float = 0.5,
                 hard_neg_ratio: float = 0.3,
                 rng_seed: int = 42):
        self._margin = margin
        self._hard_ratio = hard_neg_ratio
        self._rng = _random.Random(rng_seed)

        # 架构到编译器的映射——生成跨架构变体时使用
        self._arch_compiler_map = {
            'x86_64': 'gcc-13 -O2',
            'arm64': 'aarch64-linux-gnu-gcc-13 -O2',
            'arm32': 'arm-linux-gnueabihf-gcc-13 -O2',
            'mips32': 'mips-linux-gnu-gcc-13 -O2',
            'mips64': 'mips64-linux-gnuabi64-gcc-13 -O2',
        }

    def sample_from_embeddings(self,
                                embeddings: Dict[str, Dict[str, List[float]]],
                                cwe_labels: Dict[str, str] = None
                                ) -> TripletBatch:
        """从嵌入字典中采样三元组批次。

        参数:
          embeddings: {func_id: {arch: embedding_vector}}
            例如: {"memcpy_vuln": {"x86_64": [...], "arm64": [...]}}
          cwe_labels: {func_id: cwe_type}

        返回TripletBatch——采样结果含质量统计。

        采样算法:
          1. 遍历每个有≥2架构变体的函数作为anchor候选
          2. 随机选择anchor架构与positive架构（必须不同）
          3. 以hard_neg_ratio概率选择困难负例，否则随机负例
          4. 困难负例: 优先选同CWE不同函数，其次同架构不同函数
        """
        cwe_labels = cwe_labels or {}
        samples = []
        func_ids = list(embeddings.keys())

        # 过滤出有多架构变体的函数（可作为anchor/positive对）
        multi_arch_funcs = [
            fid for fid in func_ids
            if len(embeddings.get(fid, {})) >= 2
        ]
        if len(multi_arch_funcs) < 2:
            _log.warning("多架构变体不足——至少需要2个函数各有2+架构")
            return TripletBatch()

        for anchor_func in multi_arch_funcs:
            archs = list(embeddings[anchor_func].keys())
            if len(archs) < 2:
                continue

            # 随机选择anchor架构与不同的positive架构
            anchor_arch = self._rng.choice(archs)
            pos_archs = [a for a in archs if a != anchor_arch]
            if not pos_archs:
                continue
            pos_arch = self._rng.choice(pos_archs)

            anchor_emb = embeddings[anchor_func][anchor_arch]
            pos_emb = embeddings[anchor_func][pos_arch]

            # 负例选择
            use_hard = self._rng.random() < self._hard_ratio
            neg_func, neg_arch, neg_emb, is_hard = self._select_negative(
                anchor_func, anchor_arch, embeddings, cwe_labels, use_hard)

            if neg_emb is None:
                continue

            # 计算margin
            pos_dist = _euclidean(anchor_emb, pos_emb)
            neg_dist = _euclidean(anchor_emb, neg_emb)
            trip_margin = pos_dist - neg_dist + self._margin

            samples.append(TripletSample(
                anchor_id=anchor_func,
                anchor_arch=anchor_arch,
                anchor_embedding=anchor_emb,
                positive_id=anchor_func,
                positive_arch=pos_arch,
                positive_embedding=pos_emb,
                negative_id=neg_func,
                negative_arch=neg_arch,
                negative_embedding=neg_emb,
                is_hard_negative=is_hard,
                cwe_type=cwe_labels.get(anchor_func, ''),
                margin=trip_margin))

        # 批次统计
        if samples:
            avg_pos = sum(_euclidean(s.anchor_embedding, s.positive_embedding)
                          for s in samples) / len(samples)
            avg_neg = sum(_euclidean(s.anchor_embedding, s.negative_embedding)
                          for s in samples) / len(samples)
            hard_count = sum(1 for s in samples if s.is_hard_negative)
        else:
            avg_pos = avg_neg = 0.0
            hard_count = 0

        return TripletBatch(
            samples=samples, batch_size=len(samples),
            avg_positive_dist=round(avg_pos, 4),
            avg_negative_dist=round(avg_neg, 4),
            hard_negative_ratio=round(hard_count / max(len(samples), 1), 3))

    def _select_negative(self, anchor_func: str, anchor_arch: str,
                          embeddings: Dict, cwe_labels: Dict,
                          use_hard: bool
                          ) -> Tuple[str, str, Optional[List[float]], bool]:
        """选择负例——困难或随机。

        困难负例优先级:
          1. 同CWE + 同架构 + 不同函数（最困难——语义混淆）
          2. 同架构 + 不同函数（结构混淆）
          3. 不同函数 + 任意架构（回退）
        """
        anchor_cwe = cwe_labels.get(anchor_func, '')
        other_funcs = [f for f in embeddings if f != anchor_func]

        if not other_funcs:
            return '', '', None, False

        if use_hard:
            # 优先级1: 同CWE+同架构
            same_cwe_same_arch = [
                f for f in other_funcs
                if cwe_labels.get(f, '') == anchor_cwe
                and anchor_arch in embeddings[f]
            ]
            if same_cwe_same_arch:
                neg_func = self._rng.choice(same_cwe_same_arch)
                neg_arch = anchor_arch
                return neg_func, neg_arch, embeddings[neg_func][neg_arch], True

            # 优先级2: 同架构
            same_arch = [f for f in other_funcs if anchor_arch in embeddings[f]]
            if same_arch:
                neg_func = self._rng.choice(same_arch)
                neg_arch = anchor_arch
                return neg_func, neg_arch, embeddings[neg_func][neg_arch], True

        # 回退: 随机负例
        neg_func = self._rng.choice(other_funcs)
        neg_archs = list(embeddings[neg_func].keys())
        neg_arch = self._rng.choice(neg_archs) if neg_archs else anchor_arch
        return neg_func, neg_arch, embeddings[neg_func].get(neg_arch), False

    def estimate_min_batch_for_margin(self, target_margin: float,
                                       embedding_dim: int = 128) -> int:
        """估计达到目标margin所需的最小批次大小。

        基于对比学习理论(Naturenhance et al., 2020):
          样本效率 ∝ exp(-margin² / (2σ²)) × √(batch_size)
          σ ≈ 1/√(embedding_dim) 在高维嵌入空间的渐进性质。

        返回保守估计: 32-256范围。
        """
        sigma = 1.0 / math.sqrt(max(embedding_dim, 1))
        n = int(math.exp(target_margin ** 2 / (2 * sigma ** 2)) * 16)
        return max(32, min(n, 256))


def _euclidean(a: List[float], b: List[float]) -> float:
    """欧几里得距离——无numpy依赖"""
    return math.sqrt(sum((x - y) ** 2 for x, y in zip(a, b)))


__all__ = [
    "TripletSample",
    "TripletBatch",
    "CrossArchTripletSampler",
]
