# 语义语料蒸馏器 — 基于执行行为嵌入的种子集最优化选取
# 覆盖驱动语料约简有一个盲区: 两个种子可能覆盖相同的边，却触发
# 完全不同的程序行为。纯覆盖去重会丢弃行为多样但覆盖冗余的种子。
# 本模块面向离线场景: "已有大规模语料，如何选取最有代表性的 k 个
# 种子用于 CI 回归测试?"
#
# 方法 — Maximal Marginal Relevance (MMR) 在行为嵌入空间:
#   1. 对每个种子执行并捕获行为指纹: stdout/stderr/覆盖向量/退出码/执行时间
#   2. 将行为指纹嵌入为固定维度向量 (轻量特征工程, 不依赖外部模型)
#   3. 使用 MMR 贪心选取: 每次选择与已选集最不相似但自身"质量"最高的种子
#   4. 输出蒸馏后的最小种子集, 保证行为多样性
#
# 与 regression_corpus.py 的关系: 覆盖驱动的去重+最小集选取 (前者)
# 与行为多样性驱动的蒸馏 (本模块) 正交，可叠加使用。
from __future__ import annotations

import hashlib
import math
import time
from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple


@dataclass
class SeedFingerprint:
    """单个种子的行为指纹——执行后采集的结构化观测"""
    seed_id: str
    data: bytes = b""
    size: int = 0
    # 执行行为
    exit_code: int = 0
    crashed: bool = False
    execution_time_ms: float = 0.0
    # 输出特征
    stdout_len: int = 0
    stderr_len: int = 0
    stdout_entropy: float = 0.0      # 输出的字节香农熵
    stderr_entropy: float = 0.0
    # 覆盖特征
    covered_edges: int = 0
    new_edges_found: int = 0
    # 嵌入向量 (延迟计算)
    embedding: List[float] = field(default_factory=list)


@dataclass
class DistillationResult:
    """语义蒸馏结果"""
    original_count: int
    distilled_count: int
    selected_seeds: List[SeedFingerprint] = field(default_factory=list)
    # 质量度量
    behavioral_diversity: float = 0.0    # 选集内平均 pairwise 余弦距离
    coverage_retention: float = 0.0      # 选集保留的覆盖边比例
    distillation_time_s: float = 0.0
    summary: str = ""


class BehaviorEmbedder:
    """将种子的执行行为指纹嵌入为固定维度向量。

    嵌入维度 = 14:
      [0]: exit_code (归一化)
      [1]: crashed (0/1)
      [2]: log1p(execution_time_ms) / 10
      [3]: log1p(stdout_len) / 16
      [4]: log1p(stderr_len) / 16
      [5]: stdout_entropy / 8
      [6]: stderr_entropy / 8
      [7]: min(1.0, covered_edges / 10000)
      [8]: min(1.0, new_edges_found / 100)
      [9-13]: 覆盖率向量的哈希分桶 (5维 SimHash 风格降维)
    """

    EMBEDDING_DIM = 14

    @staticmethod
    def embed(fp: SeedFingerprint) -> List[float]:
        vec = [0.0] * BehaviorEmbedder.EMBEDDING_DIM

        vec[0] = (fp.exit_code + 256) / 512.0  # 归一化到 [0, 1] 左右
        vec[1] = 1.0 if fp.crashed else 0.0
        vec[2] = min(1.0, math.log1p(fp.execution_time_ms) / 10.0)
        vec[3] = min(1.0, math.log1p(fp.stdout_len) / 16.0)
        vec[4] = min(1.0, math.log1p(fp.stderr_len) / 16.0)
        vec[5] = fp.stdout_entropy / 8.0
        vec[6] = fp.stderr_entropy / 8.0
        vec[7] = min(1.0, fp.covered_edges / 10000.0)
        vec[8] = min(1.0, fp.new_edges_found / 100.0)

        # 将种子数据哈希为5维 pseudo-embedding
        data_hash = hashlib.sha256(fp.data[:1024]).digest()
        for i in range(5):
            # 每4字节一组, 归一化到 [0, 1]
            chunk = int.from_bytes(
                data_hash[i * 4:(i + 1) * 4], 'big', signed=False)
            vec[9 + i] = (chunk % 10000) / 10000.0

        return vec


class SemanticDistiller:
    """基于 MMR 的语义语料蒸馏器。

    典型用法:
        distiller = SemanticDistiller(target_size=100)
        fingerprints = [SeedFingerprint(...) for seed in corpus]
        result = distiller.distill(fingerprints)
        # result.selected_seeds 即为蒸馏后的最小种子集
    """

    def __init__(self, target_size: int = 100,
                 diversity_weight: float = 0.6):
        """
        target_size: 蒸馏后的目标种子数
        diversity_weight: MMR 中多样性 (λ) vs 质量 (1-λ) 的权重
          0.0 → 仅按质量排序, 0.5 → 平衡, 1.0 → 仅按多样性
        """
        self._target = target_size
        self._lambda = diversity_weight

    def distill(self, fingerprints: List[SeedFingerprint],
                target_size: Optional[int] = None,
                ) -> DistillationResult:
        """主入口: MMR 贪心选取最具行为多样性的种子子集"""
        target = target_size or self._target
        t0 = time.perf_counter()

        if not fingerprints:
            return DistillationResult(
                original_count=0, distilled_count=0,
                distillation_time_s=time.perf_counter() - t0,
                summary="空语料",
            )

        n = len(fingerprints)
        if n <= target:
            # 语料已经足够小, 无需蒸馏
            for fp in fingerprints:
                if not fp.embedding:
                    fp.embedding = BehaviorEmbedder.embed(fp)
            return DistillationResult(
                original_count=n, distilled_count=n,
                selected_seeds=list(fingerprints),
                behavioral_diversity=self._avg_pairwise_distance(fingerprints),
                coverage_retention=1.0,
                distillation_time_s=time.perf_counter() - t0,
                summary=f"语料 {n} ≤ 目标 {target}, 无需蒸馏",
            )

        # 确保所有指纹有嵌入
        for fp in fingerprints:
            if not fp.embedding:
                fp.embedding = BehaviorEmbedder.embed(fp)

        selected: List[SeedFingerprint] = []
        remaining = list(range(n))
        embeddings = [fp.embedding for fp in fingerprints]

        # 种子选择: 选择质量最高的作为 first pick
        # 质量 = covered_edges (覆盖越多越好) + new_edges_found bonus
        quality_scores = [
            min(1.0, fp.covered_edges / 10000.0)
            + 0.5 * min(1.0, fp.new_edges_found / 100.0)
            for fp in fingerprints
        ]
        best_first = max(range(n), key=lambda i: quality_scores[i])
        selected.append(fingerprints[best_first])
        remaining.remove(best_first)

        # MMR 贪心迭代
        while len(selected) < target and remaining:
            best_idx = -1
            best_mmr = -float('inf')

            for idx in remaining:
                # 质量项: 该种子的覆盖/崩溃价值
                quality = quality_scores[idx]

                # 多样性项: 与已选集的最大相似度 (取负, 因为要最小化相似度)
                max_sim = 0.0
                emb_i = embeddings[idx]
                for sel_fp in selected:
                    sim = self._cosine_similarity(emb_i, sel_fp.embedding)
                    if sim > max_sim:
                        max_sim = sim

                # MMR = λ * quality - (1-λ) * max_similarity_to_selected
                mmr = (1.0 - self._lambda) * quality - self._lambda * max_sim

                if mmr > best_mmr:
                    best_mmr = mmr
                    best_idx = idx

            if best_idx < 0:
                break

            selected.append(fingerprints[best_idx])
            remaining.remove(best_idx)

        # 计算质量度量
        diversity = self._avg_pairwise_distance(selected)

        # 覆盖保留率: 选集覆盖的边 / 全集覆盖的边
        total_edges = sum(fp.covered_edges for fp in fingerprints)
        selected_edges = sum(fp.covered_edges for fp in selected)
        cov_retention = min(1.0, selected_edges / max(1, total_edges))

        elapsed = time.perf_counter() - t0
        return DistillationResult(
            original_count=n,
            distilled_count=len(selected),
            selected_seeds=selected,
            behavioral_diversity=diversity,
            coverage_retention=cov_retention,
            distillation_time_s=elapsed,
            summary=self._build_summary(
                n, len(selected), diversity, cov_retention, elapsed),
        )

    def distill_staged(self, fingerprints: List[SeedFingerprint],
                        stages: List[int],
                        ) -> List[DistillationResult]:
        """分阶段蒸馏——每阶段产出不同大小的子集, 用于A/B测试不同语料规模。

        stages: [50, 100, 200] → 分别蒸馏到 50/100/200 个种子。
        """
        results: List[DistillationResult] = []
        current = list(fingerprints)
        for target in sorted(stages):
            result = self.distill(current, target_size=target)
            results.append(result)
            current = result.selected_seeds
        return results

    @staticmethod
    def _cosine_similarity(a: List[float], b: List[float]) -> float:
        dot = sum(x * y for x, y in zip(a, b))
        na = math.sqrt(sum(x * x for x in a))
        nb = math.sqrt(sum(y * y for y in b))
        if na < 1e-12 or nb < 1e-12:
            return 0.0
        return max(-1.0, min(1.0, dot / (na * nb)))

    @staticmethod
    def _avg_pairwise_distance(seeds: List[SeedFingerprint]) -> float:
        if len(seeds) <= 1:
            return 0.0
        total_dist = 0.0
        count = 0
        for i in range(len(seeds)):
            for j in range(i + 1, len(seeds)):
                total_dist += 1.0 - SemanticDistiller._cosine_similarity(
                    seeds[i].embedding, seeds[j].embedding)
                count += 1
        return total_dist / max(1, count)

    @staticmethod
    def _build_summary(orig: int, dist: int,
                        diversity: float, cov_ret: float,
                        elapsed: float) -> str:
        reduction = (1.0 - dist / max(1, orig)) * 100
        return (f"蒸馏: {orig} → {dist} 种子 ({reduction:.1f}%缩减), "
                f"多样性={diversity:.3f}, 覆盖保留={cov_ret:.1%}, "
                f"耗时 {elapsed:.2f}s")


def quick_distill(fingerprints: List[SeedFingerprint],
                   target_size: int = 50) -> DistillationResult:
    """便捷入口: 快速蒸馏到指定大小"""
    distiller = SemanticDistiller(target_size=target_size)
    return distiller.distill(fingerprints)


def fingerprint_from_execution(seed_data: bytes,
                                exit_code: int, crashed: bool,
                                exec_time_ms: float,
                                stdout: bytes = b"",
                                stderr: bytes = b"",
                                covered_edges: int = 0,
                                new_edges: int = 0,
                                ) -> SeedFingerprint:
    """便捷入口: 从执行结果构造 SeedFingerprint"""
    def byte_entropy(data: bytes) -> float:
        if not data:
            return 0.0
        counts = Counter(data[:8192])
        total = sum(counts.values())
        ent = 0.0
        for c in counts.values():
            if c > 0:
                p = c / total
                ent -= p * math.log2(p)
        return ent

    fp = SeedFingerprint(
        seed_id=hashlib.sha256(seed_data[:256]).hexdigest()[:12],
        data=seed_data,
        size=len(seed_data),
        exit_code=exit_code,
        crashed=crashed,
        execution_time_ms=exec_time_ms,
        stdout_len=len(stdout),
        stderr_len=len(stderr),
        stdout_entropy=byte_entropy(stdout),
        stderr_entropy=byte_entropy(stderr),
        covered_edges=covered_edges,
        new_edges_found=new_edges,
    )
    fp.embedding = BehaviorEmbedder.embed(fp)
    return fp
