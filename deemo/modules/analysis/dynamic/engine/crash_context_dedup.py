# BB 序列指数衰减嵌入 + 三级级联去重 + LCA 验证
from __future__ import annotations

import hashlib
import struct
import math
from dataclasses import dataclass, field
from collections import defaultdict
from typing import Optional


@dataclass
class CrashRecord:
    crash_id: str = ''           # SHA-256(crash_addr + exception + stack[:3])
    crash_addr: int = 0
    exception_type: str = ''     # 'SIGSEGV' | 'SIGABRT' | 'SIGBUS' | 'SIGILL'
    stack_trace: list[int] = field(default_factory=list)
    # 执行上下文——崩溃前 50 个基本块的序列
    bb_sequence: list[int] = field(default_factory=list)
    # 寄存器状态 (可选, 用于精化去重)
    register_snapshot: dict[str, int] = field(default_factory=dict)
    # 元数据
    seed_input_hash: str = ''
    timestamp: float = 0.0
    # 去重后分配的 bucket
    bucket_id: int = -1


@dataclass
class CrashBucket:
    bucket_id: int
    representative: CrashRecord   # 代表性崩溃 (最早发现或最简)
    members: list[CrashRecord] = field(default_factory=list)
    root_cause_bb: int = 0        # 推断的根因基本块
    merged_count: int = 0


# 崩溃签名生成

def make_crash_signature(crash_addr: int, exception_type: str,
                         stack_trace: list[int]) -> str:
    h = hashlib.sha256()
    h.update(struct.pack('<Q', crash_addr & 0xFFFFFFFFFFFFF000))
    h.update(exception_type.encode())
    for frame in stack_trace[:3]:
        h.update(struct.pack('<Q', (frame >> 12) << 12))
    return h.hexdigest()[:16]


# 执行上下文嵌入
# 从崩溃前 BB 序列生成固定维度嵌入——用于上下文相似度比较。

def bb_sequence_embedding(bb_seq: list[int],
                           dim: int = 32) -> list[float]:
    """将 BB 序列嵌入为 32 维向量。

    方法: 对序列做加权聚合——越靠近崩溃点的 BB 权重越高。
    每个 BB 地址被哈希到一个维度, 权重 = exp(-distance_to_crash / 10)。"""
    if not bb_seq:
        return [0.0] * dim

    vec = [0.0] * dim
    seq_len = len(bb_seq)

    for i, bb in enumerate(reversed(bb_seq)):  # 从崩溃点向前遍历
        # distance_to_crash = i (0 = 崩溃点)
        weight = math.exp(-i / 10.0)
        # BB 地址哈希到维度
        dim_idx = (bb * 2654435761) % dim  # Knuth multiplicative hash
        vec[dim_idx] += weight

    # L2 归一化
    norm = math.sqrt(sum(v * v for v in vec))
    if norm > 1e-12:
        vec = [v / norm for v in vec]

    return vec


def context_cosine_similarity(a: list[float], b: list[float]) -> float:
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(y * y for y in b))
    if na < 1e-12 or nb < 1e-12:
        return 0.0
    return dot / (na * nb)


# 最近公共祖先 (LCA) 检测
# 如果两个崩溃的 BB 序列共享最近公共祖先, 它们很可能来自同一根因。

def find_lca_bb(seq_a: list[int], seq_b: list[int]) -> int:
    # 从崩溃点 (序列末尾) 向前查找第一个共享 BB
    for bb_a in reversed(seq_a):
        if bb_a in seq_b:
            return bb_a
    return 0


# 去重引擎

class CrashContextDeduplicator:
    """三级去重: 精确签名 + 上下文嵌入 + LCA 根因判定。"""

    __slots__ = ('_buckets', '_context_embeddings', '_signature_index',
                 '_context_threshold', '_next_bucket_id')

    def __init__(self, context_threshold: float = 0.85):
        self._buckets: dict[int, CrashBucket] = {}
        self._context_embeddings: dict[int, list[float]] = {}  # bucket_id → 嵌入
        self._signature_index: dict[str, int] = {}  # signature → bucket_id
        self._context_threshold = context_threshold
        self._next_bucket_id = 0

    def classify(self, crash: CrashRecord) -> int:
        # 第1级: 精确签名匹配
        sig = make_crash_signature(
            crash.crash_addr, crash.exception_type, crash.stack_trace)
        if sig in self._signature_index:
            bid = self._signature_index[sig]
            self._buckets[bid].members.append(crash)
            self._buckets[bid].merged_count += 1
            return bid

        # 第2级: 执行上下文相似度
        ctx_embed = bb_sequence_embedding(crash.bb_sequence)
        best_bid = -1
        best_sim = 0.0

        for bid, bucket_embed in self._context_embeddings.items():
            sim = context_cosine_similarity(ctx_embed, bucket_embed)
            if sim > best_sim:
                best_sim = sim
                best_bid = bid

        if best_sim >= self._context_threshold:
            # 第3级: LCA 验证
            rep = self._buckets[best_bid].representative
            lca = find_lca_bb(crash.bb_sequence, rep.bb_sequence)
            if lca > 0:
                self._buckets[best_bid].members.append(crash)
                self._buckets[best_bid].merged_count += 1
                self._buckets[best_bid].root_cause_bb = lca
                # 更新嵌入为移动平均
                updated = []
                for i in range(len(ctx_embed)):
                    updated.append(0.8 * bucket_embed[i] + 0.2 * ctx_embed[i])
                self._context_embeddings[best_bid] = updated
                return best_bid

        # 新 bucket
        bid = self._next_bucket_id
        self._next_bucket_id += 1
        crash.bucket_id = bid
        self._buckets[bid] = CrashBucket(
            bucket_id=bid, representative=crash,
            members=[crash], root_cause_bb=crash.crash_addr,
        )
        self._context_embeddings[bid] = ctx_embed
        if sig:
            self._signature_index[sig] = bid
        return bid

    def classify_batch(self, crashes: list[CrashRecord]) -> dict[int, int]:
        return {i: self.classify(c) for i, c in enumerate(crashes)}

    def dedup_ratio(self) -> float:
        total = sum(b.merged_count + 1 for b in self._buckets.values())
        if total == 0:
            return 0.0
        return 1.0 - len(self._buckets) / total

    def stats(self) -> dict:
        sizes = [len(b.members) for b in self._buckets.values()]
        return {
            'total_crashes': sum(sizes),
            'unique_buckets': len(self._buckets),
            'dedup_ratio': round(self.dedup_ratio(), 3),
            'max_bucket_size': max(sizes) if sizes else 0,
            'context_threshold': self._context_threshold,
        }


__all__ = [
    'CrashRecord', 'CrashBucket', 'CrashContextDeduplicator',
    'make_crash_signature', 'bb_sequence_embedding',
    'find_lca_bb', 'context_cosine_similarity',
]
