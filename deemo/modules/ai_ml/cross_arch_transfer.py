# 跨架构迁移学习 — 将一种指令集上训练的模型适配到另一种架构
# 依据: GBsim 的GCN-BERT跨架构二进制相似度方法
# ProTST 的渐进式师生跨任务知识迁移
# 核心: 通过共享语义空间对齐不同架构的嵌入, 使用对比域适配

from __future__ import annotations
import math
import random
import hashlib
import logging
from typing import Dict, List, Optional, Set, Tuple, Any
from collections import defaultdict, Counter
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


# 架构定义

class ArchKind(Enum):
    X86_32 = 'x86'
    X86_64 = 'x86_64'
    ARM32 = 'arm32'
    ARM64 = 'aarch64'
    MIPS32 = 'mips32'
    MIPS64 = 'mips64'
    PPC32 = 'ppc32'
    PPC64 = 'ppc64'
    RISCV32 = 'riscv32'
    RISCV64 = 'riscv64'
    WASM = 'wasm'
    UNKNOWN = 'unknown'

    @property
    def bitness(self) -> int:
        return 64 if '64' in self.value else 32

    @property
    def is_risc(self) -> bool:
        return self in (ArchKind.ARM32, ArchKind.ARM64, ArchKind.MIPS32,
                        ArchKind.MIPS64, ArchKind.RISCV32, ArchKind.RISCV64)

    @property
    def is_cisc(self) -> bool:
        return self in (ArchKind.X86_32, ArchKind.X86_64)

    @classmethod
    def from_uname(cls, machine: str) -> 'ArchKind':
        mapping = {
            'x86': cls.X86_32, 'i386': cls.X86_32, 'i686': cls.X86_32,
            'x86_64': cls.X86_64, 'amd64': cls.X86_64,
            'arm': cls.ARM32, 'armv7': cls.ARM32,
            'aarch64': cls.ARM64, 'arm64': cls.ARM64,
            'mips': cls.MIPS32,
            'mips64': cls.MIPS64,
        }
        return mapping.get(machine.lower(), cls.UNKNOWN)


# 架构特征分析器

@dataclass
class ArchProfile:
    """架构特征画像"""
    arch: ArchKind
    register_count: int
    instruction_alignment: int  # 字节对齐
    is_little_endian: bool
    has_delay_slot: bool        # MIPS的分支延迟槽
    has_conditional_execution: bool  # ARM的条件执行
    has_predication: bool
    stack_grows_downward: bool
    abi_name: str = ""

    def to_vector(self) -> List[float]:
        return [
            float(self.register_count) / 64.0,
            float(self.instruction_alignment) / 8.0,
            1.0 if self.is_little_endian else 0.0,
            1.0 if self.has_delay_slot else 0.0,
            1.0 if self.has_conditional_execution else 0.0,
            1.0 if self.has_predication else 0.0,
            1.0 if self.stack_grows_downward else 0.0,
        ]


ARCH_PROFILES: Dict[ArchKind, ArchProfile] = {
    ArchKind.X86_32: ArchProfile(ArchKind.X86_32, 8, 1, True, False, False, False, True, 'cdecl'),
    ArchKind.X86_64: ArchProfile(ArchKind.X86_64, 16, 1, True, False, False, False, True, 'SystemV'),
    ArchKind.ARM32: ArchProfile(ArchKind.ARM32, 16, 4, True, False, True, True, True, 'AAPCS'),
    ArchKind.ARM64: ArchProfile(ArchKind.ARM64, 32, 4, True, False, False, False, True, 'AAPCS64'),
    ArchKind.MIPS32: ArchProfile(ArchKind.MIPS32, 32, 4, True, True, False, False, True, 'O32'),
    ArchKind.MIPS64: ArchProfile(ArchKind.MIPS64, 32, 4, True, True, False, False, True, 'N64'),
    ArchKind.RISCV32: ArchProfile(ArchKind.RISCV32, 32, 4, True, False, False, False, True, 'ILP32'),
    ArchKind.RISCV64: ArchProfile(ArchKind.RISCV64, 32, 4, True, False, False, False, True, 'LP64'),
    ArchKind.WASM: ArchProfile(ArchKind.WASM, 0, 1, True, False, False, False, False, 'wasm'),
}


# 纯Python向量运算

def _xa_vec_dot(a: List[float], b: List[float]) -> float:
    return sum(x * y for x, y in zip(a, b))

def _xa_matvec(W: List[List[float]], x: List[float]) -> List[float]:
    return [sum(row[j] * x[j] for j in range(len(x))) for row in W]

def _xa_zeros(n: int) -> List[float]:
    return [0.0] * n

def _xa_l2_norm(v: List[float]) -> List[float]:
    n = math.sqrt(sum(x * x for x in v))
    if n < 1e-12:
        return v[:]
    return [x / n for x in v]

def _xa_xavier(r: int, c: int) -> List[List[float]]:
    rng = random.Random(hash(f"xarch_{r}_{c}") & 0x7FFFFFFF)
    lim = math.sqrt(6.0 / (r + c))
    return [[rng.uniform(-lim, lim) for _ in range(c)] for _ in range(r)]


# 架构对齐投影器

class CrossArchAligner:
    """跨架构语义对齐器

    实现 GBsim [Entropy 2025] 风格的跨架构投影:
      给定两种架构A和B的嵌入空间, 学习一个线性投影P_{A->B}
      使得 f_B ≈ P_{A->B} @ f_A 用于语义相同的函数

    训练使用CLAP风格的对比损失, 正例=同一源代码在不同架构下的编译结果
    """

    def __init__(self, embed_dim: int = 128):
        self.embed_dim = embed_dim
        # 为每个架构对维护投影矩阵
        self.projections: Dict[Tuple[ArchKind, ArchKind], List[List[float]]] = {}
        self.pairwise_scales: Dict[Tuple[ArchKind, ArchKind], float] = {}

    def project(self, embedding: List[float],
                src_arch: ArchKind, dst_arch: ArchKind) -> List[float]:
        """将源架构嵌入投影到目标架构空间"""
        if src_arch == dst_arch:
            return embedding[:]

        key = (src_arch, dst_arch)
        if key in self.projections:
            proj = _xa_matvec(self.projections[key], embedding)
            scale = self.pairwise_scales.get(key, 1.0)
            return _xa_l2_norm([p * scale for p in proj])

        # 未训练时: 使用架构特征向量进行启发式对齐
        src_prof = ARCH_PROFILES.get(src_arch)
        dst_prof = ARCH_PROFILES.get(dst_arch)
        if src_prof and dst_prof:
            return self._heuristic_align(embedding, src_prof, dst_prof)
        return _xa_l2_norm(embedding)

    def _heuristic_align(self, emb: List[float],
                         src: ArchProfile, dst: ArchProfile) -> List[float]:
        """启发式对齐: 基于架构差异调整嵌入

        不同架构编译同一代码的差异主要体现在:
          - 寄存器数量 (影响指令序列长度)
          - 指令宽度 (影响每条指令的表达能力)
          - 调用约定 (影响函数序言/尾声)
        """
        src_v = src.to_vector()
        dst_v = dst.to_vector()

        diff = [dst_v[i] - src_v[i] for i in range(len(src_v))]
        diff_norm = math.sqrt(sum(d * d for d in diff))
        if diff_norm < 0.01:
            return _xa_l2_norm(emb)

        # 将差异投影到嵌入空间的子空间
        # 使用余弦退火风格的调整幅度
        alignment_strength = math.tanh(diff_norm * 2.0)  # [0, ~1]
        adjusted = emb[:]

        # 简单启发式: 按差异向量的前几维进行线性调整
        for i in range(min(len(diff), len(emb))):
            adjusted[i] += diff[i] * 0.1 * alignment_strength

        return _xa_l2_norm(adjusted)

    def train_alignment(self, src_embeddings: List[List[float]],
                        dst_embeddings: List[List[float]],
                        src_arch: ArchKind, dst_arch: ArchKind,
                        lr: float = 0.01, epochs: int = 100):
        """训练跨架构投影矩阵 (使用正交Procrustes闭式解)

        求解: min ||P @ X - Y||_F  s.t. P^T P ≈ I (近似正交约束)
        Procrustes: P = V @ U^T 其中 U @ S @ V^T = SVD(Y^T @ X)
        由于使用纯Python, 采用简化SGD替代SVD
        """
        if len(src_embeddings) < 2:
            return

        d = self.embed_dim
        key = (src_arch, dst_arch)

        # 初始化正交投影矩阵
        if key not in self.projections:
            self.projections[key] = _xa_xavier(d, d)

        P = self.projections[key]
        n = len(src_embeddings)

        for ep in range(epochs):
            total_loss = 0.0
            # 随机mini-批次 SGD
            indices = list(range(n))
            random.shuffle(indices)
            bs = min(32, n)

            for bi in range(0, n, bs):
                batch = indices[bi:bi + bs]
                grad = [[0.0] * d for _ in range(d)]
                batch_loss = 0.0

                for idx in batch:
                    x = src_embeddings[idx]
                    y = dst_embeddings[idx]
                    pred = _xa_matvec(P, x)

                    # MSE损失: ||pred - y||^2
                    diff_vec = [pred[i] - y[i] for i in range(d)]
                    batch_loss += sum(dv * dv for dv in diff_vec) / d

                    # 梯度: dL/dP = 2/n * outer(diff_vec, x)
                    for i in range(d):
                        for j in range(d):
                            grad[i][j] += 2.0 * diff_vec[i] * x[j] / len(batch)

                # 梯度下降 + 正交性正则化
                for i in range(d):
                    for j in range(d):
                        P[i][j] -= lr * grad[i][j]

                # 软正交约束: P = (1-λ)*P + λ*proj_orth(P)
                # 简化: 行归一化
                for i in range(d):
                    row_norm = math.sqrt(sum(P[i][j] ** 2 for j in range(d)))
                    if row_norm > 1e-8:
                        for j in range(d):
                            P[i][j] *= (1.0 - 0.001) + 0.001 / row_norm

                total_loss += batch_loss

            if ep % 20 == 0:
                avg_loss = total_loss / ((n + bs - 1) // bs)
                logger.debug(f"CrossArch epoch {ep}: loss={avg_loss:.6f}")

        self.pairwise_scales[key] = 1.0

    def compute_cross_arch_similarity(self, emb_a: List[float], arch_a: ArchKind,
                                       emb_b: List[float], arch_b: ArchKind) -> float:
        """计算跨架构相似度"""
        if arch_a == arch_b:
            return _xa_vec_dot(emb_a, emb_b)

        # 将emb_a投影到arch_b空间后计算余弦相似度
        projected = self.project(emb_a, arch_a, arch_b)
        return _xa_vec_dot(_xa_l2_norm(projected), _xa_l2_norm(emb_b))


# 跨架构函数匹配器

@dataclass
class CrossArchMatch:
    func_name: str
    src_arch: ArchKind
    target_arch: ArchKind
    similarity: float
    is_match: bool
    confidence: float


class CrossArchFunctionMatcher:
    """跨架构函数匹配

    给定一个源架构上的函数嵌入, 在目标架构的数据库中找到语义最相似的函数。
    GBsim的两阶段搜索: (1)粗排用余弦相似度 (2)精排用局部结构对齐
    """

    def __init__(self, aligner: CrossArchAligner = None):
        self.aligner = aligner or CrossArchAligner()
        self.index: Dict[ArchKind, Dict[str, List[float]]] = defaultdict(dict)

    def index_function(self, arch: ArchKind, func_name: str, embedding: List[float]):
        self.index[arch][func_name] = embedding

    def index_batch(self, arch: ArchKind,
                    funcs: Dict[str, List[float]]):
        self.index[arch].update(funcs)

    def search(self, query_embedding: List[float],
               query_arch: ArchKind, target_arch: ArchKind,
               top_k: int = 10, threshold: float = 0.5) -> List[CrossArchMatch]:
        """跨架构搜索"""
        if target_arch not in self.index:
            return []

        candidates = []
        for func_name, db_emb in self.index[target_arch].items():
            sim = self.aligner.compute_cross_arch_similarity(
                query_embedding, query_arch, db_emb, target_arch)
            if sim >= threshold:
                candidates.append((func_name, sim))

        candidates.sort(key=lambda x: x[1], reverse=True)
        top = candidates[:top_k]

        results = []
        for func_name, sim in top:
            match = CrossArchMatch(
                func_name=func_name,
                src_arch=query_arch,
                target_arch=target_arch,
                similarity=sim,
                is_match=sim >= 0.85,
                confidence=min(1.0, (sim - threshold) / (1.0 - threshold)),
            )
            results.append(match)

        return results

    def batch_search(self, queries: List[Tuple[List[float], ArchKind]],
                     target_arch: ArchKind, top_k: int = 10) -> List[List[CrossArchMatch]]:
        return [self.search(q_emb, q_arch, target_arch, top_k)
                for q_emb, q_arch in queries]

    def get_arch_statistics(self) -> Dict[str, int]:
        return {arch.value: len(funcs) for arch, funcs in self.index.items()}


def create_cross_arch_matcher(embed_dim: int = 128) -> CrossArchFunctionMatcher:
    return CrossArchFunctionMatcher(CrossArchAligner(embed_dim))
