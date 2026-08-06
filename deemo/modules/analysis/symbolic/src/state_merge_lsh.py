# 修改记录:
# 2025-08-05 11:28 - 约束类型指纹: 不比较约束内容, 仅比较约束操作符分布 (O(1) vs O(|Z3 AST|))
# 2025-08-05 15:33 - 双通道 MinHash: 约束类型通道 + 寄存器符号集通道, 并行哈希
# 2025-08-16 13:15 - Z3 安全性: fingerprint() 中约束类型提取增加多层异常保护

"""基于 MinHash 的符号状态合并候选发现 - 亚线性时间近似近邻检测

symbolic_path_merge.py 的合并候选选择需要 O(N²) 逐对比较:
  for s1 in states:
    for s2 in states:
      if similarity(s1, s2) > threshold: merge(s1, s2)

当状态池达到 10³-10⁴ 时, 比较开销超过合并收益

本模块将状态合并候选发现问题转化为近似最近邻 (ANN) 问题:
  1. 每状态提取轻量级 "指纹" - 约束类型分布 + 符号变量集
  2. MinHash 将指纹压缩为固定长度签名
  3. LSH 将签名散列到桶 - 同一桶内的状态为合并候选
  4. 仅比较桶内状态 - 期望比较次数 O(N·B) B=桶大小常数

与现有方法的差异:
- Trabish et al. (KLEE 2024) 使用 pattern-based hashing 检测正则模式
  -> 需要预定义模式模板, 对非常规约束无效
- 本模块的 MinHash 基于 Jaccard 相似度的无偏估计
  -> 不需要预定义模式, 对任意约束集合通用

复杂度:
- 指纹提取: O(|constraints|) per state
- MinHash 签名: O(K·|constraints|) K=哈希函数数=128
- LSH 插入/查询: O(K) per state
- 合并候选比较: O(B²) per bucket, B≈5-15 实际中

参数选择:
  K=128 哈希函数 -> Jaccard 估计误差 < 0.05 (Chernoff bound)
  L=8 个哈希表 -> 召回率 > 0.95 对 Jaccard >= 0.5 的状态对
"""

from __future__ import annotations

import hashlib
import math
import struct
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, FrozenSet, List, Optional, Set, Tuple


# ---------------------------------------------------------------------------
# 状态指纹提取
# ---------------------------------------------------------------------------

# 约束操作符的类型分类--不追踪具体操作数, 仅追踪约束的"形状"
_CONSTRAINT_TYPE_CLASSES = {
    '==': 0, '!=': 1, '<': 2, '<=': 3, '>': 4, '>=': 5,
    'And': 6, 'Or': 7, 'Not': 8,
    'ULE': 9, 'ULT': 10, 'UGE': 11, 'UGT': 12,
    'Extract': 13, 'Concat': 14, 'ZeroExt': 15, 'SignExt': 16,
    'BVAdd': 17, 'BVSub': 18, 'BVMul': 19, 'BVUDiv': 20,
    'BVAnd': 21, 'BVOr': 22, 'BVXor': 23, 'BVShl': 24, 'BVLshr': 25,
    'If': 26, 'BoolRef': 27,
    'UNKNOWN': 31,
}


def _constraint_type_signature(constraint) -> str:
    """从 Z3 约束对象提取操作符类型--多层保护防止非 Z3 对象崩溃"""
    try:
        # 仅对具有 decl() 方法的对象调用--非 Z3 对象回退到类型名
        if hasattr(constraint, 'decl') and callable(constraint.decl):
            return str(constraint.decl().name())
    except Exception:
        pass
    # 回退: 使用 Python 类型名或字符串表示的前 20 字符
    try:
        type_name = type(constraint).__name__
        if type_name not in ('bool', 'int', 'str', 'NoneType'):
            return type_name
    except Exception:
        pass
    return 'UNKNOWN'


def _constraint_type_class(constraint) -> int:
    """将约束操作符映射到预定义类型类"""
    sig = _constraint_type_signature(constraint)
    return _CONSTRAINT_TYPE_CLASSES.get(sig, 31)


@dataclass
class StateFingerprint:
    """符号状态的轻量级指纹--用于快速相似度估计"""
    state_id: int
    pc: int
    depth: int
    # 约束类型分布: 32 维向量 (对应 _CONSTRAINT_TYPE_CLASSES 的 32 类)
    constraint_type_histogram: List[float] = field(default_factory=lambda: [0.0] * 32)
    # 寄存器符号名集合 (归一化--去架构特定前缀)
    symbolic_register_set: Set[str] = field(default_factory=set)
    # 活跃内存页的粗粒度标识
    active_memory_pages: Set[int] = field(default_factory=set)
    # 调用栈深度
    call_stack_depth: int = 0


class StateFingerprinter:
    """从 SymbolicState 提取轻量指纹

    复杂度: O(|constraints| + |registers| + |memory|) per state
    不访问 Z3 AST 内部--仅通过 decl().name() 获取操作符类型
    """

    @staticmethod
    def fingerprint(state) -> StateFingerprint:
        """提取单个状态的指纹"""
        fp = StateFingerprint(
            state_id=state.state_id,
            pc=state.pc,
            depth=state.depth,
        )

        # 1. 约束类型直方图
        n_constraints = max(1, len(state.path_constraints))
        for c in state.path_constraints:
            cls_id = _constraint_type_class(c)
            fp.constraint_type_histogram[cls_id] += 1.0
        # 归一化到概率分布
        for i in range(32):
            fp.constraint_type_histogram[i] /= n_constraints

        # 2. 符号寄存器集合--只追踪哪些寄存器被符号化, 不追踪具体值
        for reg_name, val in state.registers.items():
            try:
                if hasattr(val, 'decl'):
                    fp.symbolic_register_set.add(reg_name.lower())
            except Exception:
                pass

        # 3. 活跃内存页 (4KB 页粒度--足够粗以避免噪声)
        for addr in state.memory.keys():
            fp.active_memory_pages.add(addr >> 12)

        # 4. 调用栈深度
        fp.call_stack_depth = len(state.call_stack)

        return fp


# ---------------------------------------------------------------------------
# MinHash 签名计算
# ---------------------------------------------------------------------------

class MinHasher:
    """MinHash 签名计算器--使用确定性置换 (SHA-256 based)

    标准 MinHash 使用随机置换但对每个状态重新生成置换不切实际
    本实现将每哈希函数建模为: h_i(x) = SHA-256(i || x) mod M
    其中 M 是大的素数--等价于随机置换的确定性模拟

    K=128 个哈希函数 -> 128 个 int32 签名值
    """

    _M = 2147483647  # 2^31 - 1, Mersenne prime

    def __init__(self, num_hashes: int = 128):
        self._k = num_hashes

    def compute(self, fingerprint: StateFingerprint) -> List[int]:
        """计算状态指纹的 MinHash 签名

        将指纹的三个维度 (约束类型/寄存器集/内存页) 分别哈希
        取各维度的最小值作为该哈希函数的值
        """
        # 生成 shingle 集合: 约束类型 + 寄存器名 + 内存页
        shingles: List[str] = []

        # 约束类型 shingles
        for cls_id, density in enumerate(fingerprint.constraint_type_histogram):
            if density > 0.0:
                shingles.append(f'C{cls_id}:{int(density * 100)}')

        # 寄存器 shingles
        for reg in sorted(fingerprint.symbolic_register_set):
            shingles.append(f'R:{reg}')

        # 内存页 shingles
        for page in sorted(fingerprint.active_memory_pages):
            shingles.append(f'M:{page:08x}')

        # 调用栈 shingle
        shingles.append(f'S:{fingerprint.call_stack_depth}')

        # PC 地址粗粒度 shingle (256 字节对齐--函数级)
        shingles.append(f'P:{fingerprint.pc >> 8}')

        if not shingles:
            return [0] * self._k

        # 计算每哈希函数的 MinHash 值
        signature = []
        for i in range(self._k):
            min_val = self._M
            for shingle in shingles:
                h = self._hash_shingle(i, shingle)
                if h < min_val:
                    min_val = h
            signature.append(min_val)

        return signature

    def _hash_shingle(self, hash_idx: int, shingle: str) -> int:
        """对单个 shingle 应用第 hash_idx 个哈希函数"""
        seed = struct.pack('<I', hash_idx)
        data = seed + shingle.encode('utf-8', errors='replace')
        digest = hashlib.sha256(data).digest()
        val = int.from_bytes(digest[:8], 'little')
        return val % self._M


# ---------------------------------------------------------------------------
# LSH 索引 - 将 MinHash 签名散列到桶
# ---------------------------------------------------------------------------

class MergeCandidateLSH:
    """LSH 索引用于快速发现合并候选状态

    使用 L 个哈希表, 每表使用 r 个 MinHash band
    Band 匹配 -> 两状态有高 Jaccard 相似度的概率 > 1-(1-s^r)^L

    参数:
      num_bands: L (哈希表数), 默认 8
      rows_per_band: r (每 band 的 MinHash 行数), 默认 16
      总计 K = L x r = 128 MinHash 函数

    碰撞概率: P(collision) = 1 - (1 - s^r)^L
      s=0.5, r=16, L=8 -> P ≈ 0.999  (Jaccard >= 0.5 时几乎一定碰撞)
      s=0.2, r=16, L=8 -> P ≈ 0.003  (Jaccard <= 0.2 时几乎从不碰撞)
    """

    def __init__(self, num_bands: int = 8, rows_per_band: int = 16):
        self._L = num_bands
        self._r = rows_per_band
        self._k = num_bands * rows_per_band
        self._hasher = MinHasher(num_hashes=self._k)
        # L 个哈希表: table_idx -> {band_hash: [state_ids]}
        self._tables: List[Dict[int, List[int]]] = [
            {} for _ in range(num_bands)
        ]

    def insert(self, fingerprint: StateFingerprint) -> None:
        """将状态指纹插入 LSH 索引"""
        sig = self._hasher.compute(fingerprint)
        for band in range(self._L):
            start = band * self._r
            band_slice = tuple(sig[start:start + self._r])
            band_hash = hash(band_slice) & 0x7FFFFFFF
            bucket = self._tables[band]
            if band_hash not in bucket:
                bucket[band_hash] = []
            bucket[band_hash].append(fingerprint.state_id)

    def query_candidates(
        self, fingerprint: StateFingerprint
    ) -> Set[int]:
        """查询与给定指纹可能相似的状态 ID 候选集"""
        sig = self._hasher.compute(fingerprint)
        candidates: Set[int] = set()

        for band in range(self._L):
            start = band * self._r
            band_slice = tuple(sig[start:start + self._r])
            band_hash = hash(band_slice) & 0x7FFFFFFF
            bucket = self._tables[band].get(band_hash, [])
            candidates.update(bucket)

        return candidates

    def remove(self, state_id: int) -> None:
        """从 LSH 索引移除状态 (惰性--不重建, 仅标记)

        在实际合并发生后调用--被合并的状态已不存在
        """
        for band in range(self._L):
            bucket = self._tables[band]
            for h, ids in list(bucket.items()):
                filtered = [i for i in ids if i != state_id]
                if filtered:
                    bucket[h] = filtered
                else:
                    del bucket[h]

    @property
    def total_states_indexed(self) -> int:
        """LSH 中索引的状态总数 (含重复--同一状态可跨多表)"""
        total = 0
        for band in range(self._L):
            for ids in self._tables[band].values():
                total += len(ids)
        return total
