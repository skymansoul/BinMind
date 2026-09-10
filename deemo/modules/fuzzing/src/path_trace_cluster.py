"""MinHash LSH 执行路径聚类 — 基于路径签名的种子相似性快速检索.

  Broder "On the resemblance and containment of documents"
    — MinHash 用于估计 Jaccard 相似度的理论基础
  Gionis et al. "Similarity Search in High Dimensions via Hashing"
    — LSH 分桶理论, b 个 band 各 r 行, 碰撞概率 = 1-(1-s^r)^b
  SimFuzz    — 执行路径聚类用于并行 fuzzing 冲突消解
  HuntFUZZ     — 基于路径共性的错误点聚类

核心假设:
  边覆盖率丢失了边的执行顺序信息。两条完全不同的执行路径可能碰巧
  产生相同的边覆盖集。反之, 共享大部分边的路径可能因少数分叉而行为迥异。
  通过对执行 trace (边ID序列) 进行 MinHash 签名, 可以保留路径的结构相似性,
  代价是固定的签名大小 (128 个 32-bit 值 = 512B/种子)。

与现有模块的关系:
  - ISRG (seed_relation_graph.py): 对覆盖集合做 Jaccard → 静态覆盖关系
  - PathCluster: 对执行 trace 做 MinHash Jaccard → 动态路径关系
  - 两者互补: ISRG 看"覆盖了什么", PathCluster 看"怎么覆盖的"
"""

import hashlib
import math
import struct
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, FrozenSet, List, Optional, Set, Tuple

# MinHash 参数
_NUM_HASHES = 128          # 签名中的哈希函数个数
_LSH_BANDS = 16            # LSH band 数
_LSH_ROWS = _NUM_HASHES // _LSH_BANDS  # 每个 band 的行数 (=8)

@dataclass
class PathSignature:
    """一个执行路径的 MinHash 签名。"""
    seed_id: str
    minhash_sig: List[int]           # 128 个 uint32, 每个是某哈希函数的最小值
    trace_length: int                # 原始 trace 长度
    created_at: float = field(default_factory=time.time)

class PathCluster:
    """基于 MinHash LSH 的执行路径聚类器。

    每条执行 trace 是边 ID 的有序序列 (可能包含重复, 因为循环)。
    MinHash 将 trace 压缩为固定大小的签名, 签名间的 Jaccard 距离
    近似于原始 trace 元素集合的 Jaccard 距离。

    LSH 将签名分桶: 将 128 个哈希值切为 16 个 band × 8 行,
    每个 band 产生一个桶键。两个签名只要在任意一个 band 中碰撞,
    就视为候选近邻 — 这大大加速了大规模语料库中的相似性查询。

    复杂度: 插入 O(b), 查询 O(b + candidates), b = band数
    """

    def __init__(self):
        # seed_id → PathSignature
        self._signatures: Dict[str, PathSignature] = {}
        # LSH 桶: bucket_key (int) → [seed_id, ...]
        self._buckets: Dict[int, List[str]] = defaultdict(list)
        # 全局边的 IDF 权重 (出现越多越不重要)
        self._edge_doc_freq: Dict[int, int] = defaultdict(int)
        self._total_traces: int = 0

    # //// 主入口: 插入一条执行 trace ////
    def insert(self, seed_id: str, trace: List[int]) -> None:
        """将一条执行 trace 的 MinHash 签名插入聚类器。

        trace: 边 ID 的有序列表 (可能含重复, 如循环展开的 trace)。
        内部会去重为集合后计算 MinHash, 但保留 trace_length 作为附加信息。
        """
        if not trace:
            return

        self._total_traces += 1
        edge_set = set(trace)

        # 更新 IDF 计数
        for eid in edge_set:
            self._edge_doc_freq[eid] += 1
        # 为避免内存无限增长, 在超过 10 万条 trace 时对 IDF 做衰减
        if self._total_traces > 100000:
            self._decay_idf()

        sig = self._compute_minhash(edge_set)
        ps = PathSignature(
            seed_id=seed_id,
            minhash_sig=sig,
            trace_length=len(trace),
        )

        # 移除旧签名 (若存在)
        old = self._signatures.pop(seed_id, None)
        if old is not None:
            self._remove_from_buckets(seed_id)

        self._signatures[seed_id] = ps
        self._add_to_buckets(seed_id, sig)

    # //// MinHash 签名计算 ////
    def _compute_minhash(self, edge_set: Set[int]) -> List[int]:
        """计算边集合的 MinHash 签名。

        使用双重哈希方案: h_i(x) = (a_i * x + b_i) mod p
        其中 a_i, b_i 是固定的随机系数, p 是大质数。
        相比为每个哈希函数独立迭代元素集合, 此方案只需一次遍历。
        """
        if not edge_set:
            return [0xFFFFFFFF] * _NUM_HASHES

        # 固定系数 (来自 SHA256 的确定性派生, 避免硬编码随机数)
        coeffs = self._hash_coefficients()
        sig = [0xFFFFFFFF] * _NUM_HASHES

        # 大质数, 接近 2^32
        p = 4294967291

        for eid in edge_set:
            x = eid & 0xFFFFFFFF
            for i in range(_NUM_HASHES):
                a_i, b_i = coeffs[i]
                h = ((a_i * x + b_i) % p)
                if h < sig[i]:
                    sig[i] = h

        return sig

    def _hash_coefficients(self) -> List[Tuple[int, int]]:
        """从 MD5 确定性派生 128 组 (a_i, b_i) 哈希系数。

        不依赖 random 模块, 保证跨进程/跨平台的签名一致性。
        """
        coeffs = []
        seed = b"BinMind::PathCluster::MinHash::v1"
        h = hashlib.md5(seed)
        for i in range(_NUM_HASHES):
            h.update(f"coeff:{i}".encode())
            digest = h.digest()
            a = int.from_bytes(digest[:4], 'little') | 1  # 奇数, 避免乘0
            b = int.from_bytes(digest[4:8], 'little')
            coeffs.append((a, b))
        return coeffs

    # //// LSH 分桶 ////
    def _band_key(self, sig: List[int], band_idx: int) -> int:
        """计算指定 band 的桶键 — 将 band 内的 r 个哈希值混编为单个整数。"""
        start = band_idx * _LSH_ROWS
        chunk = sig[start:start + _LSH_ROWS]
        # 用 SHA256 混编 chunk 以均匀分布桶
        raw = b''.join(struct.pack('<I', v) for v in chunk)
        return int.from_bytes(hashlib.sha256(raw).digest()[:8], 'little')

    def _add_to_buckets(self, seed_id: str, sig: List[int]) -> None:
        for b in range(_LSH_BANDS):
            key = self._band_key(sig, b)
            self._buckets[key].append(seed_id)

    def _remove_from_buckets(self, seed_id: str) -> None:
        """全量扫描清除旧桶条目 (频率低, 接受 O(buckets) 开销)。"""
        for bucket_list in self._buckets.values():
            if seed_id in bucket_list:
                bucket_list[:] = [sid for sid in bucket_list if sid != seed_id]

    # //// 相似种子查询 ////
    def query_similar(self, seed_id: str, top_k: int = 10,
                      min_jaccard: float = 0.1) -> List[Tuple[str, float]]:
        """查找与指定种子执行路径最相似的 top_k 个种子。

        通过 LSH 过滤候选集, 然后对候选计算精确 Jaccard。
        若目标种子不在聚类器中, 返回空列表。
        """
        sig = self._signatures.get(seed_id)
        if sig is None:
            return []

        # 候选集: 所有 LSH 桶中与该种子碰撞的种子
        candidates: Set[str] = set()
        for b in range(_LSH_BANDS):
            key = self._band_key(sig.minhash_sig, b)
            for sid in self._buckets.get(key, []):
                if sid != seed_id:
                    candidates.add(sid)

        if not candidates:
            return []

        # 对候选计算精确 MinHash Jaccard
        scored = []
        for sid in candidates:
            other = self._signatures.get(sid)
            if other is None:
                continue
            jac = self._minhash_jaccard(sig.minhash_sig, other.minhash_sig)
            if jac >= min_jaccard:
                scored.append((sid, jac))

        scored.sort(key=lambda x: x[1], reverse=True)
        return scored[:top_k]

    def _minhash_jaccard(self, sig_a: List[int], sig_b: List[int]) -> float:
        """两个 MinHash 签名间的 Jaccard 估计 = 对应位置相等的比例。"""
        matches = sum(1 for a, b in zip(sig_a, sig_b) if a == b)
        return matches / _NUM_HASHES

    # //// 路径多样性贡献 ////
    def path_diversity_score(self, seed_id: str) -> float:
        """计算该种子在路径空间中的局部多样性 (0~1)。

        1.0 = 该种子的执行路径与所有近邻都不相似 → 高度独特。
        与 ISRG.diversity_score 的区别: ISRG 看覆盖集合, 此处看路径结构。
        两者相关但不等价 — 同一覆盖集的两种不同路径可在此获得高分。
        """
        similar = self.query_similar(seed_id, top_k=5, min_jaccard=0.0)
        if not similar:
            return 1.0
        avg_sim = sum(s for _, s in similar) / len(similar)
        return 1.0 - avg_sim

    # //// 路径冗余检测 ////
    def find_near_duplicates(self, threshold: float = 0.95) -> List[Tuple[str, str, float]]:
        """检测执行路径几乎相同的种子对 (Jaccard > threshold)。

        这些对是压缩语料库的候选 — 可以安全地移除其中一个。
        """
        pairs = []
        seen: Set[FrozenSet[str]] = set()
        sigs = list(self._signatures.items())

        # 按 trace_length 预过滤: 长度差 > 2× 的不可能高相似
        for i in range(len(sigs)):
            sid_a, sig_a = sigs[i]
            for j in range(i + 1, len(sigs)):
                sid_b, sig_b = sigs[j]
                pair_key = frozenset([sid_a, sid_b])
                if pair_key in seen:
                    continue
                seen.add(pair_key)

                # 长度差异过滤
                len_ratio = min(sig_a.trace_length, sig_b.trace_length) / max(
                    1, max(sig_a.trace_length, sig_b.trace_length))
                if len_ratio < 0.5:
                    continue

                jac = self._minhash_jaccard(sig_a.minhash_sig, sig_b.minhash_sig)
                if jac >= threshold:
                    pairs.append((sid_a, sid_b, jac))

        return sorted(pairs, key=lambda x: x[2], reverse=True)

    # //// IDF 衰减 ////
    def _decay_idf(self) -> None:
        """全局 IDF 计数的指数衰减 — 防止长时间运行后新边权重被淹没。"""
        factor = 0.9
        for eid in list(self._edge_doc_freq.keys()):
            self._edge_doc_freq[eid] = max(1, int(self._edge_doc_freq[eid] * factor))

    # //// 统计 ////
    def stats(self) -> dict:
        n = len(self._signatures)
        n_buckets = len(self._buckets)
        avg_bucket_size = sum(len(v) for v in self._buckets.values()) / max(1, n_buckets)

        diversities = [
            self.path_diversity_score(sid) for sid in self._signatures
        ]
        return {
            "total_signatures": n,
            "total_traces_inserted": self._total_traces,
            "lsh_bands": _LSH_BANDS,
            "lsh_rows_per_band": _LSH_ROWS,
            "lsh_buckets": n_buckets,
            "avg_bucket_size": round(avg_bucket_size, 2),
            "avg_path_diversity": sum(diversities) / max(1, n),
            "near_duplicate_pairs": len(self.find_near_duplicates()),
        }

    def clear(self) -> None:
        self._signatures.clear()
        self._buckets.clear()
        self._edge_doc_freq.clear()
        self._total_traces = 0

# 加权 MinHash (IDF 加权)

def weighted_minhash_signature(edge_set: Set[int],
                               idf_weights: Dict[int, float],
                               n_hashes: int = 128) -> List[int]:
    """IDF 加权的 MinHash 签名变体。

    标准 MinHash 对集合元素等权重。此处引入 IDF 权重:
    罕见的边 (如异常处理路径) 在签名中获得更高权重,
    常见边 (如 libc 入口) 被降权。

    参考: Chum et al. "Total Recall: Automatic Query Expansion
    with a Generative Feature Model for Object Retrieval" 中的加权 MinHash。
    """
    if not edge_set:
        return [0xFFFFFFFF] * n_hashes

    coeffs = _hash_coeffs_static(n_hashes)
    sig = [0xFFFFFFFF] * n_hashes
    p = 4294967291

    for eid in edge_set:
        x = eid & 0xFFFFFFFF
        w = idf_weights.get(eid, 1.0)
        # 权重映射到虚拟重复次数 (上限 255)
        reps = min(255, max(1, int(w * 10)))
        for _ in range(reps):
            for i in range(n_hashes):
                a_i, b_i = coeffs[i]
                h = ((a_i * x + b_i) % p)
                if h < sig[i]:
                    sig[i] = h

    return sig

def _hash_coeffs_static(n: int) -> List[Tuple[int, int]]:
    """与 PathCluster._hash_coefficients 相同的确定性系数生成, 独立函数。"""
    import hashlib
    coeffs = []
    h = hashlib.md5(b"BinMind::PathCluster::MinHash::v1")
    for i in range(n):
        h.update(f"coeff:{i}".encode())
        digest = h.digest()
        a = int.from_bytes(digest[:4], 'little') | 1
        b = int.from_bytes(digest[4:8], 'little')
        coeffs.append((a, b))
    return coeffs
