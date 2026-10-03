# 压缩共识 — 随机量化梯度压缩的分布式调度器状态同步
#
# 多调度器实例需对集群状态 (负载分布、节点健康状况、任务队列深度)
# 达成共识。全量传输状态向量在实例数 N>10 时通信量 O(N²)。
#
# DIANA-RR 的核心洞见:
#   不应压缩梯度本身 (破坏随机重排的好处)，而应压缩梯度差
#   通过控制迭代 (control iterates) 消除量化噪声。
#   Q(x) = ||x||·sign(x)·⌊|x|/||x|| + ξ⌋ / s  (QSGD 量化)
#   压缩比: 从 32bit/float 降至 2-4 bit/分量。
#
# 本模块将 DIANA 压缩应用于调度器状态共识:
#   每轮各节点发送 compress(state - local_control) 给邻居
#   邻居解压后更新共识估计
#   控制迭代同步: control[i] ← control[i] + α·(state[i] - control[i])
#
# 应用场景:
# 分布式负载聚合: 各节点压缩自身负载向量，广播给邻居
# 全局队列深度估计: 各节点压缩局部队列深度，周期性共识
#   两者通信量从 O(N·d) 降至 O(N·d·b/32), b=量化位宽。

from __future__ import annotations

import math
import random
from typing import List, Optional, Tuple


def qsgd_compress(vector: List[float], bits: int = 4) -> Tuple[List[int], float]:
    """QSGD 随机量化压缩。

    返回 (quantized_ints, norm) —— 接收方用 norm·ints/s 解压。
    压缩比: 32·d / (bits·d + 32) ≈ 32/bits for large d。
    """
    d = len(vector)
    if d == 0:
        return [], 0.0
    # L2 范数
    norm = math.sqrt(sum(v * v for v in vector))
    if norm < 1e-9:
        return [0] * d, 0.0
    s = (1 << (bits - 1)) - 1  # 量化级数: for 4-bit, s=7
    quantized = []
    for v in vector:
        level = v / norm  # ∈ [-1, 1]
        scaled = level * s
        # 随机舍入
        lo = int(math.floor(scaled))
        prob = scaled - lo
        if random.random() < prob:
            qi = lo + 1
        else:
            qi = lo
        qi = max(-s, min(s, qi))
        quantized.append(qi)
    return quantized, norm


def qsgd_decompress(quantized: List[int], norm: float, s: int) -> List[float]:
    """QSGD 解压 — norm·quantized/s。"""
    if s <= 0:
        return [0.0] * len(quantized)
    return [norm * q / s for q in quantized]


def qsgd_decompress_to(quantized: List[int], norm: float, s: int,
                       out: List[float]):
    """就地解压到 out (避免分配)"""
    for i, q in enumerate(quantized):
        out[i] = norm * q / s


def compression_ratio(d: int, bits: int = 4) -> float:
    """压缩比 — 原始 bits / 压缩后 bits。"""
    original = 32 * d
    compressed = bits * d + 32  # ints + norm
    return original / compressed


class CompressedConsensus:
    """DIANA 风格的压缩共识协议。

    每节点维护:
      state:        本地状态向量 (e.g. 各机器负载)
      control:      控制迭代 (跟踪全局均值的本地估计)
      consensus:    全局共识估计 (所有节点的平均状态)

    每轮:
      1. 计算差值: diff = state - control
      2. 压缩差值: (q_diff, norm) = qsgd_compress(diff)
      3. 广播 (q_diff, norm) 给所有邻居
      4. 收到邻居的 (q_diff_j, norm_j) → 解压 → 更新 consensus
      5. 更新控制: control += α·(state - control)
    """

    def __init__(self, d: int, bits: int = 4, alpha: float = 0.1,
                 n_nodes: int = 4):
        self._d = d
        self._bits = bits
        self._alpha = alpha
        self._s = (1 << (bits - 1)) - 1
        self._n = n_nodes

        self._state = [0.0] * d
        self._control = [0.0] * d
        self._consensus = [0.0] * d
        self._rounds: int = 0

    def update_local_state(self, state: List[float]):
        self._state = list(state)

    def prepare_broadcast(self) -> Tuple[List[int], float]:
        """压缩本地状态与控制迭代的差值——准备广播。"""
        diff = [self._state[i] - self._control[i] for i in range(self._d)]
        return qsgd_compress(diff, self._bits)

    def receive_broadcasts(self,
                           broadcasts: List[Tuple[List[int], float]]):
        """接收所有邻居的广播 → 更新共识估计。

        consensus = (1/n)·Σ decompress(q_diff_j, norm_j) + control
        等价于各节点状态均值的无偏估计。
        """
        if not broadcasts:
            return

        # 累积解压差值
        accum = [0.0] * self._d
        for q_diff, norm in broadcasts:
            qsgd_decompress_to(q_diff, norm, self._s, accum)
        # 取均值
        n_recv = len(broadcasts)
        for i in range(self._d):
            accum[i] /= n_recv

        # consensus = control + mean(decompressed_diffs)
        for i in range(self._d):
            self._consensus[i] = self._control[i] + accum[i]

        # 更新控制迭代
        for i in range(self._d):
            self._control[i] += self._alpha * (
                self._state[i] - self._control[i]
            )

        self._rounds += 1

    @property
    def consensus(self) -> List[float]:
        return list(self._consensus)

    @property
    def compression_factor(self) -> float:
        return compression_ratio(self._d, self._bits)

    def stats(self) -> dict:
        return {
            "dimension": self._d,
            "bits_per_component": self._bits,
            "compression_ratio": round(self.compression_factor, 2),
            "rounds": self._rounds,
            "alpha": self._alpha,
            "n_nodes": self._n,
        }
