# TODO: 考虑适配 ARM Thumb 模式, Thumb 的 16-bit 指令在特征提取时需要特殊处理

# 语义函数哈希 — 对编译器版本和优化级别不敏感的函数级结构签名
#
# 传统模糊哈希（ssdeep, TLSH）在指令序列级别做相似度, 编译器改变
# 指令顺序（如 GCC 的指令调度）后哈希彻底不同。本模块的哈希不依赖
# 指令序列，而是基于基本块级别的统计特征分布,
#   1. 基本块指纹直方图：每个基本块的 (入度,出度,指令数,调用数) → bucket
#   2. 控制流骨架签名：CFG 邻接矩阵的图核 (graph kernel) 近似
#   3. 函数级特征：总块数、环数、调用密度、平均块大小
#
# 三项各自生成 64-bit 分量，拼接为 192-bit 函数哈希
# 两个函数的相似度 = 三项分量各自的汉明距离的加权平均
#
# 这个哈希不是用来替代 SimHash 做路径去重的, 它是函数级别的
# 用于跨编译/跨版本识别"同一个函数"（如漏洞函数在补丁前后的定位）

import hashlib
import struct
import numpy as np
from typing import Dict, List, Tuple


def block_histogram_hash(blocks: List[Dict], num_buckets: int = 32) -> int:
    """基本块指纹直方图的 64-bit 哈希

    每个块的 (入度,出度,指令数,调用数) 四元组压缩为 bucket index =
    (in_deg * 7 + out_deg * 11 + instr_count * 3 + call_count * 13) % num_buckets
    系数选三个互质的小素数, 减少不同四元组碰撞到同一 bucket 的概率

    直方图 → SHA256 → 前 8 字节 → uint64
    """
    counts = [0] * num_buckets
    for b in blocks:
        idx = (b.get('in_degree', 0) * 7 +
               b.get('out_degree', 0) * 11 +
               b.get('instr_count', 0) * 3 +
               b.get('call_count', 0) * 13) % num_buckets
        counts[idx] += 1

    raw = struct.pack(f'<{num_buckets}i', *counts)
    h = hashlib.sha256(raw).digest()
    return struct.unpack_from('<Q', h, 0)[0]


def graph_kernel_hash(adj: np.ndarray) -> int:
    """CFG 邻接矩阵的图核近似 64-bit 哈希

    对邻接矩阵的 k 次幂迹 (trace A^k, k=1,2,3) 做 SHA256
    A^1 的迹 = 自环数（通常 0），A^2 的迹 = 长度为 2 的闭环数
    A^3 的迹 = 长度为 3 的闭环数。这三个数字编码了 CFG 的循环拓扑,
    不依赖节点编号，对基本块重排完全不变

    选择 k=1,2,3 而非更高次幂的原因: 更高次幂的迹在数值上快速膨胀
    且对不同 CFG 的区分度随 k 增大而衰减（谱半径效应）
    """
    n = adj.shape[0]
    if n == 0:
        return 0

    traces = []
    Ak = np.eye(n) if n > 0 else np.array([[0]])
    for k in range(1, 4):
        Ak = Ak @ adj if k > 1 else adj.copy()
        tr = float(np.trace(Ak))
        traces.append(tr)

    raw = struct.pack('<ddd', *traces)
    h = hashlib.sha256(raw).digest()
    return struct.unpack_from('<Q', h, 0)[0]


def function_level_hash(blocks: List[Dict]) -> int:
    """函数级统计特征 64-bit 哈希

    总块数、环数（含回边的块数）、调用密度（含 call 的块数/总块数）、
    平均块指令数, 四项统计量 → SHA-256 前 8 字节
    """
    n = len(blocks)
    if n == 0:
        return 0

    loop_blocks = sum(1 for b in blocks if b.get('is_loop_member', False))
    call_blocks = sum(1 for b in blocks if b.get('call_count', 0) > 0)
    avg_instr = sum(b.get('instr_count', 0) for b in blocks) / n

    call_density = call_blocks / n
    raw = struct.pack('<iifd', n, loop_blocks, call_density, avg_instr)
    h = hashlib.sha256(raw).digest()
    return struct.unpack_from('<Q', h, 0)[0]


def semantic_function_hash(blocks: List[Dict], adj: np.ndarray) -> int:
    """组合三项哈希为 192-bit 函数签名（返回 Python int）

    调用方可用 >> 128 和 >> 64 分别提取三项分量
    分别计算汉明距离来定位差异来源（是块分布变了还是 CFG 骨架变了）
    """
    h1 = block_histogram_hash(blocks)
    h2 = graph_kernel_hash(adj)
    h3 = function_level_hash(blocks)
    return (h1 << 128) | (h2 << 64) | h3


def hash_similarity(hash_a: int, hash_b: int) -> float:
    """两个语义函数哈希的相似度 [0, 1]

    三项分量各自的汉明距离 → 归一化 → 加权（直方图 0.4, 图核 0.35, 函数级 0.25）
    图核权重略低, 邻接矩阵的迹对 CFG 的小改动敏感（如一个 NOP 块的插入
    会轻微改变 A^2 迹），不宜给太高
    """
    def component_sim(shift):
        mask = (1 << 64) - 1
        a = (hash_a >> shift) & mask
        b = (hash_b >> shift) & mask
        hamming = (a ^ b).bit_count()
        return 1.0 - hamming / 64.0

    sims = [component_sim(128), component_sim(64), component_sim(0)]
    return 0.4 * sims[0] + 0.35 * sims[1] + 0.25 * sims[2]
