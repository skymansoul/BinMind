"""
跨尺度熵指纹 (CSEF): 多尺度熵 + 跨尺度耦合 + 自适应 Tsallis q
生成 32 字节紧凑指纹，用于二进制区域分类和相似性检索。
"""
import math
import struct
from typing import List, Tuple
from dataclasses import dataclass

# 4 个观测尺度 (字节)——按 4× 递增，覆盖指令/基本块/函数/节 的典型尺寸
_SCALES = (64, 256, 1024, 4096)
# Tsallis q 候选: 亚扩展 (q<1) 放大尾部事件, 超扩展 (q>1) 放大主模
_Q_CANDIDATES = (0.5, 1.5, 2.0, 3.0)


@dataclass(slots=True)
class CrossScaleProfile:
    """跨尺度熵指纹的数值表示。
    entropy_scales: [H_64, H_256, H_1024, H_4096] 各尺度平均熵 (nats)
    couplings: [ρ_01, ρ_12, ρ_23] 相邻尺度 Spearman 秩相关系数
    tsallis_q: 最优 Tsallis q 参数
    """

    entropy_scales: Tuple[float, float, float, float]
    couplings: Tuple[float, float, float]
    tsallis_q: float

    def to_bytes(self) -> bytes:
        """将指纹序列化为 32 字节 (8 × float32, little-endian)。"""
        parts = list(self.entropy_scales) + list(self.couplings) + [self.tsallis_q]
        return struct.pack("<8f", *parts)

    @classmethod
    def from_bytes(cls, data: bytes) -> "CrossScaleProfile":
        """从 32 字节反序列化。"""
        if len(data) < 32:
            raise ValueError(f"需要 32 字节，收到 {len(data)}")
        vals = struct.unpack("<8f", data[:32])
        return cls(
            entropy_scales=(vals[0], vals[1], vals[2], vals[3]),
            couplings=(vals[4], vals[5], vals[6]),
            tsallis_q=vals[7],
        )

    def euclidean_distance(self, other: "CrossScaleProfile") -> float:
        """两个指纹之间的欧氏距离。entropy_scales 和 couplings 各占 50% 权重。"""
        d_ent = math.dist(self.entropy_scales, other.entropy_scales)
        d_cpl = math.dist(self.couplings, other.couplings)
        # 归一化: 熵值域约 [0, 8], 耦合值域 [-1, 1]
        return 0.5 * (d_ent / 8.0) + 0.5 * (d_cpl / 2.0)

    def cosine_similarity(self, other: "CrossScaleProfile") -> float:
        """余弦相似度，用于 SIMD 友好的大批量比较。"""
        a = list(self.entropy_scales) + list(self.couplings) + [self.tsallis_q]
        b = list(other.entropy_scales) + list(other.couplings) + [other.tsallis_q]
        dot = sum(x * y for x, y in zip(a, b))
        na = math.sqrt(sum(x * x for x in a))
        nb = math.sqrt(sum(y * y for y in b))
        if na == 0 or nb == 0:
            return 0.0
        return dot / (na * nb)


def _shannon_entropy_from_counts(counts: List[int], total: int) -> float:
    """从字节频次表计算 Shannon 熵 (nats)。零频次槽位自动跳过。"""
    if total == 0:
        return 0.0
    inv = 1.0 / total
    ent = 0.0
    for c in counts:
        if c > 0:
            p = c * inv
            ent -= p * math.log(p)
    return ent


def _tsallis_entropy_from_counts(counts: List[int], total: int, q: float) -> float:
    """从字节频次表计算 Tsallis 熵。q=1 退化为 Shannon 熵。"""
    if total == 0:
        return 0.0
    if abs(q - 1.0) < 1e-9:
        return _shannon_entropy_from_counts(counts, total)
    inv = 1.0 / total
    sum_pow = 0.0
    for c in counts:
        if c > 0:
            sum_pow += (c * inv) ** q
    return (1.0 - sum_pow) / (q - 1.0)


def _spearman_r(x: List[float], y: List[float]) -> float:
    """Spearman 秩相关系数。x, y 长度须一致且 ≥ 3。"""
    n = len(x)
    if n < 3:
        return 0.0
    # 秩转换——等值取平均秩
    def rank(vals: List[float]) -> List[float]:
        indexed = sorted(enumerate(vals), key=lambda p: p[1])
        ranks = [0.0] * n
        i = 0
        while i < n:
            j = i
            while j < n and indexed[j][1] == indexed[i][1]:
                j += 1
            avg_rank = (i + j - 1) / 2.0 + 1.0
            for k in range(i, j):
                ranks[indexed[k][0]] = avg_rank
            i = j
        return ranks

    rx = rank(x)
    ry = rank(y)
    mean_rx = (n + 1) / 2.0
    num = sum((rx[i] - mean_rx) * (ry[i] - mean_rx) for i in range(n))
    den = math.sqrt(
        sum((rx[i] - mean_rx) ** 2 for i in range(n))
        * sum((ry[i] - mean_rx) ** 2 for i in range(n))
    )
    if den == 0:
        return 0.0
    return num / den


def compute_csef(data: bytes) -> CrossScaleProfile:
    """计算跨尺度熵指纹。
    主遍历: O(N) 层级直方图合并——4 个尺度的熵在一次扫描中同时产出。
    q 优化: 额外的 O(N) 次遍历——仅在数据 ≥ 1024 字节时执行，
    对每个候选 q 重新扫描 256-字节块计算 Tsallis 序列方差。
    """
    n = len(data)
    if n < _SCALES[0]:
        # 数据不足以覆盖最小尺度——仅基于全部数据计算
        cnt = [0] * 256
        for b in data:
            cnt[b] += 1
        h = _shannon_entropy_from_counts(cnt, n)
        return CrossScaleProfile(
            entropy_scales=(h, h, h, h),
            couplings=(0.0, 0.0, 0.0),
            tsallis_q=1.0,
        )

    num_levels = len(_SCALES)
    # hist[level][256] —— 当前未完成块的直方图
    hist: List[List[int]] = [[0] * 256 for _ in range(num_levels)]
    # 每级当前块的已累积字节数
    accum: List[int] = [0] * num_levels
    # 每级全部已完成块的熵值序列
    entropy_seq: List[List[float]] = [[] for _ in range(num_levels)]
    # 每级全部已完成块的 Tsallis 熵 (q=2.0，用于方差计算)
    tsallis_seq: List[List[float]] = [[] for _ in range(num_levels)]

    for byte in data:
        hist[0][byte] += 1
        accum[0] += 1
        # 检查尺度 0 是否完成一个块
        if accum[0] == _SCALES[0]:
            h0 = _shannon_entropy_from_counts(hist[0], _SCALES[0])
            entropy_seq[0].append(h0)
            tsallis_seq[0].append(
                _tsallis_entropy_from_counts(hist[0], _SCALES[0], 2.0)
            )
            # 合并到尺度 1
            for b_idx in range(256):
                hist[1][b_idx] += hist[0][b_idx]
            accum[1] += _SCALES[0]
            hist[0] = [0] * 256
            accum[0] = 0
            # 递归检查更高级别
            for level in range(1, num_levels):
                if accum[level] >= _SCALES[level]:
                    h_lev = _shannon_entropy_from_counts(hist[level], _SCALES[level])
                    entropy_seq[level].append(h_lev)
                    tsallis_seq[level].append(
                        _tsallis_entropy_from_counts(hist[level], _SCALES[level], 2.0)
                    )
                    if level + 1 < num_levels:
                        for b_idx in range(256):
                            hist[level + 1][b_idx] += hist[level][b_idx]
                        accum[level + 1] += _SCALES[level]
                    hist[level] = [0] * 256
                    accum[level] = 0

    # 处理尾部残余——所有未完成的块按实际大小计算
    for level in range(num_levels):
        if accum[level] > 0:
            h = _shannon_entropy_from_counts(hist[level], accum[level])
            entropy_seq[level].append(h)
            tsallis_seq[level].append(
                _tsallis_entropy_from_counts(hist[level], accum[level], 2.0)
            )

    # 各尺度平均熵
    mean_entropies = tuple(
        sum(seq) / len(seq) if seq else 0.0 for seq in entropy_seq
    )

    # 跨尺度耦合: Spearman ρ 在相邻尺度间
    couplings: List[float] = []
    for lev in range(num_levels - 1):
        fine = entropy_seq[lev]
        coarse = entropy_seq[lev + 1]
        # 每个粗尺度块对应 4 个细尺度块——取细尺度的 4-块均值对齐
        ratio = _SCALES[lev + 1] // _SCALES[lev]
        aligned_fine: List[float] = []
        for i in range(0, len(fine) - ratio + 1, ratio):
            aligned_fine.append(sum(fine[i : i + ratio]) / ratio)
        # 截断到较短的长度
        min_len = min(len(aligned_fine), len(coarse))
        if min_len >= 3:
            couplings.append(_spearman_r(aligned_fine[:min_len], coarse[:min_len]))
        else:
            couplings.append(0.0)

    # 自适应 Tsallis q: 选使尺度 1 块间熵方差最大的 q
    best_q = 1.0
    best_var = -1.0
    # 使用尺度 1 的数据块 (256 字节窗口) 作为判别基础
    seq_for_q = entropy_seq[1] if len(entropy_seq[1]) >= 4 else entropy_seq[0]
    if len(seq_for_q) >= 4:
        # 对完整数据重新计算各 q 下的 Tsallis 熵序列
        for q in _Q_CANDIDATES:
            # 在尺度 1 块上采样
            block_size = _SCALES[1]
            tsallis_vals: List[float] = []
            for i in range(0, n - block_size + 1, block_size):
                chunk = data[i : i + block_size]
                cnt = [0] * 256
                for b in chunk:
                    cnt[b] += 1
                tsallis_vals.append(
                    _tsallis_entropy_from_counts(cnt, block_size, q)
                )
            if len(tsallis_vals) >= 2:
                mean_v = sum(tsallis_vals) / len(tsallis_vals)
                var_v = sum((v - mean_v) ** 2 for v in tsallis_vals) / len(tsallis_vals)
                if var_v > best_var:
                    best_var = var_v
                    best_q = q

    return CrossScaleProfile(
        entropy_scales=mean_entropies,
        couplings=(couplings[0] if len(couplings) > 0 else 0.0,
                   couplings[1] if len(couplings) > 1 else 0.0,
                   couplings[2] if len(couplings) > 2 else 0.0),
        tsallis_q=best_q,
    )


def compute_csef_streaming() -> "StreamingCSEF":
    """创建流式 CSEF 计算器。实现位于 csef_scan 模块。"""
    from modules.utils.csef_scan import StreamingCSEF
    return StreamingCSEF()
