"""
熵引导的内容定义分块 (EG-CDC)
-------------------------------
滚动哈希 CDC + 局部熵反馈: 高熵→粗粒度分块, 低熵→细粒度分块。
滞后机制防止参数在熵边界处反复切换。
"""
import math
from typing import List, Tuple, Iterator
from dataclasses import dataclass

# 熵→参数的映射表
# 格式: (entropy_low, entropy_high, window_size, trigger_mask, min_chunk)
_ENTROPY_PARAM_TABLE = [
    # 低熵 (0-4 nats): 结构化数据、文本——细粒度分块
    (0.0, 4.0, 32, 0x07FF, 64),
    # 中熵 (4-6 nats): 机器码、混合数据——标准粒度
    (4.0, 6.0, 48, 0x0FFF, 256),
    # 中高熵 (6-7 nats): 压缩数据——粗粒度
    (6.0, 7.0, 64, 0x1FFF, 512),
    # 高熵 (7-8 nats): 加密/高强度压缩——最粗粒度
    (7.0, 8.0, 96, 0x3FFF, 1024),
]

# 熵估计窗口 (字节数)
_ENTROPY_WINDOW = 256
# 指数滑动平均系数——控制熵估计的响应速度
# 0.3: 较快响应 (约 5 个窗口达到稳态)
_EMA_ALPHA = 0.3
# 参数切换的滞后阈值——熵变化小于此值时维持当前参数
_HYSTERESIS = 0.4


@dataclass(slots=True)
class ChunkInfo:
    """单个块的元信息。"""
    offset: int        # 块在原始数据中的起始偏移
    length: int        # 块长度 (字节)
    entropy: float     # 切割点处的局部熵估计


def _entropy_ema(histogram: List[int], total: int) -> float:
    """从 256 槽直方图计算 Shannon 熵 (nats)。"""
    if total == 0:
        return 0.0
    inv = 1.0 / total
    ent = 0.0
    for c in histogram:
        if c > 0:
            p = c * inv
            ent -= p * math.log(p)
    return ent


def _select_params(entropy: float) -> Tuple[int, int, int]:
    """根据熵值选择 CDC 参数。
    返回 (window_size, trigger_mask, min_chunk)。
    使用阈值表进行分段常数映射——比连续函数更可解释且抗噪。
    """
    for lo, hi, ws, mask, mc in _ENTROPY_PARAM_TABLE:
        if lo <= entropy < hi:
            return ws, mask, mc
    # 兜底: 超高熵 (>8, 实际不可能) 用最粗粒度
    return _ENTROPY_PARAM_TABLE[-1][2:]


class EntropyGuidedCDC:
    """熵引导的 CDC 分块器。"""

    def __init__(self):
        # 当前熵估计 (指数滑动平均)
        self._current_entropy: float = 4.5  # 中性初值
        # 当前使用的参数组索引——用于滞后判断
        self._current_level: int = 1  # 对应中熵段

    def _update_entropy(self, histogram: List[int], total: int):
        """用新直方图更新熵估计 (EMA 平滑)。"""
        raw = _entropy_ema(histogram, total)
        self._current_entropy = (
            _EMA_ALPHA * raw + (1.0 - _EMA_ALPHA) * self._current_entropy
        )

    def _maybe_switch_params(self) -> Tuple[int, int, int]:
        """根据当前熵估计选择 CDC 参数，滞后防抖。"""
        ent = self._current_entropy
        # 确定熵值落入的参数段
        target_level = self._current_level
        for i, (lo, hi, _, _, _) in enumerate(_ENTROPY_PARAM_TABLE):
            if lo <= ent < hi:
                target_level = i
                break
        # 滞后: 仅当跨越段边界且差值超过阈值时才切换
        if target_level != self._current_level:
            mid_current = (
                _ENTROPY_PARAM_TABLE[self._current_level][0]
                + _ENTROPY_PARAM_TABLE[self._current_level][1]
            ) / 2.0
            mid_target = (
                _ENTROPY_PARAM_TABLE[target_level][0]
                + _ENTROPY_PARAM_TABLE[target_level][1]
            ) / 2.0
            if abs(mid_target - mid_current) > _HYSTERESIS:
                self._current_level = target_level
        return _ENTROPY_PARAM_TABLE[self._current_level][2:]

    def chunkify(self, data: bytes) -> Iterator[ChunkInfo]:
        """将字节数据分割为熵引导的变长块。
        返回 ChunkInfo 迭代器——不复制数据，仅记录偏移和长度。
        """
        n = len(data)
        if n == 0:
            return

        # 初始化熵估计: 用第一个窗口
        init_hist = [0] * 256
        init_len = min(_ENTROPY_WINDOW, n)
        for i in range(init_len):
            init_hist[data[i]] += 1
        self._current_entropy = _entropy_ema(init_hist, init_len)
        self._current_level = 1  # 重置到中熵段

        ws, trigger_mask, min_chunk = self._maybe_switch_params()
        chunk_start = 0
        entropy_hist = init_hist[:]

        # 滚动哈希窗口
        window = 0
        MOD = 0xFFFFFFFF
        for i in range(min(ws, n)):
            window = ((window << 1) ^ data[i]) & MOD

        i = ws
        while i < n:
            # 每 64 字节更新一次熵估计
            if i % 64 == 0 and i >= _ENTROPY_WINDOW:
                # 滑动直方图: 移出旧字节，移入新字节
                for j in range(i - 64, i):
                    if j >= _ENTROPY_WINDOW:
                        old_byte = data[j - _ENTROPY_WINDOW]
                        entropy_hist[old_byte] = max(0, entropy_hist[old_byte] - 1)
                        entropy_hist[data[j]] += 1
                self._update_entropy(entropy_hist, _ENTROPY_WINDOW)
                ws, trigger_mask, min_chunk = self._maybe_switch_params()

            # CDC 切割判断
            if (window & trigger_mask) == 0 and (i - chunk_start) >= min_chunk:
                yield ChunkInfo(
                    offset=chunk_start,
                    length=i - chunk_start,
                    entropy=self._current_entropy,
                )
                chunk_start = i
                # 重置滚动哈希窗口
                window = 0
                new_ws = min(ws, n - i)
                for j in range(new_ws):
                    window = ((window << 1) ^ data[i + j]) & MOD
                i += new_ws
                continue

            # 更新滚动哈希
            window = ((window << 1) ^ data[i]) & MOD
            window ^= (data[i - ws] << ws) & MOD
            i += 1

        # 最后一个块
        if chunk_start < n:
            yield ChunkInfo(
                offset=chunk_start,
                length=n - chunk_start,
                entropy=self._current_entropy,
            )

    def reset(self):
        """重置内部状态——切换数据源时调用。"""
        self._current_entropy = 4.5
        self._current_level = 1


def eg_cdc_chunks(data: bytes) -> List[ChunkInfo]:
    """便捷函数: 一次性返回所有块的元信息列表。"""
    cdc = EntropyGuidedCDC()
    return list(cdc.chunkify(data))


def eg_cdc_boundary_entropy_map(data: bytes) -> List[Tuple[int, float]]:
    """返回切割点列表: [(offset, entropy_at_cut), ...]。
    排除偏移 0 (起始点不是切割点)。
    用于跨版本二进制的边界稳定性分析。
    """
    chunks = eg_cdc_chunks(data)
    return [(ch.offset + ch.length, ch.entropy) for ch in chunks[:-1]]


def eg_cdc_compare(
    data_a: bytes, data_b: bytes
) -> dict:
    """比较两个二进制文件的 EG-CDC 分块结果。
    返回块数比、平均块大小比、熵分布差异等指标——
    用于评估分块稳定性。
    """
    chunks_a = eg_cdc_chunks(data_a)
    chunks_b = eg_cdc_chunks(data_b)
    len_a = [ch.length for ch in chunks_a]
    len_b = [ch.length for ch in chunks_b]
    ent_a = [ch.entropy for ch in chunks_a]
    ent_b = [ch.entropy for ch in chunks_b]
    avg_len_a = sum(len_a) / len(len_a) if len_a else 0
    avg_len_b = sum(len_b) / len(len_b) if len_b else 0
    avg_ent_a = sum(ent_a) / len(ent_a) if ent_a else 0
    avg_ent_b = sum(ent_b) / len(ent_b) if ent_b else 0
    return {
        "chunk_count_a": len(chunks_a),
        "chunk_count_b": len(chunks_b),
        "avg_chunk_len_a": avg_len_a,
        "avg_chunk_len_b": avg_len_b,
        "avg_entropy_a": avg_ent_a,
        "avg_entropy_b": avg_ent_b,
        "len_ratio": avg_len_a / avg_len_b if avg_len_b else 0,
        "entropy_delta": avg_ent_a - avg_ent_b,
    }
