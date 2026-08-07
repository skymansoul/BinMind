# 零熵区域优化 + 向量化 CDC 增强
#
#   Al Jarah et al., "The Impact of Low-Entropy on Chunking Techniques for
#     Data Deduplication": 零熵/低熵数据块对 CDC 算法
#     (Rabin, FastCDC, AE, RAM) 的性能损耗分析 —— 零熵区域导致 chunk
#     边界检测失效，chunk 大小分布严重偏离预期。
#   Al Jarah, "Exploiting Zero-Entropy Data for Efficient Deduplication"
#: ZERO 预处理 —— 在 CDC 之前扫描并提取
#     零熵区域 → RLE 编码 → 剩余数据走标准 CDC → 空间节省上限 29%。
#   VectorCDC 方向 (SIMD 加速 hashless CDC):
#     使用向量指令加速 CDC, 吞吐量显著提升.
#     Python 中无法直接使用 SSE/AVX 指令, 在逻辑层实现等效的
#     零熵跳过 (zero-skip) 和 range scan 策略以减少无效 hash 计算.
#
# 设计思路:
#   1. detect_zero_runs: 扫描二进制数据，识别连续 >= min_run 字节的
#      相同字节值区域 (含 0x00 及 0xFF Padding 等高频填充模式)。
#   2. ZeroRegionExtractor: 将零熵区域替换为 (offset, byte_value, length)
#      元组，剩余数据走标准 CDC，空间节省来自 RLE 编码压缩。
#   3. 零熵跳过模式 (ZeroSkipCDC): 在 CDC gear hash 循环中，
#      检测到进入零熵区域时直接跳至区域末尾，削减 hash 计算量。

from typing import List, Tuple, Optional, Iterator

# 零熵区域检测

def detect_zero_runs(data: bytes, min_run: int = 64,
                      target_byte: int = None) -> List[Tuple[int, int, int]]:
    """扫描数据中连续重复字节的区间。

    返回 [(offset, byte_value, length), ...]。
    target_byte=None 时检测任意相同字节值（不限 0x00 单类模式）。

    min_run=64 来自 Al Jarah 2025 实验校准: 短于 64 字节的零熵区域
    单独 RLE 编码的元数据开销 (offset+length+value ~12-16 bytes)
    超过收益，应留给标准 CDC 自行切割。
    """
    if not data:
        return []
    runs = []
    n = len(data)
    i = 0
    while i < n:
        b = data[i]
        # 定位连续相同字节段的终点
        j = i + 1
        while j < n and data[j] == b:
            j += 1
        run_len = j - i
        if run_len >= min_run and (target_byte is None or b == target_byte):
            runs.append((i, b, run_len))
        i = j
    return runs


def zero_entropy_ratio(data: bytes, min_run: int = 64) -> float:
    """零熵区域占比 —— 快速判定 ZERO 预处理是否值得投入计算资源。

    若 ratio < 0.05 (不足 5%)，零熵优化的开销可能超过收益。
    参考 Al Jarah 2025: VM image 和 scientific data 中 ratio
    可达 15-40%，此时 ZERO 预处理显著提升去重效果。
    """
    runs = detect_zero_runs(data, min_run)
    total_ze = sum(r[2] for r in runs)
    return total_ze / max(len(data), 1)


# ZeroRegionExtractor — 零熵提取 + RLE 编码

class ZeroRegionExtractor:
    """从二进制数据中剥离零熵区域并做 RLE 编码压缩。

    输出: (non_zero_data, rle_records)
      non_zero_data: 剔除零熵区域后的剩余数据 (拼接)
      rle_records: [(original_offset, byte_value, length), ...]
    """

    def __init__(self, min_run: int = 64):
        self.min_run = min_run

    def extract(self, data: bytes) -> Tuple[bytes, List[Tuple[int, int, int]]]:
        """从 data 中移除零熵区域。"""
        runs = detect_zero_runs(data, self.min_run)
        if not runs:
            return data, []

        non_zero_parts = []
        rle_records = []
        prev_end = 0
        for offset, byte_val, length in runs:
            if offset > prev_end:
                non_zero_parts.append(data[prev_end:offset])
            rle_records.append((offset, byte_val, length))
            prev_end = offset + length
        if prev_end < len(data):
            non_zero_parts.append(data[prev_end:])
        return b"".join(non_zero_parts), rle_records

    def reconstruct(self, non_zero_data: bytes,
                    rle_records: List[Tuple[int, int, int]],
                    original_size: int) -> bytes:
        """基于 non_zero_data + RLE records 还原完整原始数据。"""
        result = bytearray(original_size)
        nz_pos = 0
        prev_end = 0
        for offset, byte_val, length in rle_records:
            # 回填 offset 前的非零数据段
            gap = offset - prev_end
            if gap > 0:
                result[prev_end:offset] = non_zero_data[nz_pos:nz_pos + gap]
                nz_pos += gap
            # 填充 RLE 区域
            result[offset:offset + length] = bytes([byte_val] * length)
            prev_end = offset + length
        # 尾部剩余非零数据
        if prev_end < original_size:
            result[prev_end:] = non_zero_data[nz_pos:]
        return bytes(result)

    def savings(self, data: bytes) -> dict:
        """评估零熵提取的空间节省指标。"""
        nz_data, rle = self.extract(data)
        rle_size = len(rle) * 14  # 每条 RLE 记录 ~14 bytes (3 varints)
        return {
            "original_size": len(data),
            "non_zero_size": len(nz_data),
            "zero_regions": len(rle),
            "rle_overhead": rle_size,
            "total_encoded": len(nz_data) + rle_size,
            "savings_ratio": round(
                1 - (len(nz_data) + rle_size) / max(len(data), 1), 4),
            "zero_ratio": round(
                (len(data) - len(nz_data)) / max(len(data), 1), 4),
        }


# ZeroSkipCDC — 零熵跳过模式的 CDC
# 在标准 gear hash CDC 基础上，检测到零熵区域时直接跳过，
# 将整段零熵区域作为一个 chunk 或在区域边界强制切分。

def zero_skip_cdc(data: bytes, min_chunk: int = 1024, max_chunk: int = 16384,
                  mask_bits: int = 12, zero_min_run: int = 64) -> List[bytes]:
    """带零熵跳过的 CDC 分块器。

    与标准 cdc_chunk (dedup.py) 的差异:
    在 gear hash 循环中检测零熵区域的起始边界，
    进入后直接跳至区域末尾以节省 hash 计算。
    适合 VM image、core dump、firmware blob 等大段填充场景。
    参考 SIMD-CDC 的 range-scan 优化策略思想.
    """
    if len(data) <= min_chunk:
        return [data]

    from .dedup import _gear_table
    gear_table = _gear_table()

    mask = (1 << mask_bits) - 1
    gear = 0
    chunks = []
    start = 0
    i = 0

    # 提前索引进阶零熵区域
    ze_runs = detect_zero_runs(data, zero_min_run)
    ze_idx = 0
    in_ze = False
    ze_end = 0

    while i < len(data):
        # 判断当前偏移是否进入/离开零熵区域
        if ze_idx < len(ze_runs) and i >= ze_runs[ze_idx][0] and i < ze_runs[ze_idx][0] + ze_runs[ze_idx][2]:
            if not in_ze:
                # 进入零熵区域: 之前的部分若 >= min_chunk 则切分
                if i - start >= min_chunk:
                    chunks.append(data[start:i])
                    start = i
                    gear = 0
                in_ze = True
                ze_end = ze_runs[ze_idx][0] + ze_runs[ze_idx][2]
        elif in_ze and i >= ze_end:
            in_ze = False
            ze_idx += 1
            # 零熵区域作为独立 chunk 整体产出
            if i - start >= min_chunk:
                chunks.append(data[start:ze_end])
                start = ze_end
                i = ze_end
                gear = 0
                continue

        if in_ze:
            # 零熵区域内部: 不计算 gear hash，逐字节推进
            i += 1
            if i - start >= max_chunk:
                chunks.append(data[start:i])
                start = i
                gear = 0
                in_ze = False
                ze_idx += 1
            continue

        # 标准 gear hash 路径
        b = data[i]
        gear = ((gear << 1) + gear_table[(gear >> 24) ^ b]) & 0xFFFFFFFF
        chunk_len = i - start

        if chunk_len >= max_chunk:
            chunks.append(data[start:i])
            start = i
            gear = 0
        elif chunk_len >= min_chunk and (gear & mask) == 0:
            chunks.append(data[start:i])
            start = i
            gear = 0
        i += 1

    if start < len(data):
        chunks.append(data[start:])
    return chunks


def zero_skip_stats(data: bytes, zero_min_run: int = 64) -> dict:
    """零熵跳过 CDC 效果评估指标集。"""
    standard = len(_standard_cdc_wrapper(data))
    optimized = len(zero_skip_cdc(data, zero_min_run=zero_min_run))
    ze_runs = detect_zero_runs(data, zero_min_run)
    return {
        "size": len(data),
        "zero_regions": len(ze_runs),
        "zero_bytes": sum(r[2] for r in ze_runs),
        "standard_chunks": standard,
        "zero_skip_chunks": optimized,
        "chunk_reduction": standard - optimized,
    }


def _standard_cdc_wrapper(data: bytes) -> List[bytes]:
    from .dedup import cdc_chunk
    return cdc_chunk(data)


# 导出别名 —— 简化外部 import 路径
_zero_skip_chunk = zero_skip_cdc
