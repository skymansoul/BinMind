"""
CSEF 流式计算与区域扫描
------------------------
大文件分块流式处理和滑动窗口区域扫描。
与 cross_scale_entropy.py 分离——核心模块保持零类实例化开销。
"""
from typing import List
from modules.utils.cross_scale_entropy import (
    CrossScaleProfile,
    compute_csef,
    _SCALES,
    _shannon_entropy_from_counts,
    _spearman_r,
)


class StreamingCSEF:
    """流式跨尺度熵指纹计算器。
    适用场景:
      数百 MB 以上的二进制文件，无法一次性加载到内存。
      每次 update() 处理一个 chunk (建议 ≥ 4 KiB 以摊销 Python 循环开销)。
    """

    def __init__(self):
        self._num_levels = len(_SCALES)
        self._hist: List[List[int]] = [[0] * 256 for _ in range(self._num_levels)]
        self._accum: List[int] = [0] * self._num_levels
        self._entropy_seq: List[List[float]] = [[] for _ in range(self._num_levels)]
        self._total_bytes = 0

    def update(self, data: bytes):
        """馈入下一块数据。无返回值——结果在 finalize() 中统一产出。"""
        for byte in data:
            self._total_bytes += 1
            self._hist[0][byte] += 1
            self._accum[0] += 1
            if self._accum[0] == _SCALES[0]:
                h0 = _shannon_entropy_from_counts(self._hist[0], _SCALES[0])
                self._entropy_seq[0].append(h0)
                for b_idx in range(256):
                    self._hist[1][b_idx] += self._hist[0][b_idx]
                self._accum[1] += _SCALES[0]
                self._hist[0] = [0] * 256
                self._accum[0] = 0
                for level in range(1, self._num_levels):
                    if self._accum[level] >= _SCALES[level]:
                        h_lev = _shannon_entropy_from_counts(
                            self._hist[level], _SCALES[level]
                        )
                        self._entropy_seq[level].append(h_lev)
                        if level + 1 < self._num_levels:
                            for b_idx in range(256):
                                self._hist[level + 1][b_idx] += self._hist[level][
                                    b_idx
                                ]
                            self._accum[level + 1] += _SCALES[level]
                        self._hist[level] = [0] * 256
                        self._accum[level] = 0

    def finalize(self) -> CrossScaleProfile:
        """完成计算，返回指纹。
        流式模式下 Tsallis q 固定为 1.0——
        因为 q 选择需回溯完整数据测试各候选值，而流式模式不保留原始数据。
        """
        for level in range(self._num_levels):
            if self._accum[level] > 0:
                h = _shannon_entropy_from_counts(
                    self._hist[level], self._accum[level]
                )
                self._entropy_seq[level].append(h)

        mean_entropies = tuple(
            sum(seq) / len(seq) if seq else 0.0 for seq in self._entropy_seq
        )

        couplings: List[float] = []
        for lev in range(self._num_levels - 1):
            fine = self._entropy_seq[lev]
            coarse = self._entropy_seq[lev + 1]
            ratio = _SCALES[lev + 1] // _SCALES[lev]
            aligned: List[float] = []
            for i in range(0, len(fine) - ratio + 1, ratio):
                aligned.append(sum(fine[i : i + ratio]) / ratio)
            min_len = min(len(aligned), len(coarse))
            if min_len >= 3:
                couplings.append(_spearman_r(aligned[:min_len], coarse[:min_len]))
            else:
                couplings.append(0.0)

        return CrossScaleProfile(
            entropy_scales=mean_entropies,
            couplings=(
                couplings[0] if len(couplings) > 0 else 0.0,
                couplings[1] if len(couplings) > 1 else 0.0,
                couplings[2] if len(couplings) > 2 else 0.0,
            ),
            tsallis_q=1.0,
        )

    @property
    def total_bytes_processed(self) -> int:
        return self._total_bytes


def csef_region_scan(
    data: bytes, window: int = 4096, stride: int = 2048
) -> List[CrossScaleProfile]:
    """对长数据执行滑动窗口 CSEF 扫描。
    返回每个窗口位置的指纹列表。
    stride < window 时相邻窗口重叠——用于检测熵分布突变边界
    (如 PE 文件中节与节之间的过渡带)。
    """
    profiles = []
    for start in range(0, len(data) - window + 1, stride):
        chunk = data[start : start + window]
        profiles.append(compute_csef(chunk))
    return profiles


def csef_region_labels(
    profiles: List[CrossScaleProfile],
) -> List[str]:
    """根据 CSEF 指纹序列标注每个区域类型。
    返回 ["code" | "data" | "compressed" | "encrypted" | "mixed"] 列表。

    分类决策树 (基于 4 类二进制样本的网格搜索优化阈值):
      1. 总熵 > 7.5 → encrypted (接近均匀分布)
      2. 总熵 > 6.0 + ρ_01 > 0.5 → compressed (尺度同步，高熵)
      3. 总熵 > 6.0 + ρ_01 ≤ 0.5 → mixed
      4. 总熵 > 4.0 + ρ_01 < 0 → code (细尺度波动大于粗尺度)
      5. 总熵 > 4.0 + ρ_01 ≥ 0 → data
      6. 总熵 ≤ 4.0 → data (低熵，结构化文本/表格)
    """
    labels = []
    for p in profiles:
        mean_ent = sum(p.entropy_scales) / 4.0
        rho_01 = p.couplings[0]
        if mean_ent > 7.5:
            labels.append("encrypted")
        elif mean_ent > 6.0:
            if rho_01 > 0.5:
                labels.append("compressed")
            else:
                labels.append("mixed")
        elif mean_ent > 4.0:
            if rho_01 < 0:
                labels.append("code")
            else:
                labels.append("data")
        else:
            labels.append("data")
    return labels
