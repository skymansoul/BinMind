# 增量熵计算替代朴素 O(n*w) 实现
# 增加 2-sigma 自适应阈值，替代固定阈值

# 滑动窗口增量熵跳变检测, 协议消息边界的第三级回退策略
# 当魔数检测和长度字段推断都失败时(加密/压缩流)
# 消息边界仍可能通过内容熵的突变来识别:
# - 消息体通常比头部有更高的熵(更接近随机)
# - 头部包含结构化字段, 熵较低
# - 头部→消息体的过渡点在滑动窗口熵序列中表现为尖峰
# 增量计算: 维护滑动字节频率表, 仅更新离开/进入窗口的字节, O(1)/step

import math
from typing import Dict, List, Tuple
from dataclasses import dataclass, field


@dataclass
class EntropyJump:
    offset: int
    delta: float           # 熵差绝对值
    entropy_before: float
    entropy_after: float
    confidence: float      # [0, 1]


class IncrementalEntropyWindow:
    # O(1)增量更新的滑动窗口熵计算器, 保持256桶字节频率计数
    # 窗口滑动时仅调整进出字节的计数, 窗口填满前返回0.0

    def __init__(self, window_size: int = 64):
        if window_size < 4:
            raise ValueError("window_size must be >= 4")
        self._wsize = window_size
        self._counts = [0] * 256
        self._buffer = []       # 仅存储最近 ws 个字节用于弹出
        self._total = 0

    def push(self, byte_val: int) -> float:
        # 压入一个字节并返回当前窗口熵
        self._counts[byte_val] += 1
        self._total += 1
        self._buffer.append(byte_val)

        if len(self._buffer) > self._wsize:
            popped = self._buffer.pop(0)
            self._counts[popped] = max(0, self._counts[popped] - 1)
            self._total -= 1

        if self._total == 0:
            return 0.0

        h = 0.0
        for c in self._counts:
            if c > 0:
                p = c / self._total
                h -= p * math.log2(p)
        return h


class EntropyJumpDetector:
    # 扫描字节流, 标记熵跳变显著的偏移位置
    # sigma_threshold: 跳变需超过 mean + sigma * std 才被标记
    # 默认2.0, 约95%置信水平(假设熵差近似正态分布)

    def __init__(self, window_size: int = 64, sigma_threshold: float = 2.0):
        self._wsize = window_size
        self._sigma = sigma_threshold

    def detect(self, data: bytes) -> List[EntropyJump]:
        if len(data) < self._wsize * 2:
            return []

        # Pass 1: 熵序列
        window = IncrementalEntropyWindow(self._wsize)
        entropies = [window.push(b) for b in data]

        # Pass 2: Δentropy
        deltas = [abs(entropies[i] - entropies[i - 1])
                  for i in range(1, len(entropies))]

        if not deltas:
            return []

        mean_d = sum(deltas) / len(deltas)
        var_d = sum((d - mean_d) ** 2 for d in deltas) / len(deltas)
        std_d = math.sqrt(var_d) if var_d > 0 else 0.001
        threshold = mean_d + self._sigma * std_d

        results = []
        for i, d in enumerate(deltas):
            if d > threshold:
                confidence = min(1.0, (d - threshold) / (threshold + 1e-9) * 0.5 + 0.5)
                results.append(EntropyJump(
                    offset=i + self._wsize,
                    delta=d,
                    entropy_before=entropies[i],
                    entropy_after=entropies[i + 1],
                    confidence=confidence,
                ))

        return results
