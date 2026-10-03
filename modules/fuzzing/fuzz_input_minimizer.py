"""覆盖率保持的输入最小化器 — afl-tmin 算法 Python 实现及扩展策略。

支持逐字节贪心、二分压缩、按行/按 token 删除四种最小化模式。
最小化约束：结果输入必须仍触发原始种子覆盖的所有边（final_coverage ⊇ original_coverage）。
二分模式 O(log n) 次执行，适用于大文件快速收缩。
"""

import hashlib
import logging
import math
import os
import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


class MinimizeStrategy(str, Enum):
    BYTE_WISE = "byte_wise"          # 逐字节删除，最精细策略
    CHUNK_BINARY = "chunk_binary"    # 二分区间删除，O(log n) 次执行
    LINE_WISE = "line_wise"          # 按换行符分割删除，面向文本输入
    TOKEN_WISE = "token_wise"        # 按空白分隔 token 删除


@dataclass
class MinimizeResult:
    original_size: int
    minimized_size: int
    original_coverage: Set[int]
    final_coverage: Set[int]
    iterations: int
    elapsed: float
    strategy: str
    removed_bytes: int = 0
    minimized_data: bytes = b""
    # 各阶段尺寸变化记录，用于绘制收缩曲线
    size_history: List[Tuple[int, int]] = field(default_factory=list)


# 执行器签名: 输入 bytes -> 返回覆盖边 ID 集合
ExecutorFunc = Callable[[bytes], Set[int]]


class InputMinimizer:
    """覆盖率保持的输入最小化引擎。

    核心约束: 最小化后的输入必须仍触发原始种子覆盖的所有边。
    逐字节模式基于 afl-tmin 的贪心删除：每个位置尝试删除 1 字节，
    覆盖不变则保留，否则跳过。二分模式作为大文件加速替代。
    """

    def __init__(self, executor: ExecutorFunc,
                 max_iterations: int = 5000,
                 timeout_seconds: float = 300.0):
        """
        executor: 接受 bytes 返回覆盖边集合的可调用对象。
        max_iterations: 逐字节模式的最大迭代步数上限。
        timeout_seconds: 整个最小化过程的全局时间限制。
        """
        self.executor = executor
        self.max_iter = max_iterations
        self.timeout = timeout_seconds

    def minimize(self, seed: bytes,
                 strategy: MinimizeStrategy = MinimizeStrategy.CHUNK_BINARY,
                 ) -> MinimizeResult:
        t0 = time.time()
        orig_size = len(seed)

        # 测量原始种子的基线覆盖
        orig_cov = self.executor(seed)
        if not orig_cov:
            # 执行器返回空覆盖：种子无效或执行器异常
            return MinimizeResult(
                original_size=orig_size, minimized_size=orig_size,
                original_coverage=set(), final_coverage=set(),
                iterations=0, elapsed=time.time() - t0,
                strategy=strategy.value, minimized_data=seed,
            )

        size_hist: List[Tuple[int, int]] = []

        if strategy == MinimizeStrategy.BYTE_WISE:
            result_data = self._minimize_bytewise(seed, orig_cov, size_hist, t0)
        elif strategy == MinimizeStrategy.CHUNK_BINARY:
            result_data = self._minimize_binary(seed, orig_cov, size_hist, t0)
        elif strategy == MinimizeStrategy.LINE_WISE:
            result_data = self._minimize_linewise(seed, orig_cov, size_hist, t0)
        elif strategy == MinimizeStrategy.TOKEN_WISE:
            result_data = self._minimize_tokenwise(seed, orig_cov, size_hist, t0)
        else:
            result_data = seed

        final_cov = self.executor(result_data)
        elapsed = time.time() - t0

        return MinimizeResult(
            original_size=orig_size,
            minimized_size=len(result_data),
            original_coverage=orig_cov,
            final_coverage=final_cov,
            iterations=len(size_hist),
            elapsed=elapsed,
            strategy=strategy.value,
            removed_bytes=orig_size - len(result_data),
            minimized_data=result_data,
            size_history=size_hist,
        )

    # 逐字节贪心删除

    def _minimize_bytewise(self, data: bytes, ref_cov: Set[int],
                           hist: List[Tuple[int, int]],
                           start_time: float) -> bytes:
        """O(n) 线性扫描，每位置尝试删除 1 字节，保留覆盖不变的删除。

        这是最慢但最彻底的策略，适合最终发布前的精细化最小化。
        """
        raw = bytearray(data)
        i = 0
        iterations = 0
        while i < len(raw) and iterations < self.max_iter:
            if time.time() - start_time > self.timeout:
                logger.info("最小化超时, 在位置 %d 停止", i)
                break
            iterations += 1

            # 尝试删去位置 i 的单字节
            candidate = bytes(raw[:i] + raw[i + 1:])
            try:
                cov = self.executor(candidate)
            except Exception:
                cov = set()

            if ref_cov.issubset(cov):
                # 覆盖不变则永久删除
                del raw[i]
                hist.append((iterations, len(raw)))
            else:
                i += 1  # 覆盖丢失则保留此字节

        return bytes(raw)

    # 二分区间压缩

    def _minimize_binary(self, data: bytes, ref_cov: Set[int],
                         hist: List[Tuple[int, int]],
                         start_time: float) -> bytes:
        """递归二分删除，类似 git bisect 的区间探测。

        对巨型种子（>10MB），逐字节不可行，二分在 O(log n) 次执行中逼近最优。
        """
        raw = bytearray(data)
        iterations = 0

        def _bisect(lo: int, hi: int) -> None:
            nonlocal iterations
            if hi - lo <= 1 or iterations >= self.max_iter:
                return
            if time.time() - start_time > self.timeout:
                return

            mid = (lo + hi) // 2
            iterations += 1

            # 尝试删除 [lo, mid) 区间
            candidate = bytes(raw[:lo] + raw[mid:])
            try:
                cov = self.executor(candidate)
            except Exception:
                cov = set()

            if ref_cov.issubset(cov):
                # 区间可删除，递归处理右侧（被删除区间后移）
                del raw[lo:mid]
                hist.append((iterations, len(raw)))
                _bisect(lo, lo + (hi - mid))
            else:
                # 不可删除，递归更细粒度区间
                _bisect(lo, mid)
                _bisect(mid, hi)

        _bisect(0, len(raw))
        return bytes(raw)

    # 按行最小化（文本输入）

    def _minimize_linewise(self, data: bytes, ref_cov: Set[int],
                           hist: List[Tuple[int, int]],
                           start_time: float) -> bytes:
        """将输入视为 UTF-8 文本，逐行尝试删除。

        适用于 JSON/XML/HTTP 请求等换行符分隔的结构化文本输入。
        """
        try:
            text = data.decode('utf-8', errors='replace')
        except Exception:
            return data

        lines = text.split('\n')
        iterations = 0
        i = 0
        while i < len(lines) and iterations < self.max_iter:
            if time.time() - start_time > self.timeout:
                break
            iterations += 1
            # 尝试删除第 i 行
            new_lines = lines[:i] + lines[i + 1:]
            candidate = '\n'.join(new_lines).encode('utf-8')
            try:
                cov = self.executor(candidate)
            except Exception:
                cov = set()
            if ref_cov.issubset(cov):
                del lines[i]
                hist.append((iterations, sum(len(l) + 1 for l in lines)))
            else:
                i += 1

        return '\n'.join(lines).encode('utf-8')

    # 按 token 最小化

    def _minimize_tokenwise(self, data: bytes, ref_cov: Set[int],
                            hist: List[Tuple[int, int]],
                            start_time: float) -> bytes:
        """按空白分隔的 token 逐项删除。

        适用于命令行参数、自然语言等空白分隔的输入格式。
        """
        try:
            text = data.decode('utf-8', errors='replace')
        except Exception:
            return data

        tokens = text.split()
        iterations = 0
        i = 0
        while i < len(tokens) and iterations < self.max_iter:
            if time.time() - start_time > self.timeout:
                break
            iterations += 1
            new_tokens = tokens[:i] + tokens[i + 1:]
            candidate = ' '.join(new_tokens).encode('utf-8')
            try:
                cov = self.executor(candidate)
            except Exception:
                cov = set()
            if ref_cov.issubset(cov):
                del tokens[i]
                hist.append((iterations, sum(len(t) + 1 for t in tokens)))
            else:
                i += 1

        return ' '.join(tokens).encode('utf-8')


# 覆盖保持验证

def verify_coverage_preserved(
    original: bytes, minimized: bytes,
    executor: ExecutorFunc,
) -> Tuple[bool, float]:
    """验证最小化结果是否保留了原始种子的全部覆盖边。

    返回 (是否完全保留, 覆盖率交集占比)。
    """
    orig_cov = executor(original)
    min_cov = executor(minimized)

    if not orig_cov:
        return len(min_cov) == 0, 1.0

    preserved = orig_cov.intersection(min_cov)
    ratio = len(preserved) / len(orig_cov)
    return ratio >= 1.0, ratio


# 语料批量最小化

def minimize_corpus(
    seed_dir: str,
    output_dir: str,
    executor: ExecutorFunc,
    strategy: MinimizeStrategy = MinimizeStrategy.CHUNK_BINARY,
) -> Dict:
    """对语料目录中所有种子文件独立执行最小化，返回聚合统计。

    每个种子独立处理，输出写入 output_dir。
    """
    import os
    os.makedirs(output_dir, exist_ok=True)

    minimizer = InputMinimizer(executor)
    total_saved = 0
    total_seeds = 0

    for fname in os.listdir(seed_dir):
        fpath = os.path.join(seed_dir, fname)
        if not os.path.isfile(fpath):
            continue
        try:
            with open(fpath, 'rb') as f:
                data = f.read()
        except OSError:
            continue

        result = minimizer.minimize(data, strategy)
        saved = result.original_size - result.minimized_size
        total_saved += saved
        total_seeds += 1

        out_path = os.path.join(output_dir, fname)
        with open(out_path, 'wb') as f:
            f.write(result.minimized_data)

    return {
        "seeds_processed": total_seeds,
        "total_bytes_saved": total_saved,
        "strategy": strategy.value,
    }
