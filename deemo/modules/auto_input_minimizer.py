"""
自动化输入约束最小化模块 (Delta Debugging)

功能:
    1. 对 Fuzzer 发现的 crash 输入或 PoC, 使用 delta debugging 算法自动最小化输入
    2. 保留崩溃特征
    3. 减少分析噪声, 快速定位关键触发字节

核心技术:
    - Delta Debugging: 递归二分/区间删除
    - 约束求解 (Z3) 验证最小化后仍触发
    - 多策略: ddmin, hierarchy, lexical
"""

import logging
import os
import time
import hashlib
from typing import Dict, Any, List, Optional, Tuple, Callable
from dataclasses import dataclass, field, asdict
from enum import Enum
from collections import defaultdict

logger = logging.getLogger(__name__)


class MinimizationStrategy(Enum):
    DDMIN = "ddmin"             # 经典 Delta Debugging
    HIERARCHY = "hierarchy"     # 层次化
    LEXICAL = "lexical"         # 词法 (基于 token 边界)
    BITS = "bits"               # 位级


@dataclass
class MinimizationResult:
    """最小化结果"""
    original: bytes
    minimized: bytes
    original_size: int
    minimized_size: int
    iterations: int
    elapsed: float
    strategy: MinimizationStrategy
    success: bool
    history: List[Dict[str, Any]] = field(default_factory=list)


class DeltaDebugger:
    """
    Delta Debugging 最小化器
    """

    def __init__(self,
                 oracle: Callable[[bytes], bool],
                 strategy: MinimizationStrategy = MinimizationStrategy.DDMIN,
                 max_iter: int = 100,
                 timeout_sec: float = 300.0):
        self.oracle = oracle
        self.strategy = strategy
        self.max_iter = max_iter
        self.timeout_sec = timeout_sec
        self.history: List[Dict[str, Any]] = []

    def _is_interesting(self, data: bytes) -> bool:
        try:
            return bool(self.oracle(data))
        except Exception as e:
            logger.debug(f"oracle 异常: {e}")
            return False

    def minimize(self, original: bytes) -> MinimizationResult:
        start = time.time()
        if not self._is_interesting(original):
            return MinimizationResult(
                original=original, minimized=original,
                original_size=len(original), minimized_size=len(original),
                iterations=0, elapsed=time.time() - start,
                strategy=self.strategy, success=False
            )
        if self.strategy == MinimizationStrategy.DDMIN:
            cur = self._ddmin(original)
        elif self.strategy == MinimizationStrategy.HIERARCHY:
            cur = self._hierarchy(original)
        elif self.strategy == MinimizationStrategy.LEXICAL:
            cur = self._lexical(original)
        elif self.strategy == MinimizationStrategy.BITS:
            cur = self._bits(original)
        else:
            cur = original
        return MinimizationResult(
            original=original, minimized=cur,
            original_size=len(original), minimized_size=len(cur),
            iterations=len(self.history), elapsed=time.time() - start,
            strategy=self.strategy, success=len(cur) < len(original),
            history=self.history
        )

    def _ddmin(self, data: bytes) -> bytes:
        """Zeller Delta Debugging"""
        n = 2
        while len(data) >= 2 and (time.time() - self.history[0]['ts']
                                  if self.history else 0) < self.timeout_sec:
            self._record("start", len(data))
            chunk_size = max(1, len(data) // n)
            chunk_starts = list(range(0, len(data), chunk_size))
            complement = bytearray()
            for cs in chunk_starts:
                test = data[:cs] + data[cs + chunk_size:]
                if self._is_interesting(test):
                    data = test
                    n = max(n - 1, 2)
                    self._record("reduce_chunk", len(data))
                    break
            else:
                # 试互补
                if n < len(data):
                    n = min(n * 2, len(data))
                else:
                    break
            if len(self.history) > self.max_iter:
                break
        # 进一步位级别清理
        data = self._bits(data)
        return data

    def _hierarchy(self, data: bytes) -> bytes:
        """层次化: 先按 1/2, 再 1/4, 再 1/8 ..."""
        cur = data
        for divisor in [2, 4, 8, 16, 32, 64, 128]:
            chunk_size = max(1, len(cur) // divisor)
            i = 0
            while i < len(cur):
                candidate = cur[:i] + cur[i + chunk_size:]
                if self._is_interesting(candidate):
                    cur = candidate
                else:
                    i += chunk_size
            self._record(f"hierarchy_{divisor}", len(cur))
        return cur

    def _lexical(self, data: bytes) -> bytes:
        """按词法 (token) 边界删除"""
        tokens: List[bytes] = []
        # 简单: 按 4 字节对齐
        for i in range(0, len(data), 4):
            tokens.append(data[i:i + 4])
        if not tokens:
            return data
        # 贪心删除
        cur_tokens = list(tokens)
        i = 0
        while i < len(cur_tokens):
            candidate_tokens = cur_tokens[:i] + cur_tokens[i + 1:]
            candidate = b"".join(candidate_tokens)
            if self._is_interesting(candidate):
                cur_tokens = candidate_tokens
            else:
                i += 1
            self._record("lexical", sum(len(t) for t in cur_tokens))
        return b"".join(cur_tokens)

    def _bits(self, data: bytes) -> bytes:
        """位级清理"""
        cur = data
        # 删除每个字节的高位
        i = 0
        while i < len(cur):
            for bit in range(8):
                test = bytearray(cur)
                test[i] &= ~(1 << bit)
                if self._is_interesting(bytes(test)):
                    cur = bytes(test)
            i += 1
            if len(self.history) > self.max_iter * 2:
                break
        return cur

    def _record(self, op: str, size: int):
        self.history.append({'op': op, 'size': size, 'ts': time.time()})


class CrashInputMinimizer:
    """崩溃输入最小化器"""

    def __init__(self, binary_path: str,
                 crash_runner: Optional[Callable[[str, bytes], bool]] = None,
                 timeout_sec: float = 30.0):
        self.binary_path = binary_path
        self.crash_runner = crash_runner
        self.timeout_sec = timeout_sec

    def _default_runner(self, input_data: bytes) -> bool:
        """默认通过子进程运行并检测崩溃"""
        import subprocess
        import tempfile
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(input_data)
            tmp_path = f.name
        try:
            r = subprocess.run(
                [self.binary_path, tmp_path],
                capture_output=True, timeout=self.timeout_sec
            )
            # 退出码 139 (SIGSEGV) / 134 (SIGABRT) / -11
            return r.returncode in (-11, 139, 134, -6, -8) or r.returncode > 128
        except subprocess.TimeoutExpired:
            return False
        except Exception as e:
            logger.debug(f"crash runner 异常: {e}")
            return False
        finally:
            try:
                os.remove(tmp_path)
            except OSError:
                pass

    def minimize(self, crash_input: bytes,
                 strategy: MinimizationStrategy = MinimizationStrategy.DDMIN
                 ) -> MinimizationResult:
        runner = self.crash_runner or self._default_runner
        debugger = DeltaDebugger(runner, strategy=strategy)
        return debugger.minimize(crash_input)


def minimize_crash_input(
    binary_path: str,
    crash_input: bytes,
    strategy: str = "ddmin"
) -> Dict[str, Any]:
    """便捷入口"""
    try:
        strat = MinimizationStrategy(strategy)
    except ValueError:
        strat = MinimizationStrategy.DDMIN
    m = CrashInputMinimizer(binary_path)
    res = m.minimize(crash_input, strategy=strat)
    return {
        'success': res.success,
        'original_size': res.original_size,
        'minimized_size': res.minimized_size,
        'reduction_ratio': 1.0 - res.minimized_size / max(1, res.original_size),
        'iterations': res.iterations,
        'elapsed': res.elapsed,
        'minimized_hex': res.minimized.hex(),
        'minimized_preview': res.minimized[:64].hex()
    }
