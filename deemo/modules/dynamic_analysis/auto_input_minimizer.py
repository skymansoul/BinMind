# Crash-input 最小化器，delta-debug 将 PoC 缩减至最小触发载荷
import logging
import os
import time
import hashlib
from typing import Dict, Any, List, Optional, Callable
from dataclasses import dataclass, field, asdict
from enum import StrEnum
from collections import defaultdict

logger = logging.getLogger(__name__)

DEFAULT_MAX_ITER = 100
DEFAULT_TIMEOUT_SEC = 300.0
TOKEN_ALIGN = 4
BIT_COUNT = 8


class MinimizationStrategy(StrEnum):
    DDMIN = "ddmin"             # Classic Delta Debugging
    HIERARCHY = "hierarchy"     # Hierarchical
    LEXICAL = "lexical"         # Lexical (token boundary based)
    BITS = "bits"               # Bit-level


@dataclass
class MinimizationResult:
    original: bytes
    minimized: bytes
    original_size: int
    minimized_size: int
    iterations: int
    elapsed: float
    strategy: str
    success: bool
    history: list = field(default_factory=list)


class DeltaDebugger:
    # Delta Debugging 最小化器

    def __init__(self,
                 oracle: Callable[[bytes], bool],
                 strategy: MinimizationStrategy = MinimizationStrategy.DDMIN,
                 max_iter: int = DEFAULT_MAX_ITER,
                 timeout_sec: float = DEFAULT_TIMEOUT_SEC):
        self.oracle = oracle
        self.strategy = strategy
        self.max_iter = max_iter
        self.timeout_sec = timeout_sec
        self.history: List[Dict[str, Any]] = []

    def _is_interesting(self, data: bytes) -> bool:
        try:
            return bool(self.oracle(data))
        except Exception as e:
            logger.debug(f"Oracle exception: {e}")
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
        # Zeller Delta Debugging，调优数值参数
        n = 2
        start_ts = time.time()
        while len(data) >= 2 and (time.time() - start_ts) < self.timeout_sec:
            self._record("start", len(data))
            chunk_size = max(1, len(data) // n)
            chunk_starts = list(range(0, len(data), chunk_size))
            for cs in chunk_starts:
                test = data[:cs] + data[cs + chunk_size:]
                if self._is_interesting(test):
                    data = test
                    n = max(n - 1, 2)
                    self._record("reduce_chunk", len(data))
                    break
            else:
                # Try complement.
                if n < len(data):
                    n = min(n * 2, len(data))
                else:
                    break
            if len(self.history) > self.max_iter:
                break
        data = self._bits(data)
        return data

    def _hierarchy(self, data: bytes) -> bytes:
        # Hierarchical: 1/2, then 1/4, then 1/8 ...
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
        # Delete by token boundaries.
        tokens: List[bytes] = []
        for i in range(0, len(data), TOKEN_ALIGN):
            tokens.append(data[i:i + TOKEN_ALIGN])
        if not tokens:
            return data
        # Greedy deletion.
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
        # Bit-level cleanup.
        cur = data
        # Clear each byte's high bits.
        for i in range(len(cur)):
            for bit in range(BIT_COUNT):
                test = bytearray(cur)
                test[i] &= ~(1 << bit)
                if self._is_interesting(bytes(test)):
                    cur = bytes(test)
            if len(self.history) > self.max_iter * 2:
                break
        return cur

    def _record(self, op: str, size: int):
        self.history.append({'op': op, 'size': size, 'ts': time.time()})


class CrashInputMinimizer:
    # Crash 输入最小化器

    def __init__(self, binary_path: str,
                 crash_runner: Optional[Callable[[str, bytes], bool]] = None,
                 timeout_sec: float = 30.0):
        self.binary_path = binary_path
        self.crash_runner = crash_runner
        self.timeout_sec = timeout_sec

    def _default_runner(self, input_data: bytes) -> bool:
        # 默认执行器，通过 subprocess 运行目标程序并检测崩溃
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
            return r.returncode in (-11, 139, 134, -6, -8) or r.returncode > 128
        except subprocess.TimeoutExpired:
            return False
        except Exception as e:
            logger.debug(f"Crash runner exception: {e}")
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
    # 便捷入口
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
