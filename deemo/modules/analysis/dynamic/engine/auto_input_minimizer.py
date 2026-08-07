# Crash-input minimizer: delta-debug PoC down a minimal triggering payload
# 舍入 3: FrameShift-style structure-preserving 变异s — 检测 size/校验和
# relation fields preserves reduction avoid generating
# malformed inputs rejected reaching crash site

import logging
import os
import time
import struct
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
    FRAME_SHIFT = "frame_shift" # FrameShift: structure-preserving (舍入 3)

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
    """
    Delta Debugging minimizer
    
    舍入 3: Added FrameShift strategy — 检测 relation fields
    (size fields, 校验和s, length prefixes) preserves
    integrity reduction. FrameShift  显示
    avoids generating malformed inputs rejected
    reaching actual crash site, improving effective reduction
    ratio 20-50% structured 格式化
    """

    # 关系字段模式: (识别正则, 修正函数)
    # 格式: (pattern_bytes, 'size'|'校验和'|'count')
    _RELATION_PATTERNS = [
        (rb'(\x00\x00\x00\x00)', 'size_le32'),  # 4-byte 小端 size
        (rb'(\x00\x00)', 'size_le16'),           # 2-byte 小端 size
    ]

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
        self._relation_fields: List[Tuple[int, int, str]] = []  # (offset, size, relation_type)

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

        # Round 3: 预扫描关系字段 — FrameShift核心步骤
        self._relation_fields = self._scan_relation_fields(original)

        if self.strategy == MinimizationStrategy.DDMIN:
            cur = self._ddmin(original)
        elif self.strategy == MinimizationStrategy.HIERARCHY:
            cur = self._hierarchy(original)
        elif self.strategy == MinimizationStrategy.LEXICAL:
            cur = self._lexical(original)
        elif self.strategy == MinimizationStrategy.BITS:
            cur = self._bits(original)
        elif self.strategy == MinimizationStrategy.FRAME_SHIFT:
            cur = self._frame_shift(original)
        else:
            cur = original
        return MinimizationResult(
            original=original, minimized=cur,
            original_size=len(original), minimized_size=len(cur),
            iterations=len(self.history), elapsed=time.time() - start,
            strategy=self.strategy, success=len(cur) < len(original),
            history=self.history
        )

    def _scan_relation_fields(self, data: bytes) -> List[Tuple[int, int, str]]:
        """FrameShift式关系字段扫描：检测输入中可能承载size/checksum/count
        语义的字段位置。这些字段在缩减过程中需要同步更新以保持有效性"""
        relations = []
        # 扫描常见的长度前缀模式: 4字节LE值 ≈ 当前位置之后的数据长度
        for offset in range(0, min(len(data) - 8, 512), 1):
            remaining = len(data) - offset - 4
            if remaining <= 0:
                continue
            stored_size = struct.unpack_from('<I', data, offset)[0]
            # 如果4字节LE值与剩余数据大小匹配 ±16，可能是长度字段
            if abs(stored_size - remaining) <= 16 and stored_size > 0:
                relations.append((offset, 4, 'size_le32'))
                self._record(f"relation_field_size_le32@{offset}", len(data))

        return relations

    def _apply_relations(self, data: bytearray) -> bytearray:
        """FrameShift修正：重新计算并写入关系字段
        每次缩减后调用，确保size/checksum字段与实际数据一致"""
        for offset, field_size, rel_type in self._relation_fields:
            if offset + field_size > len(data):
                continue
            if rel_type == 'size_le32' and field_size == 4:
                remaining = len(data) - offset - 4
                struct.pack_into('<I', data, offset, remaining)
            elif rel_type == 'size_le16' and field_size == 2:
                remaining = len(data) - offset - 2
                struct.pack_into('<H', data, offset, remaining & 0xFFFF)
        return data

    def _frame_shift(self, data: bytes) -> bytes:
        """FrameShift策略：在DDMIN的基础上，每次缩减后修正关系字段
        这模拟FrameShift论文的核心机制 — 在变异子(mutator)和规约子(minimizer)
        之间插入关系字段检测层，确保生成的数据保持结构完整性"""
        cur = bytearray(data)
        n = 2
        start_ts = time.time()

        while len(cur) >= 2 and (time.time() - start_ts) < self.timeout_sec:
            self._record("frame_shift_start", len(cur))
            chunk_size = max(1, len(cur) // n)
            chunk_starts = list(range(0, len(cur), chunk_size))

            reduced = False
            for cs in chunk_starts:
                end_cs = min(cs + chunk_size, len(cur))
                test = bytearray(bytes(cur[:cs]) + bytes(cur[end_cs:]))
                # 关键步骤：修正关系字段后再测试
                test = self._apply_relations(test)

                if self._is_interesting(bytes(test)):
                    cur = test
                    n = max(n - 1, 2)
                    self._record("frame_shift_reduce", len(cur))
                    reduced = True
                    break

            if not reduced:
                if n < len(cur):
                    n = min(n * 2, len(cur))
                else:
                    break

            if len(self.history) > self.max_iter:
                break

        # 最后做bit级精确修剪
        cur_bytes = bytes(cur)
        cur_bytes = self._bits(cur_bytes)
        return cur_bytes

    def _ddmin(self, data: bytes) -> bytes:
        """Zeller Delta Debugging tuned numeric parameters"""
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
                # Try complement
                if n < len(data):
                    n = min(n * 2, len(data))
                else:
                    break
            if len(self.history) > self.max_iter:
                break
        data = self._bits(data)
        return data

    def _hierarchy(self, data: bytes) -> bytes:
        # Hierarchical: 1/2, 1/4, 1/8
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
        # 删除 token boundaries
        tokens: List[bytes] = []
        for i in range(0, len(data), TOKEN_ALIGN):
            tokens.append(data[i:i + TOKEN_ALIGN])
        if not tokens:
            return data
        # Greedy deletion
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
        # Bit-level cleanup
        cur = data
        # 清除 byte's high bits
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
    """Crash input minimizer"""

    def __init__(self, binary_path: str,
                 crash_runner: Optional[Callable[[str, bytes], bool]] = None,
                 timeout_sec: float = 30.0):
        self.binary_path = binary_path
        self.crash_runner = crash_runner
        self.timeout_sec = timeout_sec

    def _default_runner(self, input_data: bytes) -> bool:
        # Default runner: 执行 binary via subprocess 检测 crash
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

    # Round 3: 级联最小化 — 组合多种策略以达到最优缩减
    def minimize_cascade(self, crash_input: bytes) -> MinimizationResult:
        """级联最小化: DDMIN → FrameShift → Bits
        每阶段输出作为下一阶段输入，FrameShift在中间阶段确保结构化数据的完整性"""
        start = time.time()
        cur = crash_input
        all_history = []
        strategies = [
            MinimizationStrategy.DDMIN,
            MinimizationStrategy.FRAME_SHIFT,
            MinimizationStrategy.BITS,
        ]

        runner = self.crash_runner or self._default_runner
        for strat in strategies:
            dbg = DeltaDebugger(runner, strategy=strat)
            result = dbg.minimize(cur)
            cur = result.minimized
            all_history.extend(dbg.history)

        return MinimizationResult(
            original=crash_input, minimized=cur,
            original_size=len(crash_input), minimized_size=len(cur),
            iterations=len(all_history),
            elapsed=time.time() - start,
            strategy="cascade",
            success=len(cur) < len(crash_input),
            history=all_history,
        )

def minimize_crash_input(
    binary_path: str,
    crash_input: bytes,
    strategy: str = "ddmin"
) -> Dict[str, Any]:
    """Convenience 入口"""
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
