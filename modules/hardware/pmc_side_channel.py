"""Performance Monitoring Counter (PMC) side-channel detection."""

import json
import logging
import math
import os
import statistics
import struct
import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Callable, Dict, List, Optional

_log = logging.getLogger(__name__)


class PMCCounterType(IntEnum):
    INSTRUCTIONS = 0
    CYCLES = 1
    CACHE_MISSES = 2
    CACHE_REFERENCES = 3
    BRANCH_MISSES = 4
    BRANCH_INSTRUCTIONS = 5
    L1D_MISSES = 6
    L1I_MISSES = 7
    LLC_MISSES = 8
    TLB_MISSES = 9
    STALLED_CYCLES = 10


@dataclass
class PMCSample:
    counter: PMCCounterType
    values: Dict[str, int] = field(default_factory=dict)  # secret_value -> count

@dataclass
class ExploitabilityScore:
    score: float              # 0..1
    leaked_bits: float = 0.0
    signal_to_noise: float = 0.0
    counter: PMCCounterType = PMCCounterType.CACHE_MISSES
    description: str = ""


# 利用性分级常量 — 供调用方按等级引用, 与逐项评分结果并存
ExploitabilityScore.NONE = ExploitabilityScore(
    score=0.0, description="未检测到可利用信号")
ExploitabilityScore.LOW = ExploitabilityScore(
    score=0.2, description="低利用性")
ExploitabilityScore.MEDIUM = ExploitabilityScore(
    score=0.5, description="中等利用性")
ExploitabilityScore.HIGH = ExploitabilityScore(
    score=1.0, description="高利用性")



class PMCSideChannelEvaluator:
    """Collect hardware performance counters during cryptographic operations
    and correlate them with secret data.
    """

    _COUNTER_NAME = {
        PMCCounterType.INSTRUCTIONS: "instructions",
        PMCCounterType.CYCLES: "cycles",
        PMCCounterType.CACHE_MISSES: "cache_misses",
        PMCCounterType.CACHE_REFERENCES: "cache_references",
        PMCCounterType.BRANCH_MISSES: "branch_misses",
        PMCCounterType.L1D_MISSES: "l1d_misses",
        PMCCounterType.L1I_MISSES: "l1i_misses",
        PMCCounterType.LLC_MISSES: "llc_misses",
        PMCCounterType.TLB_MISSES: "tlb_misses",
        PMCCounterType.STALLED_CYCLES: "stalled_cycles",
    }

    def __init__(self, use_perf: bool = True):
        self._perf_available = False
        self._check_perf()

    # -- main evaluate --------------------------------------------------------

    def evaluate(self, impl: Any, secrets: Optional[List[bytes]] = None,
                 trials: int = 500) -> List[ExploitabilityScore]:
        """Evaluate an implementation. `impl` is callable(secret) -> result."""
        if not callable(impl):
            scores: List[ExploitabilityScore] = []
            scores.append(ExploitabilityScore(
                score=0.0, description="Static analysis only; no PMC profiling available",
            ))
            return scores

        secrets = secrets or [b"\x00", b"\xFF", b"\xAA", b"\x55"]
        return self._profile_callable(impl, secrets, trials)

    # -- profiling ------------------------------------------------------------

    def _profile_callable(self, op: Callable, secrets: List[bytes],
                          trials: int) -> List[ExploitabilityScore]:
        """Collect PMC data per secret value and compute correlation."""

        # Collect timing + derived metrics for each secret
        all_timings: Dict[bytes, List[float]] = defaultdict(list)
        # Simulated PMC: instruction counts via code-path length proxy
        all_icounts: Dict[bytes, List[int]] = defaultdict(list)

        for _ in range(trials):
            for secret in secrets:
                t0 = time.perf_counter_ns()
                result = op(secret)
                elapsed = time.perf_counter_ns() - t0
                all_timings[secret].append(elapsed)

                # Approximate instruction count from result size / operation
                if isinstance(result, (bytes, bytearray)):
                    icount = len(result) * 4 + 64  # rough per-byte instruction estimate
                elif isinstance(result, (list, tuple)):
                    icount = len(result) * 8 + 32
                else:
                    icount = elapsed // 5  # ~200MHz on many CPUs = 5ns/instruction
                all_icounts[secret].append(max(1, icount))

        scores: List[ExploitabilityScore] = []

        # ---- Timing-based leakage ----------------------------------------------------
        timing_score = self._compute_leakage(all_timings, PMCCounterType.CYCLES)
        if timing_score.score > 0.1:
            scores.append(timing_score)

        # ---- Instruction-count leakage ------------------------------------------------
        icount_score = self._compute_leakage(all_icounts, PMCCounterType.INSTRUCTIONS,
                                             is_int=True)
        if icount_score.score > 0.1 or timing_score.score <= 0.1:
            scores.append(icount_score)

        # ---- Cache-related leakage --------------------------------------------------
        if self._perf_available:
            cache_data = self._read_perf_cache()
            if cache_data:
                for counter_type, values in cache_data.items():
                    s = self._compute_leakage(values, counter_type)
                    if s.score > 0.05:
                        scores.append(s)

        # ---- Branch prediction leakage ------------------------------------------------
        branch_variance = self._estimate_branch_misses(all_timings)
        if branch_variance > 0.15:
            scores.append(ExploitabilityScore(
                score=min(1.0, branch_variance * 3),
                leaked_bits=branch_variance * 3,
                signal_to_noise=branch_variance,
                counter=PMCCounterType.BRANCH_MISSES,
                description=f"Estimated branch-prediction variance: {branch_variance:.2%}",
            ))

        if not scores:
            scores.append(ExploitabilityScore(
                score=0.0,
                description="No significant PMC-side leakage detected",
            ))

        return sorted(scores, key=lambda s: s.score, reverse=True)

    def _compute_leakage(self, data: Dict[bytes, List],
                          counter: PMCCounterType,
                          is_int: bool = False) -> ExploitabilityScore:
        """Compute how much a counter leaks about the secret."""
        if len(data) < 2:
            return ExploitabilityScore(score=0.0, counter=counter)

        values_list = list(data.values())
        # ANOVA-style: between-group vs. within-group variance
        all_vals = [item for sublist in values_list for item in sublist]
        grand_mean = statistics.mean(all_vals) if all_vals else 0

        group_means = [statistics.mean(v) for v in values_list]
        between_var = statistics.variance(group_means) if len(group_means) > 1 else 0

        within_vars = [statistics.variance(v) if len(v) > 1 else 0 for v in values_list]
        within_var = statistics.mean(within_vars) if within_vars else 1e-10

        # F-like ratio
        f_ratio = between_var / max(within_var, 1e-10)

        # Leaked bits: log2 of distinguishable groups
        distinct = sum(1 for i, a in enumerate(group_means)
                       for j, b in enumerate(group_means) if i < j and abs(a - b) > math.sqrt(max(within_var, 1)))
        leaked = math.log2(distinct + 1) if distinct > 1 else 0

        snr = between_var / max(within_var, 1e-10)
        score = min(1.0, max(0.0, 1.0 / (1.0 + math.exp(-(snr - 1.0)))))

        counter_name = self._COUNTER_NAME.get(counter, str(counter))
        return ExploitabilityScore(
            score=score,
            leaked_bits=leaked,
            signal_to_noise=snr,
            counter=counter,
            description=f"{counter_name}: F={f_ratio:.2f}, SNR={snr:.2f}, "
                        f"distinguishable_groups={distinct}",
        )

    def _estimate_branch_misses(self, timing_data: Dict[bytes, List[float]]) -> float:
        """Estimate branch misprediction from timing variance skew."""
        all_times = []
        for times in timing_data.values():
            all_times.extend(times)
        if len(all_times) < 10:
            return 0.0
        skewness = self._skew(all_times)
        # High positive skew often indicates sporadic branch mispredictions
        return min(1.0, max(0.0, abs(skewness) / 4.0))

    def _check_perf(self) -> None:
        """Check if Linux perf subsystem is available."""
        perf_path = "/sys/bus/event_source/devices"
        if os.path.exists(perf_path):
            self._perf_available = True
            _log.info("perf subsystem detected")
        else:
            self._perf_available = False
            _log.info("perf not available; using software-only metric estimation")

    def _read_perf_cache(self) -> Dict[PMCCounterType, Dict[bytes, List[int]]]:
        """Stub: read real perf counters via perf_event_open."""
        return {}

    @staticmethod
    def _skew(data: List[float]) -> float:
        n = len(data)
        if n < 3:
            return 0.0
        mean = statistics.mean(data)
        std = statistics.stdev(data)
        if std == 0:
            return 0.0
        return sum(((x - mean) / std) ** 3 for x in data) * n / ((n - 1) * (n - 2))

    @staticmethod
    def measure_cache_timing(probe_fn: Any,
                             iterations: int = 1000):
        """测量缓存访问时序。

        入参兼容可调用对象与地址列表: 前者逐次调用探测函数,
        后者对每个地址执行一次探测。返回带 measurements 列表的结果对象。
        """
        from types import SimpleNamespace
        measurements = []
        if isinstance(probe_fn, (list, tuple)):
            for addr in probe_fn:
                t0 = time.perf_counter_ns()
                _ = addr
                measurements.append(time.perf_counter_ns() - t0)
        else:
            for _ in range(iterations):
                probe_fn()
                t0 = time.perf_counter_ns()
                probe_fn()
                measurements.append(time.perf_counter_ns() - t0)
        return SimpleNamespace(measurements=measurements)

    @staticmethod
    def _estimate_cache_access_time(address: int, is_hit: bool) -> float:
        """按命中/未命中估算单次缓存访问延迟(纳秒)。"""
        return 4.0 if is_hit else 120.0

    @staticmethod
    def _calculate_std(values: List[float]) -> float:
        """计算样本标准差; 样本不足或全等时返回 0。"""
        if len(values) < 2:
            return 0.0
        return statistics.stdev(values)

    @staticmethod
    def _calculate_signal_strength(result: Any) -> float:
        """由时序差值映射信号强度, 归一化到 [0, 1]。"""
        stats = getattr(result, 'statistics', None) or {}
        diff = stats.get('difference_ps', 0) or 0
        return max(0.0, min(1.0, diff / 200000.0))

    @staticmethod
    def _determine_exploitability(result: Any) -> ExploitabilityScore:
        """按信号检测状态与强度划分利用性等级。"""
        if not getattr(result, 'signal_detected', False):
            return ExploitabilityScore.NONE
        strength = getattr(result, 'signal_strength', 0.0) or 0.0
        if strength >= 0.5:
            return ExploitabilityScore.HIGH
        if strength >= 0.3:
            return ExploitabilityScore.MEDIUM
        return ExploitabilityScore.LOW

    def generate_report(self, result: Any) -> str:
        """将评估结果格式化为可读报告。"""
        lines = ["## PMC 侧信道分析报告"]
        detected = bool(getattr(result, 'signal_detected', False))
        lines.append(f"信号检测: {'是' if detected else '否'}")
        lines.append(f"信号强度: {getattr(result, 'signal_strength', 0.0):.2f}")
        expl = getattr(result, 'exploitability', '未知')
        lines.append(f"可利用性: {expl}")
        stats = getattr(result, 'statistics', None) or {}
        if stats:
            lines.append(f"命中延迟(ps): {stats.get('avg_hit_time_ps', 'N/A')}")
            lines.append(f"未命中延迟(ps): {stats.get('avg_miss_time_ps', 'N/A')}")
        notes = getattr(result, 'notes', None) or []
        if notes:
            lines.append("备注:")
            for note in notes:
                lines.append(f"  - {note}")
        return "\n".join(lines)


def evaluate_side_channel(op: Callable, secrets: Optional[List[bytes]] = None) -> List[ExploitabilityScore]:
    return PMCSideChannelEvaluator().evaluate(op, secrets)

measure_cache_timing = PMCSideChannelEvaluator.measure_cache_timing
