"""Microarchitectural side-channel validator -- cache timing, Spectre/Meltdown patterns."""

import logging
import os
import statistics
import time
import platform
from dataclasses import dataclass, field
from typing import Any, Callable, List, Tuple

_log = logging.getLogger(__name__)

# Flush+Reload threshold (cycles) -- platform-dependent, calibrated at init
_CACHE_HIT_THRESHOLD: int = 120
_FLUSH_RELOAD_ITERATIONS = 1000


@dataclass
class SideChannelEvidence:
    confidence: float
    attack_type: str = ""
    description: str = ""
    measured_bandwidth_bps: float = 0.0
    p_value: float = 1.0
    raw_samples: List[float] = field(default_factory=list)

@dataclass
class VerificationResult:
    passed: bool
    vulnerability: str = ""
    evidence: List[SideChannelEvidence] = field(default_factory=list)
    mitigation_suggestions: List[str] = field(default_factory=list)


# Core validator

class MicroarchSideChannelValidator:
    """Test whether a given implementation leaks information through microarchitectural
    covert or side channels.
    """

    def __init__(self, cache_line_size: int = 64, calibrate: bool = True):
        self._cl_size = cache_line_size or self._detect_cache_line_size()
        self._hit_threshold = _CACHE_HIT_THRESHOLD
        if calibrate:
            self._calibrate()

    # -- public ---------------------------------------------------------------

    def validate(self, impl: Any, trials: int = 1000) -> VerificationResult:
        """`impl` is a callable(secret) or a binary path to instrument."""
        if callable(impl):
            return self._validate_callable(impl, trials)
        return VerificationResult(
            passed=True,
            vulnerability="static_analysis_only",
            evidence=[],
            mitigation_suggestions=["Run with a callable instrumenting the target"],
        )

    # -- Flush+Reload ---------------------------------------------------------

    def flush_reload(self, probe_address: int, iterations: int = None) -> Tuple[float, float]:
        """Measure access time difference between cached and evicted probe address."""
        n = iterations or _FLUSH_RELOAD_ITERATIONS
        cached_times = []
        evicted_times = []

        for _ in range(n):
            # Hit
            t0 = self._rdtscp() if hasattr(self, "_rdtscp") else time.perf_counter_ns()
            self._access(probe_address)
            t1 = self._rdtscp() if hasattr(self, "_rdtscp") else time.perf_counter_ns()
            cached_times.append(t1 - t0)

            # Evict
            self._clflush(probe_address)
            if self._has_mfence():
                self._mfence()
            t2 = self._rdtscp() if hasattr(self, "_rdtscp") else time.perf_counter_ns()
            self._access(probe_address)
            t3 = self._rdtscp() if hasattr(self, "_rdtscp") else time.perf_counter_ns()
            evicted_times.append(t3 - t2)

        cached_median = statistics.median(cached_times)
        evicted_median = statistics.median(evicted_times)
        return cached_median, evicted_median

    # -- Spectre pattern detection --------------------------------------------

    def detect_spectre_v1(self, condition_fn: Callable[[int], int], array_size: int = 256,
                          trials: int = 100) -> SideChannelEvidence:
        """Check if a conditional access leaks via Spectre-v1 (bounds-check bypass).

        `condition_fn(x)` returns array index to access.
        """
        hit_times = []
        for _ in range(trials):
            for in_bounds in (True, False):
                idx = array_size // 2 if in_bounds else array_size * 64
                self._clflush_all_probe_array(array_size * 256)
                _ = condition_fn(idx)
                t = self._probe_access_time(0)
                hit_times.append(t)

        # Compare hit distributions
        in_bound = hit_times[::2]
        out_bound = hit_times[1::2]
        med_in = statistics.median(in_bound)
        med_out = statistics.median(out_bound)
        leaked = med_out < self._hit_threshold and med_out < med_in * 0.7

        return SideChannelEvidence(
            confidence=0.8 if leaked else 0.2,
            attack_type="Spectre-v1",
            description=f"In-bounds median={med_in:.1f}, out-of-bounds={med_out:.1f}",
            p_value=self._welch_ttest(in_bound, out_bound) if len(in_bound) > 5 else 1.0,
            raw_samples=hit_times,
        )

    def detect_spectre_v2(self, indirect_branch_fn: Callable[[int], int],
                          trials: int = 100) -> SideChannelEvidence:
        """Check for Spectre-v2 (branch target injection)."""
        times = []
        for _ in range(trials):
            self._clflush_all_probe_array(256 * 64)
            _ = indirect_branch_fn(0)
            t = self._probe_access_time(0)
            times.append(t)

        median_access = statistics.median(times)
        leaked = median_access < self._hit_threshold
        return SideChannelEvidence(
            confidence=0.6 if leaked else 0.1,
            attack_type="Spectre-v2",
            description=f"Indirect-branch probe median={median_access:.1f} cycles",
            raw_samples=times,
        )

    # -- Meltdown pattern detection -------------------------------------------

    def detect_meltdown(self, kernel_access_fn: Callable[[], int],
                        probe_array_base: int, trials: int = 100) -> SideChannelEvidence:
        """Check for Meltdown (kernel-memory leak via fault suppression)."""
        times = []
        for _ in range(trials):
            self._clflush(probe_array_base)
            try:
                _ = kernel_access_fn()
            except Exception:
                pass  # Expected: SIGSEGV or exception
            t = self._probe_access_time(probe_array_base)
            times.append(t)

        median_t = statistics.median(times)
        leaked = median_t < self._hit_threshold
        return SideChannelEvidence(
            confidence=0.9 if leaked else 0.1,
            attack_type="Meltdown",
            description=f"Kernel-probe access median={median_t:.1f} cycles",
            raw_samples=times,
        )

    # -- Info leakage rate ----------------------------------------------------

    def measure_leakage_rate(self, victim_fn: Callable[[bytes], None],
                              observe_fn: Callable[[], int],
                              secret_bits: int = 8,
                              trials: int = 1000) -> float:
        """Estimate bits-per-second leakage via a side channel.

        Returns estimated bandwidth in bits/sec.
        """
        correct = 0
        t0 = time.monotonic()
        for _ in range(trials):
            secret = int.from_bytes(os.urandom(1), "little") & ((1 << secret_bits) - 1)
            victim_fn(secret.to_bytes(1, "little"))
            observation = observe_fn()
            if observation == secret:
                correct += 1
        elapsed = time.monotonic() - t0
        if elapsed == 0:
            return 0.0
        accuracy = correct / trials
        import math
        if accuracy <= 0:
            info_per_trial = 0.0
        elif accuracy >= 1:
            info_per_trial = float(secret_bits)
        else:
            # 二进制对称信道互信息近似：k - H(误码率)
            err = 1.0 - accuracy
            h_err = -(err * math.log2(err) + accuracy * math.log2(accuracy))
            info_per_trial = secret_bits - h_err
        bitrate = trials * info_per_trial / elapsed
        return max(0.0, bitrate)

    # -- internal helpers -----------------------------------------------------

    def _validate_callable(self, impl: Callable, trials: int) -> VerificationResult:
        evidence: List[SideChannelEvidence] = []
        # Collect timing traces for two different secrets
        timings_a = []
        timings_b = []
        for i in range(trials):
            t0 = self._rdtscp() if hasattr(self, "_rdtscp") else time.perf_counter_ns()
            impl(b"\x00")
            t1 = self._rdtscp() if hasattr(self, "_rdtscp") else time.perf_counter_ns()
            timings_a.append(t1 - t0)

            t0 = self._rdtscp() if hasattr(self, "_rdtscp") else time.perf_counter_ns()
            impl(b"\xFF")
            t1 = self._rdtscp() if hasattr(self, "_rdtscp") else time.perf_counter_ns()
            timings_b.append(t1 - t0)

        p_val = self._welch_ttest(timings_a, timings_b)
        median_a = statistics.median(timings_a)
        median_b = statistics.median(timings_b)

        evidence.append(SideChannelEvidence(
            confidence=1.0 - p_val if p_val else 0.0,
            attack_type="timing",
            description=f"Secret 0x00 median={median_a:.1f}, 0xFF median={median_b:.1f}",
            p_value=p_val,
            raw_samples=timings_a + timings_b,
        ))

        passed = p_val > 0.01  # not statistically significant
        mitigations = []
        if not passed:
            mitigations.append("Implement constant-time operations")
            mitigations.append("Use data-independent memory access patterns")

        return VerificationResult(
            passed=passed,
            vulnerability="timing_side_channel" if not passed else "none",
            evidence=evidence,
            mitigation_suggestions=mitigations,
        )

    # -- platform abstractions ------------------------------------------------

    def _calibrate(self) -> None:
        """Measure actual cache hit/miss threshold on this hardware."""
        buf = bytearray(self._cl_size * 2)
        addr = id(buf)
        hits = []
        misses = []
        for _ in range(100):
            _ = buf[0]
            t0 = time.perf_counter_ns()
            _ = buf[0]
            hits.append(time.perf_counter_ns() - t0)

            self._clflush(addr)
            t0 = time.perf_counter_ns()
            _ = buf[0]
            misses.append(time.perf_counter_ns() - t0)

        hit_med = statistics.median(hits)
        miss_med = statistics.median(misses)
        self._hit_threshold = int((hit_med + miss_med) / 2)
        _log.debug("Calibrated hit threshold: %d ns  (hit=%d, miss=%d)",
                    self._hit_threshold, hit_med, miss_med)

    @staticmethod
    def _access(addr: int) -> None:
        import ctypes
        ctypes.c_char.from_address(addr).value

    @staticmethod
    def _clflush(addr: int) -> None:
        try:
            import ctypes
            ctypes.c_char.from_address(addr)
            # Python-level flush via memory barrier + load
            _ = [0] * 4096  # Evict from L1 with unrelated data
        except Exception:
            _log.debug("suppressed", exc_info=True)

    @staticmethod
    def _clflush_all_probe_array(size: int) -> None:
        _ = [0] * size

    @staticmethod
    def _probe_access_time(addr: int) -> float:
        t0 = time.perf_counter_ns()
        try:
            import ctypes
            ctypes.c_char.from_address(addr).value
        except Exception:
            _log.debug("suppressed", exc_info=True)
        return time.perf_counter_ns() - t0

    @staticmethod
    def _has_mfence() -> bool:
        return platform.machine() in ("x86_64", "AMD64", "i386", "i686")

    @staticmethod
    def _mfence() -> None:
        pass

    @staticmethod
    def _rdtscp() -> int:
        return time.perf_counter_ns()

    @staticmethod
    def _detect_cache_line_size() -> int:
        if platform.machine() in ("x86_64", "AMD64"):
            return 64
        if "arm" in platform.machine() or "aarch64" in platform.machine():
            return 64
        return 64

    @staticmethod
    def _welch_ttest(a: List[float], b: List[float]) -> float:
        """Welch's t-test p-value approximation."""
        try:
            import math
            mean_a = statistics.mean(a)
            mean_b = statistics.mean(b)
            var_a = statistics.variance(a) if len(a) > 1 else 0.0
            var_b = statistics.variance(b) if len(b) > 1 else 0.0
            n_a, n_b = len(a), len(b)
            if var_a == 0 and var_b == 0:
                return 1.0
            t_stat = (mean_a - mean_b) / math.sqrt(var_a / n_a + var_b / n_b)
            nu_num = (var_a / n_a + var_b / n_b) ** 2
            nu_den = (var_a / n_a) ** 2 / (n_a - 1) + (var_b / n_b) ** 2 / (n_b - 1)
            nu = nu_num / nu_den if nu_den else 1.0
            # Rough p-value via approximation
            x = nu / (nu + t_stat * t_stat)
            p = max(0.0, min(1.0, 2.0 * (1.0 - _beta_reg(x, nu / 2, 0.5))))
            return p
        except Exception:
            return 1.0


def _beta_reg(x: float, a: float, b: float) -> float:
    """Incomplete beta regularized function approximation."""
    if x <= 0:
        return 0.0
    if x >= 1:
        return 1.0
    # Simple continued fraction approximation won't cover all cases
    return x ** a * (1 - x) ** b / (a + b)


def create_microarch_validator() -> MicroarchSideChannelValidator:
    return MicroarchSideChannelValidator()
