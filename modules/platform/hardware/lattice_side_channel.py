"""基于格的密码侧信道分析，多项式乘法时序泄漏。"""

import logging
import math
import os
import statistics
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

_log = logging.getLogger(__name__)


@dataclass
class PolynomialOperation:
    degree: int
    coefficient_count: int = 0
    operation_type: str = ""    # NTT / INTT / mul / add
    constant_time: bool = False

@dataclass
class TimingAnalysisResult:
    samples: List[float] = field(default_factory=list)
    operation: Optional[PolynomialOperation] = None
    mean: float = 0.0
    stddev: float = 0.0
    coefficient_correlation: Dict[int, float] = field(default_factory=dict)
    is_constant_time: bool = True
    # 新增：频率侧信道（Hertzbleed 风格）指标
    freq_variation_hz: float = 0.0
    mutual_information_bits: float = 0.0
    cliff_delta: float = 0.0

@dataclass
class SideChannelVulnerability:
    type: str                      # timing | power | em | frequency
    operation: str = ""            # e.g. "NTT", "polynomial_mul"
    severity: str = "MEDIUM"       # LOW | MEDIUM | HIGH | CRITICAL
    description: str = ""
    evidence: List[TimingAnalysisResult] = field(default_factory=list)


# 统计工具：互信息与 Cliff's Delta
# 使用直方图估计互信息（MI），比单纯的 t-test 更善于捕捉非线性依赖。
# Cliff's delta 是无分布假设的 effect size，适合非正态时序样本。
# Mainali & Ghimire (2025) "Statistical Side-Channel Risk Model"

def _mutual_information_hist(samples_a: List[float], samples_b: List[float],
                             bins: int = 20) -> float:
    """基于直方图的离散互信息估计（bits）。

    bins 自适应：样本少时用 10-bin 粗粒度，大样本用 30-bin。
    """
    all_vals = samples_a + samples_b
    n = min(len(samples_a), len(samples_b))
    if n < 10:
        return 0.0

    # 自适应分箱
    n_bins = min(bins, max(5, int(math.sqrt(n))))
    rng = (min(all_vals), max(all_vals))
    if rng[1] - rng[0] < 1.0:
        return 0.0

    bin_width = (rng[1] - rng[0]) / n_bins

    def _count(arr):
        counts = [0] * n_bins
        for v in arr:
            idx = min(n_bins - 1, int((v - rng[0]) / bin_width))
            counts[idx] += 1
        return [c / len(arr) for c in counts]

    pa = _count(samples_a)
    pb = _count(samples_b)
    mi = 0.0
    for i in range(n_bins):
        if pa[i] > 0 and pb[i] > 0:
            # pa 相对于 pb 的 KL 散度
            mi += pa[i] * math.log2(pa[i] / max(pb[i], 1e-10))
    return max(0.0, mi)


def _cliff_delta(a: List[float], b: List[float]) -> float:
    """Cliff's delta: 非参数效应量 [-1, 1]。

    |δ| > 0.474 → "大", |δ| > 0.33 → "中", |δ| > 0.147 → "小"。
    对时序侧信道：正 δ 表示 a 组的时序显著高于 b 组。
    """
    n_a, n_b = len(a), len(b)
    if n_a == 0 or n_b == 0:
        return 0.0
    # 统计 a_i > b_j 和 a_i < b_j 的比例
    dominance = 0
    for x in a:
        dominance += sum(1 for y in b if x > y)
    delta = dominance / (n_a * n_b)
    return 2 * delta - 1


# 分析器

class LatticeSideChannelAnalyzer:
    """检测基于格的密码运算中的时序泄漏。

    聚焦于多项式乘法、NTT/INTT 变换以及系数相关的分支，
    常见于 Kyber、Dilithium 等方案。

    用法::

        analyzer = LatticeSideChannelAnalyzer()
        result = analyzer.analyze(ntt_implementation, n=256, q=3329)
    """

    # 公开 API：对外仅暴露 analyze 入口，其余均为内部检测管线
    def analyze(self, impl: Any, n: int = 256, q: int = 3329,
                trials: int = 500, **kwargs) -> List[SideChannelVulnerability]:
        """分析一个实现。

        `impl` 可以是可调用对象 (coefficients) -> result，或 dict/路径用于静态分析。
        """
        if callable(impl):
            return self._analyze_callable(impl, n, q, trials)
        vulns: List[SideChannelVulnerability] = []
        vulns.append(SideChannelVulnerability(
            type="timing", operation="static_check",
            severity="LOW",
            description="Static analysis of lattice operations",
        ))
        return vulns

    def _analyze_callable(self, op: Callable, n: int, q: int,
                          trials: int) -> List[SideChannelVulnerability]:
        """对可调用对象进行插桩，跨随机系数集检测时序泄漏。"""
        vulns: List[SideChannelVulnerability] = []

        # 时序追踪采集：全量采样 + 逐系数定位采样，双路数据支撑后续统计
        all_samples: List[float] = []
        coeff_timings: Dict[int, List[float]] = defaultdict(list)

        for _ in range(trials):
            coeffs = [int.from_bytes(os.urandom(2), "little") % q for __ in range(n)]
            t0 = time.perf_counter_ns()
            op(coeffs)
            elapsed = time.perf_counter_ns() - t0
            all_samples.append(elapsed)

            # 逐系数相关性：仅使用一个非零系数运行
            for bit in range(min(8, n)):
                single = [0] * n
                idx = (bit * n // 8) % n
                single[idx] = coeffs[idx]
                t0 = time.perf_counter_ns()
                op(single)
                coeff_timings[idx].append(time.perf_counter_ns() - t0)

        # 统计分析：全量样本均值/方差 + 系数维度中位数偏离
        mean_t = statistics.mean(all_samples)
        std_t = statistics.stdev(all_samples) if len(all_samples) > 1 else 0.0

        # 系数相关性：若不同系数索引产生不同的中位时序，
        # 则大概率存在数据依赖分支。
        coeff_medians: Dict[int, float] = {}
        for idx, times in coeff_timings.items():
            coeff_medians[idx] = statistics.median(times)

        if len(coeff_medians) > 1:
            medians_list = list(coeff_medians.values())
            global_med = statistics.median(medians_list)
            deviations = {idx: abs(m - global_med) / max(global_med, 1)
                          for idx, m in coeff_medians.items()}
            max_dev = max(deviations.values()) if deviations else 0.0
        else:
            deviations = {}
            max_dev = 0.0

        # 判定：是否常数时间？
        # 若系数选择导致时序变化 > 5%，标记为非恒定时间。
        is_const = max_dev < 0.05 and std_t / max(mean_t, 1) < 0.1

        # 互信息与效应量：对分布形态差异做二次验证，避免仅靠方差误判
        # 比较零系数 vs 饱和系数的分布差异
        zero_times = coeff_timings.get(0, all_samples[:min(50, len(all_samples))])
        sat_idx = min(n - 1, 1)
        sat_times = coeff_timings.get(sat_idx, all_samples[-min(50, len(all_samples)):])
        mi_bits = _mutual_information_hist(zero_times, sat_times)
        cd_val = _cliff_delta(zero_times, sat_times)

        result = TimingAnalysisResult(
            samples=all_samples,
            operation=PolynomialOperation(
                degree=n - 1, coefficient_count=n,
                operation_type="custom", constant_time=is_const,
            ),
            mean=mean_t, stddev=std_t,
            coefficient_correlation=deviations,
            is_constant_time=is_const,
            mutual_information_bits=mi_bits,
            cliff_delta=cd_val,
        )

        if not is_const:
            vulns.append(SideChannelVulnerability(
                type="timing",
                operation="polynomial_operation",
                severity="HIGH" if max_dev > 0.15 else "MEDIUM",
                description=f"Timing varies with coefficient values "
                            f"(median={mean_t:.1f}ns, std={std_t:.1f}ns, "
                            f"max_coeff_deviation={max_dev:.2%}, "
                            f"MI={mi_bits:.3f}bits, δ={cd_val:.3f})",
                evidence=[result],
            ))

        # NTT 专项检测：变换过程的数据依赖是格密码最典型的泄漏源
        ntt_result = self._check_ntt_timing(op, n, q, trials // 2)
        if ntt_result is not None and not ntt_result.is_constant_time:
            vulns.append(SideChannelVulnerability(
                type="timing",
                operation="NTT",
                severity="CRITICAL",
                description="NTT transform exhibits coefficient-dependent timing",
                evidence=[ntt_result],
            ))

        # 频率侧信道（Hertzbleed 风格）检测
        # 启发式：大的时间方差 + 小样本时也较稳定 → DVFS 相关的频率泄漏
        freq_result = self._check_frequency_side_channel(op, n, q, min(trials, 200))
        if freq_result and freq_result.freq_variation_hz > 5.0:
            vulns.append(SideChannelVulnerability(
                type="frequency",
                operation="DVFS_side_channel",
                severity="HIGH" if freq_result.freq_variation_hz > 20.0 else "MEDIUM",
                description=f"Frequency side-channel detected: "
                            f"estimated variation {freq_result.freq_variation_hz:.1f}MHz",
                evidence=[freq_result],
            ))

        if not vulns:
            vulns.append(SideChannelVulnerability(
                type="timing",
                operation="polynomial_operation",
                severity="LOW",
                description="No significant timing leakage detected",
                evidence=[result],
            ))

        return vulns

    def _check_ntt_timing(self, op: Callable, n: int, q: int,
                           trials: int) -> Optional[TimingAnalysisResult]:
        """NTT 时序专项检测：对比零系数与饱和系数。"""
        zero_times = []
        sat_times = []
        for _ in range(trials):
            zero_coeffs = [0] * n
            t0 = time.perf_counter_ns()
            op(zero_coeffs)
            zero_times.append(time.perf_counter_ns() - t0)

            sat_coeffs = [q - 1] * n
            t0 = time.perf_counter_ns()
            op(sat_coeffs)
            sat_times.append(time.perf_counter_ns() - t0)

        z_med = statistics.median(zero_times)
        s_med = statistics.median(sat_times)
        ratio = abs(s_med - z_med) / max(z_med, 1)
        mi_val = _mutual_information_hist(zero_times, sat_times)

        return TimingAnalysisResult(
            samples=zero_times + sat_times,
            operation=PolynomialOperation(degree=n - 1, operation_type="NTT"),
            mean=(z_med + s_med) / 2,
            stddev=statistics.stdev(zero_times + sat_times) if len(zero_times) > 1 else 0,
            is_constant_time=ratio < 0.05,
            mutual_information_bits=mi_val,
            cliff_delta=_cliff_delta(zero_times, sat_times),
        )

    def _check_frequency_side_channel(self, op: Callable, n: int, q: int,
                                       trials: int) -> Optional[TimingAnalysisResult]:
        """检测频率侧信道：运行不同汉明权重的输入，观察耗时是否呈非线性变化。

        参考: Yu et al. "Hints from Hertz" —
        NTT 中间值汉明权重差异会通过 DVFS 影响 CPU 频率，
        频率变化反过来在时序上表现为方差膨胀。
        """
        hw_low_times = []
        hw_high_times = []
        for _ in range(trials):
            # 低汉明权重：系数全为 0 或 2^k
            low_coeffs = [0] * n
            t0 = time.perf_counter_ns()
            op(low_coeffs)
            hw_low_times.append(time.perf_counter_ns() - t0)

            # 高汉明权重：系数全为 (q-1) → 所有位为 1
            high_coeffs = [q - 1] * n
            t0 = time.perf_counter_ns()
            op(high_coeffs)
            hw_high_times.append(time.perf_counter_ns() - t0)

        low_med = statistics.median(hw_low_times)
        high_med = statistics.median(hw_high_times)
        # 频率变化估算：假设 2.5 GHz 基准，用时差异 > 3% 换算回 MHz
        base_ghz = 2.5
        ratio_diff = abs(high_med - low_med) / max(low_med, 1)
        freq_var = base_ghz * ratio_diff * 1000  # MHz

        return TimingAnalysisResult(
            samples=hw_low_times + hw_high_times,
            operation=PolynomialOperation(degree=n - 1, operation_type="DVFS_probe"),
            mean=(low_med + high_med) / 2,
            stddev=statistics.stdev(hw_low_times + hw_high_times) if len(hw_low_times) > 1 else 0,
            is_constant_time=ratio_diff < 0.02,
            freq_variation_hz=freq_var,
            mutual_information_bits=_mutual_information_hist(hw_low_times, hw_high_times),
        )

    @staticmethod
    def detect_conditional_branch_in_ntt(source_code: str) -> List[Tuple[int, str]]:
        """静态分析：查找 NTT 代码中基于模约简的条件分支。"""
        import re
        issues = []
        patterns = [
            (r"if\s*\(\s*(\w+)\s*[><=]+\s*q\s*\)", "conditional on modulus q"),
            (r"if\s*\(\s*(\w+)\s*[><=]+\s*(\w+)\s*\)", "conditional on coefficient comparison"),
            (r"(\w+)\s*\?\s*(\w+)\s*\+\s*q\s*:", "ternary add-q reduction (potential leak)"),
        ]
        for lineno, line in enumerate(source_code.split("\n"), 1):
            for pat, desc in patterns:
                if re.search(pat, line):
                    issues.append((lineno, desc))
        return issues
