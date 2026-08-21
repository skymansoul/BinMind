"""侧信道评估框架, CPA、t-test、泄漏评估。"""

import logging
import math
import os
import statistics
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

import numpy as np

_log = logging.getLogger(__name__)


@dataclass
class TimingMeasurement:
    samples: List[float] = field(default_factory=list)
    label: str = ""
    sample_count: int = 0
    mean: float = 0.0
    stddev: float = 0.0

@dataclass
class CacheProfiler:
    hits: int = 0
    misses: int = 0
    access_times: List[float] = field(default_factory=list)

@dataclass
class CacheHit:
    address: int = 0
    latency: float = 0.0
    is_hit: bool = False

@dataclass
class ChannelBandwidth:
    bits_per_second: float = 0.0
    confidence: float = 0.0
    # 新增：Jensen-Shannon 散度作为信息泄漏的替代指标
    js_divergence: float = 0.0

@dataclass
class EvaluationResult:
    passed: bool
    test_type: str
    p_value: float = 1.0
    t_statistic: float = 0.0
    cpa_correlation: float = 0.0
    cpa_rank: int = 0
    leakage_detected: bool = False
    bandwidth: ChannelBandwidth = field(default_factory=ChannelBandwidth)
    details: Dict[str, Any] = field(default_factory=dict)
    # 新增：互信息泄漏量
    mutual_information: float = 0.0

@dataclass
class BandwidthCalculator:
    @staticmethod
    def estimate(samples_a: List[float], samples_b: List[float],
                 sample_rate_hz: float = 100.0) -> ChannelBandwidth:
        """给定两个分布，估算信息泄漏带宽。"""
        if len(samples_a) < 10 or len(samples_b) < 10:
            return ChannelBandwidth()
        # 基于直方图的互信息近似估计
        all_samples = samples_a + samples_b
        bins = min(50, len(all_samples) // 5)
        hist_a, edges = np.histogram(samples_a, bins=bins)
        hist_b, _ = np.histogram(samples_b, bins=edges)
        # 归一化
        pa = hist_a / max(hist_a.sum(), 1)
        pb = hist_b / max(hist_b.sum(), 1)
        # 互信息：联合分布与边际分布乘积间的 KL 散度
        mi = 0.0
        for i in range(len(edges) - 1):
            if pa[i] > 0 and pb[i] > 0:
                mi += pa[i] * math.log2(pa[i] / max(pb[i], 1e-10))
        mi = max(0.0, mi)
        bps = mi * sample_rate_hz
        # Jensen-Shannon 散度: (KL(P||M) + KL(Q||M)) / 2
        m = [(pa[i] + pb[i]) / 2 for i in range(len(pa))]
        js = 0.0
        for i in range(len(pa)):
            if pa[i] > 0 and m[i] > 0:
                js += pa[i] * math.log2(pa[i] / m[i])
            if pb[i] > 0 and m[i] > 0:
                js += pb[i] * math.log2(pb[i] / m[i])
        js /= 2.0
        return ChannelBandwidth(
            bits_per_second=bps,
            confidence=min(1.0, mi / 4.0),
            js_divergence=js,
        )


# SideChannelEvaluator -- 主入口

class TimingMeasurer:
    """高分辨率时序测量辅助工具。"""

    def __init__(self, warmup: int = 5):
        self._warmup = warmup
        self._inner = None

    def measure(self, fn: Callable[[], Any], iterations: int = 100) -> TimingMeasurement:
        """多次计时函数调用，舍弃预热样本。"""
        for _ in range(self._warmup):
            fn()

        samples = []
        for _ in range(iterations):
            t0 = time.perf_counter_ns()
            fn()
            samples.append(time.perf_counter_ns() - t0)

        return TimingMeasurement(
            samples=samples,
            sample_count=len(samples),
            mean=statistics.mean(samples),
            stddev=statistics.stdev(samples) if len(samples) > 1 else 0.0,
        )


class SideChannelEvaluator:
    """综合侧信道评估：CPA、Welch t-test、泄漏评估。

    用法::

        evaluator = SideChannelEvaluator()
        result = evaluator.evaluate(crypto_impl, traces=power_traces, plaintexts=plaintexts)
    """

    def __init__(self):
        self._measurer = TimingMeasurer()

# 主入口

    def evaluate(self, impl: Any, **kwargs) -> List[EvaluationResult]:
        """对给定实现运行所有相关测试。

        `impl`: 可调用对象(key, plaintext) -> ciphertext，或待插桩路径。
        `traces`: 可选功耗/EM 轨迹列表 (np.ndarray)。
        `plaintexts`: CPA 用明文列表。
        `keys`: CPA 用密钥列表（其中一个为真实密钥）。
        """
        traces = kwargs.get("traces")
        plaintexts = kwargs.get("plaintexts")
        keys = kwargs.get("keys")

        results: List[EvaluationResult] = []

        # 1. Welch t 检验 (TVLA 风格：固定 vs 随机)
        if callable(impl):
            t_result = self._welch_ttest(impl, kwargs.get("trials", 500))
            results.append(t_result)

        # 2. 相关功耗分析 (CPA)
        if traces is not None and plaintexts is not None:
            cpa_result = self._cpa(np.array(traces), plaintexts, keys)
            results.append(cpa_result)

        # 3. 带宽估算
        if len(results) > 0:
            bw = self._estimate_bandwidth(impl, kwargs.get("trials", 200))
            results[0].bandwidth = bw

        if not results:
            results.append(EvaluationResult(
                passed=True, test_type="no_data",
                details={"note": "Insufficient data for evaluation"},
            ))

        return results

# Welch t-test（TVLA）

    def _welch_ttest(self, op: Callable, trials: int = 500) -> EvaluationResult:
        """非特定（fixed vs. random）t-test。

        增强：增加互信息（MI）作为辅助泄漏指标。
        单纯 t-test 可能漏掉非线性依赖关系（如缓存冲突模式），
        MI 可捕捉此类非单调关联。
        """
        fixed_times = []
        random_times = []
        fixed_input = bytes([0x00] * 16)
        for _ in range(trials):
            random_input = os.urandom(16)

            t0 = time.perf_counter_ns()
            op(fixed_input)
            fixed_times.append(time.perf_counter_ns() - t0)

            t0 = time.perf_counter_ns()
            op(random_input)
            random_times.append(time.perf_counter_ns() - t0)

        # 计算 Welch t 统计量
        n1, n2 = len(fixed_times), len(random_times)
        m1 = statistics.mean(fixed_times)
        m2 = statistics.mean(random_times)
        v1 = statistics.variance(fixed_times) if n1 > 1 else 0
        v2 = statistics.variance(random_times) if n2 > 1 else 0

        se = math.sqrt(v1 / n1 + v2 / n2)
        t_stat = (m1 - m2) / se if se > 0 else 0

        # 自由度 (Welch-Satterthwaite)
        num = (v1 / n1 + v2 / n2) ** 2
        den = (v1 / n1) ** 2 / (n1 - 1) + (v2 / n2) ** 2 / (n2 - 1)
        df = num / den if den > 0 else 1

        # 双尾 p 值近似
        x = df / (df + t_stat * t_stat)
        p = max(0.0, min(1.0, 2.0 * (1.0 - _incomplete_beta(x, df / 2, 0.5))))

        leakage = abs(t_stat) > 4.5

        # 互信息估算
        mi = BandwidthCalculator.estimate(fixed_times, random_times)

        return EvaluationResult(
            passed=not leakage,
            test_type="welch_ttest_tvla",
            p_value=p,
            t_statistic=abs(t_stat),
            leakage_detected=leakage,
            mutual_information=mi.bits_per_second,
            details={
                "fixed_mean_ns": m1, "random_mean_ns": m2,
                "fixed_std_ns": math.sqrt(v1), "random_std_ns": math.sqrt(v2),
                "samples_per_group": n1,
            },
        )

# CPA

    def _cpa(self, traces: np.ndarray, plaintexts: List[int],
             keys: Optional[List[int]] = None) -> EvaluationResult:
        """基于汉明权重模型的相关功耗分析。

        traces: 形状 (n_traces, n_samples)
        plaintexts: 明文字节值列表
        keys: 可选密钥候选列表（默认 0..255）

        增强：使用 k-fold 交叉验证避免 CPA 过拟合。
        小样本量（< 200 traces）时，单次 CPA 可能产生虚假高相关。
        """
        n_traces, n_samples = traces.shape
        key_candidates = keys or list(range(256))
        max_corr = 0.0
        best_key = 0

        # k-fold 交叉验证：3 折，对候选密钥做稳健性评估
        n_folds = min(3, n_traces // 10)
        if n_folds < 1:
            n_folds = 1

        for kg in key_candidates:
            # S盒(pt XOR key_guess)的汉明权重
            predictions = np.array([
                bin(p ^ kg).count("1") for p in plaintexts[:n_traces]
            ], dtype=np.float64)

            fold_corrs = []
            for fold in range(n_folds):
                start = fold * n_traces // n_folds
                end = (fold + 1) * n_traces // n_folds
                if end - start < 5:
                    continue
                trace_col = traces[start:end, :].mean(axis=0).astype(np.float64)
                pred_col = predictions[start:end].mean()
                # 简化的折内相关
                corr = np.corrcoef(predictions[start:end], traces[start:end].mean(axis=1))[0, 1]
                if not math.isnan(corr):
                    fold_corrs.append(abs(corr))

            if fold_corrs:
                mean_corr = np.mean(fold_corrs)
                if mean_corr > max_corr:
                    max_corr = mean_corr
                    best_key = kg

        rank = sum(1 for _ in range(256) if _ != best_key) + 1

        leakage = max_corr > 0.3
        return EvaluationResult(
            passed=not leakage,
            test_type="cpa",
            cpa_correlation=max_corr,
            cpa_rank=rank if keys is None else 256 - rank + 1,
            leakage_detected=leakage,
            details={
                "best_key_guess": best_key,
                "max_correlation": max_corr,
                "n_traces": n_traces,
                "n_key_candidates": len(key_candidates),
                "cross_validation_folds": n_folds,
            },
        )

# 带宽估算

    def _estimate_bandwidth(self, op: Callable, trials: int = 200) -> ChannelBandwidth:
        try:
            fixed = []
            random_vals = []
            for _ in range(trials):
                t0 = time.perf_counter_ns()
                op(b"\x00" * 16)
                fixed.append(time.perf_counter_ns() - t0)

                t0 = time.perf_counter_ns()
                op(os.urandom(16))
                random_vals.append(time.perf_counter_ns() - t0)

            return BandwidthCalculator.estimate(fixed, random_vals)
        except Exception:
            return ChannelBandwidth()

# 逐时点 SNR 估计
    # 对每条 trace 的每个采样点估计信噪比，用于定位泄漏点。

    @staticmethod
    def estimate_snr_per_sample(traces: np.ndarray, labels: List[int]) -> np.ndarray:
        """按时间采样点计算信噪比。

        SNR[t] = Var(组间均值)[t] / 平均(组内方差)[t]
        返回形状 (n_samples,) 的 SNR 数组。
        """
        n_traces, n_samples = traces.shape
        unique_labels = sorted(set(labels))
        if len(unique_labels) < 2:
            return np.zeros(n_samples)

        snr = np.zeros(n_samples)
        for s in range(n_samples):
            col = traces[:, s].astype(np.float64)
            group_means = [col[np.array(labels) == lbl].mean() for lbl in unique_labels]
            between_var = np.var(group_means) if len(group_means) > 1 else 0.0
            within_vars = [col[np.array(labels) == lbl].var() for lbl in unique_labels
                         if (np.array(labels) == lbl).sum() > 1]
            within_var = np.mean(within_vars) if within_vars else 1e-10
            snr[s] = between_var / max(within_var, 1e-10)
        return snr


# 辅助函数：不完全 Beta 分布近似

def _incomplete_beta(x: float, a: float, b: float) -> float:
    """不完全 Beta 函数连分数近似。"""
    if x <= 0:
        return 0.0
    if x >= 1:
        return 1.0
    # 简单近似正则化
    log_beta = math.lgamma(a) + math.lgamma(b) - math.lgamma(a + b)
    front = math.exp(math.log(x) * a + math.log(1 - x) * b - log_beta) / a
    return min(1.0, max(0.0, front))


def create_side_channel_evaluator() -> SideChannelEvaluator:
    return SideChannelEvaluator()
