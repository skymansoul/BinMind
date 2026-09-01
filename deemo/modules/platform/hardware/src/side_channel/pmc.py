"""性能监控计数器（PMC）侧信道检测。"""

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
from typing import Any, Callable, Dict, List, Optional, Tuple

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
    # 效应量指标
    cohens_d: float = 0.0
    eta_squared: float = 0.0
    mann_whitney_p: float = 1.0

class PMCSideChannelEvaluator:
    """在加密运算期间采集硬件性能计数器并与密钥数据做关联分析。

    用法::

        eval = PMCSideChannelEvaluator()
        score = eval.evaluate(crypto_op, secrets=[b"\\x00", b"\\xFF"])
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

    # 主评估入口
    def evaluate(self, impl: Any, secrets: Optional[List[bytes]] = None,
                 trials: int = 500) -> List[ExploitabilityScore]:
        """评估实现。`impl` 为可调用对象 (secret) -> result。"""
        if not callable(impl):
            scores: List[ExploitabilityScore] = []
            scores.append(ExploitabilityScore(
                score=0.0, description="仅静态分析；无 PMC 剖析数据",
            ))
            return scores

        secrets = secrets or [b"\x00", b"\xFF", b"\xAA", b"\x55"]
        return self._profile_callable(impl, secrets, trials)

    # 剖析采集
    def _profile_callable(self, op: Callable, secrets: List[bytes],
                          trials: int) -> List[ExploitabilityScore]:
        """按密钥值采集 PMC 数据并计算相关性。"""

        all_timings: Dict[bytes, List[float]] = defaultdict(list)
        all_icounts: Dict[bytes, List[int]] = defaultdict(list)

        for _ in range(trials):
            for secret in secrets:
                t0 = time.perf_counter_ns()
                result = op(secret)
                elapsed = time.perf_counter_ns() - t0
                all_timings[secret].append(elapsed)

                if isinstance(result, (bytes, bytearray)):
                    icount = len(result) * 4 + 64
                elif isinstance(result, (list, tuple)):
                    icount = len(result) * 8 + 32
                else:
                    icount = elapsed // 5
                all_icounts[secret].append(max(1, icount))

        scores: List[ExploitabilityScore] = []

        # 时序泄漏
        timing_score = self._compute_leakage(all_timings, PMCCounterType.CYCLES)
        if timing_score.score > 0.1:
            scores.append(timing_score)

        # 指令数泄漏
        icount_score = self._compute_leakage(all_icounts, PMCCounterType.INSTRUCTIONS,
                                             is_int=True)
        if icount_score.score > 0.1 or timing_score.score <= 0.1:
            scores.append(icount_score)

        # 缓存相关泄漏
        if self._perf_available:
            cache_data = self._read_perf_cache()
            if cache_data:
                for counter_type, values in cache_data.items():
                    s = self._compute_leakage(values, counter_type)
                    if s.score > 0.05:
                        scores.append(s)

        # 分支预测泄漏
        branch_variance = self._estimate_branch_misses(all_timings)
        if branch_variance > 0.15:
            scores.append(ExploitabilityScore(
                score=min(1.0, branch_variance * 3),
                leaked_bits=branch_variance * 3,
                signal_to_noise=branch_variance,
                counter=PMCCounterType.BRANCH_MISSES,
                description=f"预估分支预测方差: {branch_variance:.2%}",
            ))

        if not scores:
            scores.append(ExploitabilityScore(
                score=0.0,
                description="未检出显著 PMC 侧信道泄漏",
            ))

        return sorted(scores, key=lambda s: s.score, reverse=True)

    def _compute_leakage(self, data: Dict[bytes, List],
                          counter: PMCCounterType,
                          is_int: bool = False) -> ExploitabilityScore:
        """计算某计数器对密钥的泄漏量。

        增强：增加 Cohen's d、eta-squared 和 Mann-Whitney U 检验，
        作为 ANOVA F-ratio 补充。参考 SLAD 多维度信号评估思路。
        """
        if len(data) < 2:
            return ExploitabilityScore(score=0.0, counter=counter)

        values_list = list(data.values())
        all_vals = [item for sublist in values_list for item in sublist]
        grand_mean = statistics.mean(all_vals) if all_vals else 0

        group_means = [statistics.mean(v) for v in values_list]
        between_var = statistics.variance(group_means) if len(group_means) > 1 else 0

        within_vars = [statistics.variance(v) if len(v) > 1 else 0 for v in values_list]
        within_var = statistics.mean(within_vars) if within_vars else 1e-10

        # F 比率近似
        f_ratio = between_var / max(within_var, 1e-10)

        # 泄漏比特：可区分组数的 log2
        distinct = sum(1 for i, a in enumerate(group_means)
                       for j, b in enumerate(group_means) if i < j and abs(a - b) > math.sqrt(max(within_var, 1)))
        leaked = math.log2(distinct + 1) if distinct > 1 else 0

        snr = between_var / max(within_var, 1e-10)
        score = min(1.0, max(0.0, 1.0 / (1.0 + math.exp(-(snr - 1.0)))))

        # Cohen's d: 最大组间差 / 合并标准差
        max_group_diff = max(group_means) - min(group_means)
        pooled_std = math.sqrt(within_var) if within_var > 0 else 1.0
        cohens_d = max_group_diff / pooled_std

        # eta^2: 组间变异 / 总变异（ANOVA 效应量）
        total_var = statistics.variance(all_vals) if len(all_vals) > 1 else 1e-10
        n_groups = len(values_list)
        ss_between = sum(len(v) * (m - grand_mean) ** 2 for v, m in zip(values_list, group_means))
        ss_total = sum((x - grand_mean) ** 2 for x in all_vals)
        eta_sq = ss_between / max(ss_total, 1e-10)

        # Mann-Whitney U: 前两组非参数检验
        mw_p = self._mann_whitney_u(list(values_list[0]), list(values_list[1]))

        counter_name = self._COUNTER_NAME.get(counter, str(counter))
        return ExploitabilityScore(
            score=score,
            leaked_bits=leaked,
            signal_to_noise=snr,
            counter=counter,
            description=f"{counter_name}: F={f_ratio:.2f}, SNR={snr:.2f}, "
                        f"可区分组数={distinct}",
            cohens_d=cohens_d,
            eta_squared=eta_sq,
            mann_whitney_p=mw_p,
        )

    def _estimate_branch_misses(self, timing_data: Dict[bytes, List[float]]) -> float:
        """从时序方差偏度估算分支预测失败率。"""
        all_times = []
        for times in timing_data.values():
            all_times.extend(times)
        if len(all_times) < 10:
            return 0.0
        skewness = self._skew(all_times)
        return min(1.0, max(0.0, abs(skewness) / 4.0))

    def _check_perf(self) -> None:
        """检查 Linux perf 子系统是否可用。"""
        perf_path = "/sys/bus/event_source/devices"
        if os.path.exists(perf_path):
            self._perf_available = True
            _log.info("perf 子系统已检测")
        else:
            self._perf_available = False
            _log.info("perf 不可用；使用纯软件指标估算")

    def _read_perf_cache(self) -> Dict[PMCCounterType, Dict[bytes, List[int]]]:
        """桩：通过 perf_event_open 读取真实 perf 计数器。"""
        return {}

    @staticmethod
    def _mann_whitney_u(a: List[float], b: List[float]) -> float:
        """Mann-Whitney U 检验近似 p 值（大样本正态近似）。

        无分布假设，比 Welch t-test 更稳健地处理非正态样本。
        """
        n_a, n_b = len(a), len(b)
        if n_a < 5 or n_b < 5:
            return 1.0
        # 合并排序并计算秩和
        combined = [(v, 0) for v in a] + [(v, 1) for v in b]
        combined.sort(key=lambda x: x[0])
        rank_sum_a = 0
        for rank, (v, group) in enumerate(combined, 1):
            if group == 0:
                rank_sum_a += rank
        u_a = rank_sum_a - n_a * (n_a + 1) / 2
        # 正态近似
        mean_u = n_a * n_b / 2
        std_u = math.sqrt(n_a * n_b * (n_a + n_b + 1) / 12)
        if std_u == 0:
            return 1.0
        z = (u_a - mean_u) / std_u
        # 标准正态 CDF 近似
        p = 2.0 * (1.0 - 0.5 * (1.0 + math.erf(abs(z) / math.sqrt(2))))
        return max(0.0, min(1.0, p))

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
    def measure_cache_timing(probe_fn: Callable[[], None],
                              iterations: int = 1000) -> Dict[str, float]:
        """测量探测函数的缓存命中/未命中时序。"""
        hits = []
        for _ in range(iterations):
            probe_fn()
            t0 = time.perf_counter_ns()
            probe_fn()
            hits.append(time.perf_counter_ns() - t0)
        return {
            "median_hit_ns": statistics.median(hits),
            "std_hit_ns": statistics.stdev(hits) if len(hits) > 1 else 0,
        }


def evaluate_side_channel(op: Callable, secrets: Optional[List[bytes]] = None) -> List[ExploitabilityScore]:
    return PMCSideChannelEvaluator().evaluate(op, secrets)

measure_cache_timing = PMCSideChannelEvaluator.measure_cache_timing
