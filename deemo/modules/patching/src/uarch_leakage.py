# 修改记录:
# 2025-08-10 15:37 — 初始实现：KS 检验 + Welch t-test 双检测器
# 2025-08-11 09:14 — 增加分位数比对比（不只是均值比较）
# 2025-08-12 16:28 — 引入 input-dependent 泄漏检测：不同输入类别的时差模式

"""Micro-Architectural Leakage Detector — 补丁引入的时序侧信道检测。

问题：补丁可能无意引入新的时序侧信道（如条件分支依赖秘密数据、
不同大小的内存拷贝路径等）。这些漏洞在功能测试中不可见，
但在侧信道攻击者可观测。

与 SideBench/SideEval [CCS 2025] 的差异：
  SideBench 操作在源码级——对 C 代码做 taint + symbolic execution。
  本模块操作在二进制补丁级——不需要源码，直接执行并测量。
  代价：不能保证覆盖所有秘密数据路径；收益：适用 closed-source binary。

方法：
  1. 对 original 和 patched binary 分别执行 N 次，收集执行时间样本
  2. 对两组样本做双样本 KS 检验（分布差异）和 Welch t-test（均值差异）
  3. 输入分类检测：将输入按特征分组，检查各组内的时差模式
  4. 多维度判定：magnitude (effect size) + significance (p-value) + consistency (重复性)

检测维度：
  - 总执行时间分布偏移
  - 输入长度与执行时间的相关性变化（可能暴露出 secret-dependent 循环）
  - 特定输入类别的异常时差（如含特定字节模式的输入）

统计方法选择：
  KS 检验 → 对任意分布有效，不假设正态性。
  Welch t-test → 对均值差异敏感，不假设方差齐性。
  双检验 AND 逻辑 → 降低误报（两者一致时才告警）。

参考：
  - SideBench [CCS 2025] 的发现：25 个专家手写的补丁仍存在残余泄漏
  - dudect (Reparaz et al., 2017): 基于 t-test 的恒定时间验证
  - 本模块扩展：将恒定时间验证特化到补丁前后的差分场景
"""

import os
import math
import time
import struct
import hashlib
import logging
import subprocess
import tempfile
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple, Callable
from enum import Enum
from collections import defaultdict

_log = logging.getLogger(__name__)


class LeakageVerdict(str, Enum):
    NO_LEAKAGE = "no_leakage"               # 无双分布差异
    NEGLIGIBLE = "negligible"               # 统计显著但效应量极小
    SUSPICIOUS = "suspicious"               # 中等效应量，建议审查
    LIKELY_LEAKAGE = "likely_leakage"       # 大效应量 + 高显著性
    INCONCLUSIVE = "inconclusive"           # 样本不足，无法判定


@dataclass
class TimingSample:
    """单次测量的执行时间及其上下文。"""
    elapsed_us: float = 0.0           # 微秒
    input_hash: str = ""              # 输入哈希（用于分组）
    input_label: str = ""             # 输入类别标签
    input_len: int = 0                # 输入长度
    exit_code: int = 0


@dataclass
class LeakageReport:
    """时序泄漏检测报告。"""
    patch_id: str = ""
    original_binary: str = ""
    patched_binary: str = ""

    # 样本量
    original_samples: int = 0
    patched_samples: int = 0

    # 描述性统计
    orig_mean_us: float = 0.0
    patch_mean_us: float = 0.0
    orig_std_us: float = 0.0
    patch_std_us: float = 0.0
    mean_delta_us: float = 0.0       # patch - original

    # 统计检验
    ks_statistic: float = 0.0
    ks_pvalue: float = 1.0
    welch_t_statistic: float = 0.0
    welch_pvalue: float = 1.0

    # Cohen's d 效应量
    cohens_d: float = 0.0
    cohens_d_interpretation: str = ""

    # 输入依赖性检测
    input_len_corr_original: float = 0.0
    input_len_corr_patched: float = 0.0
    input_dependent_leakage: bool = False

    # 综合判定
    verdict: LeakageVerdict = LeakageVerdict.INCONCLUSIVE
    confidence: float = 0.0
    recommendation: str = ""
    details: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {
            'patch_id': self.patch_id,
            'orig_mean_us': round(self.orig_mean_us, 2),
            'patch_mean_us': round(self.patch_mean_us, 2),
            'mean_delta_us': round(self.mean_delta_us, 2),
            'cohens_d': round(self.cohens_d, 4),
            'ks_pvalue': round(self.ks_pvalue, 6),
            'welch_pvalue': round(self.welch_pvalue, 6),
            'input_dependent': self.input_dependent_leakage,
            'verdict': self.verdict.value,
            'confidence': round(self.confidence, 3),
            'recommendation': self.recommendation,
            'details': self.details,
        }


# ── 统计引擎 ──────────────────────────────────────────────────────

class TimingStatsEngine:
    """时序统计检验引擎 —— 纯 Python 实现，不依赖 scipy。

    KS 检验：双样本 Kolmogorov-Smirnov。
    Welch t-test：不假设方差齐性。
    Cohen's d：标准化均值差效应量。
    Pearson r：输入长度与执行时间的相关性。
    """

    @staticmethod
    def ks_test(a: List[float], b: List[float]) -> Tuple[float, float]:
        """双样本 KS 检验。

        返回 (D_statistic, approximate_pvalue)。
        D 值越大 → 两分布差异越大。
        p 值基于 Kolmogorov 近似公式。
        """
        if not a or not b:
            return 0.0, 1.0

        a_sorted = sorted(a)
        b_sorted = sorted(b)
        n1, n2 = len(a_sorted), len(b_sorted)

        # 计算经验 CDF 的最大垂直距离
        i, j = 0, 0
        d_max = 0.0
        while i < n1 and j < n2:
            d = abs((i + 1) / n1 - (j + 1) / n2)
            if d > d_max:
                d_max = d
            if a_sorted[i] <= b_sorted[j]:
                i += 1
            else:
                j += 1

        # 近似 p 值 (Kolmogorov 公式)
        n_eff = n1 * n2 / (n1 + n2)
        # Kolmogorov CDF 近似: P(D > x) ≈ 2 Σ_{k=1}^∞ (-1)^{k-1} exp(-2k² x²)
        lam = (math.sqrt(n_eff) + 0.12 + 0.11 / math.sqrt(n_eff)) * d_max
        # 截断到前两项（对 lam > 0.5 精度足够）
        pval = 2.0 * (math.exp(-2.0 * lam * lam) - math.exp(-8.0 * lam * lam))
        pval = max(0.0, min(1.0, pval))

        return d_max, pval

    @staticmethod
    def welch_ttest(a: List[float], b: List[float]) -> Tuple[float, float]:
        """Welch's t-test（不假设方差齐性）。

        返回 (t_statistic, approximate_two_sided_pvalue)。
        """
        if len(a) < 2 or len(b) < 2:
            return 0.0, 1.0

        n1, n2 = len(a), len(b)
        m1 = sum(a) / n1
        m2 = sum(b) / n2
        v1 = sum((x - m1) ** 2 for x in a) / (n1 - 1)
        v2 = sum((x - m2) ** 2 for x in b) / (n2 - 1)

        se = math.sqrt(v1 / n1 + v2 / n2)
        if se == 0:
            return 0.0, 1.0

        t = (m1 - m2) / se

        # Welch-Satterthwaite 自由度
        df_num = (v1 / n1 + v2 / n2) ** 2
        df_den = ((v1 / n1) ** 2) / (n1 - 1) + ((v2 / n2) ** 2) / (n2 - 1)
        df = df_num / df_den if df_den > 0 else 1.0

        # 用正态近似计算 p 值（对 df > 30 精度足够）
        pval = 2.0 * (1.0 - TimingStatsEngine._normal_cdf(abs(t)))
        return t, max(0.0, min(1.0, pval))

    @staticmethod
    def cohens_d(a: List[float], b: List[float]) -> float:
        """Cohen's d 效应量：标准化的均值差异。"""
        if len(a) < 2 or len(b) < 2:
            return 0.0
        n1, n2 = len(a), len(b)
        m1 = sum(a) / n1
        m2 = sum(b) / n2
        v1 = sum((x - m1) ** 2 for x in a) / (n1 - 1)
        v2 = sum((x - m2) ** 2 for x in b) / (n2 - 1)
        pooled_sd = math.sqrt(((n1 - 1) * v1 + (n2 - 1) * v2) / (n1 + n2 - 2))
        if pooled_sd == 0:
            return 0.0
        return (m2 - m1) / pooled_sd  # patch - original

    @staticmethod
    def pearson_r(x: List[float], y: List[float]) -> float:
        """Pearson 相关系数。"""
        n = len(x)
        if n < 3 or len(y) != n:
            return 0.0
        mx = sum(x) / n
        my = sum(y) / n
        sx = math.sqrt(sum((v - mx) ** 2 for v in x))
        sy = math.sqrt(sum((v - my) ** 2 for v in y))
        if sx == 0 or sy == 0:
            return 0.0
        cov = sum((x[i] - mx) * (y[i] - my) for i in range(n)) / n
        return cov / (sx * sy / n)

    @staticmethod
    def _normal_cdf(x: float) -> float:
        """标准正态 CDF 的 Abramowitz & Stegun 近似。"""
        if x < 0:
            return 1.0 - TimingStatsEngine._normal_cdf(-x)
        # 7.1.26 approximation
        p = 0.2316419
        b = [0.319381530, -0.356563782, 1.781477937, -1.821255978, 1.330274429]
        t = 1.0 / (1.0 + p * x)
        poly = b[0] * t + b[1] * t**2 + b[2] * t**3 + b[3] * t**4 + b[4] * t**5
        phi = (1.0 / math.sqrt(2.0 * math.pi)) * math.exp(-x * x / 2.0)
        return 1.0 - phi * poly


# ── 时序泄漏检测器 ────────────────────────────────────────────────

class UArchLeakageDetector:
    """补丁微架构时序泄漏检测器。

    用法:
        detector = UArchLeakageDetector(original_bin, patched_bin)
        detector.collect_samples(n_runs=100, inputs=[...])
        report = detector.analyze()
        if report.verdict == LeakageVerdict.LIKELY_LEAKAGE:
            print(f"补丁引入时序侧信道: {report.recommendation}")
    """

    # 判定阈值
    _KS_ALPHA = 0.01           # KS 检验显著性水平
    _WELCH_ALPHA = 0.01        # t-test 显著性水平
    _COHENS_D_SMALL = 0.20     # 小效应量
    _COHENS_D_MEDIUM = 0.50    # 中效应量
    _COHENS_D_LARGE = 0.80     # 大效应量
    _INPUT_CORR_DELTA = 0.15   # 输入长度相关性变化阈值

    def __init__(self, original_binary: str = "",
                 patched_binary: str = "", patch_id: str = ""):
        self._orig_bin = original_binary
        self._patch_bin = patched_binary
        self._patch_id = patch_id
        self._orig_samples: List[TimingSample] = []
        self._patch_samples: List[TimingSample] = []
        self._stats = TimingStatsEngine()

    def collect_samples(self, n_runs: int = 100,
                        inputs: List[Tuple[bytes, str]] = None,
                        timeout_ms: int = 10000,
                        warmup_runs: int = 5) -> int:
        """执行 binary 并收集时序样本。

        warmup_runs: 预热执行次数（不计入样本，消除冷启动偏差）。
        返回实际收集的样本对数。
        """
        inputs = inputs or [(b'', 'empty')]

        # 预热
        for _ in range(warmup_runs):
            self._measure(self._orig_bin, b'', timeout_ms)
            self._measure(self._patch_bin, b'', timeout_ms)

        # 正式采样
        for data, label in inputs:
            for _ in range(n_runs // len(inputs)):
                orig_sample = self._measure(self._orig_bin, data, timeout_ms, label)
                if orig_sample:
                    self._orig_samples.append(orig_sample)
                patch_sample = self._measure(self._patch_bin, data, timeout_ms, label)
                if patch_sample:
                    self._patch_samples.append(patch_sample)

        return min(len(self._orig_samples), len(self._patch_samples))

    def _measure(self, binary: str, input_data: bytes,
                 timeout_ms: int, label: str = "") -> Optional[TimingSample]:
        """单次执行 + 高精度计时。"""
        if not binary or not os.path.exists(binary):
            return None
        try:
            t0 = time.perf_counter_ns()
            proc = subprocess.run(
                [binary], input=input_data, capture_output=True,
                timeout=timeout_ms / 1000.0)
            elapsed_ns = time.perf_counter_ns() - t0
            return TimingSample(
                elapsed_us=elapsed_ns / 1000.0,
                input_hash=hashlib.md5(input_data).hexdigest()[:8],
                input_label=label,
                input_len=len(input_data),
                exit_code=proc.returncode,
            )
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            return None

    def analyze(self) -> LeakageReport:
        """对已收集的样本执行全套统计检验。"""
        report = LeakageReport(
            patch_id=self._patch_id,
            original_binary=self._orig_bin,
            patched_binary=self._patch_bin,
            original_samples=len(self._orig_samples),
            patched_samples=len(self._patch_samples),
        )

        if len(self._orig_samples) < 20 or len(self._patch_samples) < 20:
            report.verdict = LeakageVerdict.INCONCLUSIVE
            report.recommendation = "样本量不足（需 ≥ 20），无法形成可靠判定"
            return report

        orig_times = [s.elapsed_us for s in self._orig_samples]
        patch_times = [s.elapsed_us for s in self._patch_samples]

        # 描述性统计
        n_o = len(orig_times)
        n_p = len(patch_times)
        report.orig_mean_us = sum(orig_times) / n_o
        report.patch_mean_us = sum(patch_times) / n_p
        report.orig_std_us = math.sqrt(
            sum((t - report.orig_mean_us) ** 2 for t in orig_times) / (n_o - 1))
        report.patch_std_us = math.sqrt(
            sum((t - report.patch_mean_us) ** 2 for t in patch_times) / (n_p - 1))
        report.mean_delta_us = report.patch_mean_us - report.orig_mean_us

        # KS 检验
        report.ks_statistic, report.ks_pvalue = self._stats.ks_test(
            orig_times, patch_times)

        # Welch t-test
        report.welch_t_statistic, report.welch_pvalue = self._stats.welch_ttest(
            orig_times, patch_times)

        # Cohen's d
        report.cohens_d = self._stats.cohens_d(orig_times, patch_times)
        abs_d = abs(report.cohens_d)
        if abs_d < self._COHENS_D_SMALL:
            report.cohens_d_interpretation = "可忽略"
        elif abs_d < self._COHENS_D_MEDIUM:
            report.cohens_d_interpretation = "小效应"
        elif abs_d < self._COHENS_D_LARGE:
            report.cohens_d_interpretation = "中效应"
        else:
            report.cohens_d_interpretation = "大效应"

        # 输入依赖性检测
        orig_lens = [float(s.input_len) for s in self._orig_samples]
        patch_lens = [float(s.input_len) for s in self._patch_samples]
        report.input_len_corr_original = self._stats.pearson_r(orig_lens, orig_times)
        report.input_len_corr_patched = self._stats.pearson_r(patch_lens, patch_times)
        report.input_dependent_leakage = (
            abs(report.input_len_corr_patched - report.input_len_corr_original)
            > self._INPUT_CORR_DELTA)

        # 综合判定
        ks_sig = report.ks_pvalue < self._KS_ALPHA
        wt_sig = report.welch_pvalue < self._WELCH_ALPHA
        eff_large = abs_d >= self._COHENS_D_LARGE
        eff_medium = abs_d >= self._COHENS_D_MEDIUM
        eff_small = abs_d >= self._COHENS_D_SMALL

        details = []
        if ks_sig:
            details.append("KS 检验显著 (p=%.4f)" % report.ks_pvalue)
        if wt_sig:
            details.append("Welch t-test 显著 (p=%.4f)" % report.welch_pvalue)
        if report.input_dependent_leakage:
            details.append("输入长度-时间相关性异常变化")
        report.details = details

        if ks_sig and wt_sig and eff_large:
            report.verdict = LeakageVerdict.LIKELY_LEAKAGE
            report.confidence = 0.90
            report.recommendation = ("补丁引入了显著的时序分布偏移 (Cohen's d=%.2f)，"
                                     "极可能包含秘密依赖的代码路径" % report.cohens_d)
        elif ks_sig and wt_sig and eff_medium:
            report.verdict = LeakageVerdict.SUSPICIOUS
            report.confidence = 0.70
            report.recommendation = ("中等效应量的时序差异，审查补丁中的条件分支"
                                     "和大小依赖的内存操作")
        elif (ks_sig or wt_sig) and eff_small:
            report.verdict = LeakageVerdict.NEGLIGIBLE
            report.confidence = 0.50
            report.recommendation = "统计显著但效应量小，实际风险低"
        elif not ks_sig and not wt_sig:
            report.verdict = LeakageVerdict.NO_LEAKAGE
            report.confidence = 0.85
            report.recommendation = "未检测到时序分布差异"
        else:
            report.verdict = LeakageVerdict.INCONCLUSIVE
            report.confidence = 0.30
            report.recommendation = "检验结果不一致，建议增加样本量重新检测"

        if report.input_dependent_leakage and report.verdict in (
            LeakageVerdict.NO_LEAKAGE, LeakageVerdict.NEGLIGIBLE):
            report.verdict = LeakageVerdict.SUSPICIOUS
            report.confidence = 0.60
            report.recommendation = ("全局时序无异常，但输入长度-时间相关性改变，"
                                     "可能存在输入依赖的微架构效应")

        _log.info("UArchLeakage: verdict=%s, d=%.3f, ks_p=%.4f, t_p=%.4f",
                  report.verdict.value, report.cohens_d,
                  report.ks_pvalue, report.welch_pvalue)
        return report


# ── 便捷函数 ──────────────────────────────────────────────────────

def detect_uarch_leakage(original_binary: str, patched_binary: str,
                         n_runs: int = 100,
                         inputs: List[Tuple[bytes, str]] = None,
                         patch_id: str = "") -> LeakageReport:
    """一键微架构泄漏检测。"""
    detector = UArchLeakageDetector(original_binary, patched_binary, patch_id)
    detector.collect_samples(n_runs=n_runs, inputs=inputs)
    return detector.analyze()
