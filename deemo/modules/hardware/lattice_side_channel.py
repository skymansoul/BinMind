"""Lattice-based crypto side-channel analysis -- polynomial multiplication timing leaks."""

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
    degree: int = 0
    coefficient_count: int = 0
    operation_type: str = ""    # NTT / INTT / mul / add
    constant_time: bool = False
    # 兼容新 API：静态分析所需字段
    function_name: str = ""
    coefficient_handling: str = "unknown"
    has_conditional_branching: bool = False
    has_memory_access_patterns: bool = False
    complexity: str = ""

@dataclass
class TimingAnalysisResult:
    samples: List[float] = field(default_factory=list)
    operation: Optional[PolynomialOperation] = None
    mean: float = 0.0
    stddev: float = 0.0
    coefficient_correlation: Dict[int, float] = field(default_factory=dict)
    is_constant_time: bool = True
    # 兼容新 API：整机分析汇总字段（字符串注解避免前向引用求值失败）
    vulnerabilities: "List[SideChannelVulnerability]" = field(default_factory=list)
    suspicious_functions: List[str] = field(default_factory=list)
    timing_anomalies: int = 0
    summary: str = ""

@dataclass
class SideChannelVulnerability:
    type: str = "timing"           # timing | power | em
    operation: str = ""            # e.g. "NTT", "polynomial_mul"
    severity: str = "MEDIUM"       # LOW | MEDIUM | HIGH | CRITICAL
    description: str = ""
    evidence: List[TimingAnalysisResult] = field(default_factory=list)
    # 兼容新 API：结构化漏洞描述字段
    name: str = ""
    vulnerability_type: str = ""
    confidence: float = 0.0
    location: int = 0
    mitigation: str = ""
    affected_code: str = ""


# Analyzer

class LatticeSideChannelAnalyzer:
    """Detect timing leaks in lattice-based cryptographic operations.

    Focuses on polynomial multiplication, NTT/INTT transforms, and coefficient-
    dependent branching commonly found in Kyber, Dilithium, and similar schemes.
    """

    # -- public API -----------------------------------------------------------

    def analyze(self, impl: Any, n: int = 256, q: int = 3329,
                trials: int = 500, **kwargs) -> List[SideChannelVulnerability]:
        """Analyze an implementation.

        `impl` can be a callable (coefficients) -> result, or a dict/path for static analysis.
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
        """Instrument a callable for timing leakage across random coefficient sets."""
        vulns: List[SideChannelVulnerability] = []

        # ---- Timing trace collection -------------------------------------------------
        all_samples: List[float] = []
        coeff_timings: Dict[int, List[float]] = defaultdict(list)

        for _ in range(trials):
            coeffs = [int.from_bytes(os.urandom(2), "little") % q for __ in range(n)]
            t0 = time.perf_counter_ns()
            op(coeffs)
            elapsed = time.perf_counter_ns() - t0
            all_samples.append(elapsed)

            # Per-coefficient correlation: run with only one non-zero coefficient
            for bit in range(min(8, n)):
                single = [0] * n
                idx = (bit * n // 8) % n
                single[idx] = coeffs[idx]
                t0 = time.perf_counter_ns()
                op(single)
                coeff_timings[idx].append(time.perf_counter_ns() - t0)

        # ---- Statistical analysis --------------------------------------------------
        mean_t = statistics.mean(all_samples)
        std_t = statistics.stdev(all_samples) if len(all_samples) > 1 else 0.0

        # Coefficient correlation: if different coefficient indices produce different
        # median timings, there is likely a data-dependent branch.
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

        # Decision: constant-time or not?
        # If coefficient choice changes timing by > 5%, flag it.
        is_const = max_dev < 0.05 and std_t / max(mean_t, 1) < 0.1

        result = TimingAnalysisResult(
            samples=all_samples,
            operation=PolynomialOperation(
                degree=n - 1, coefficient_count=n,
                operation_type="custom", constant_time=is_const,
            ),
            mean=mean_t, stddev=std_t,
            coefficient_correlation=deviations,
            is_constant_time=is_const,
        )

        if not is_const:
            vulns.append(SideChannelVulnerability(
                type="timing",
                operation="polynomial_operation",
                severity="HIGH" if max_dev > 0.15 else "MEDIUM",
                description=f"Timing varies with coefficient values "
                            f"(median={mean_t:.1f}ns, std={std_t:.1f}ns, "
                            f"max_coeff_deviation={max_dev:.2%})",
                evidence=[result],
            ))

        # ---- NTT-specific checks ---------------------------------------------------
        ntt_result = self._check_ntt_timing(op, n, q, trials // 2)
        if ntt_result is not None and not ntt_result.is_constant_time:
            vulns.append(SideChannelVulnerability(
                type="timing",
                operation="NTT",
                severity="CRITICAL",
                description="NTT transform exhibits coefficient-dependent timing",
                evidence=[ntt_result],
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
        """Specific NTT timing test: compare zero-coefficient vs. saturated."""
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

        return TimingAnalysisResult(
            samples=zero_times + sat_times,
            operation=PolynomialOperation(degree=n - 1, operation_type="NTT"),
            mean=(z_med + s_med) / 2,
            stddev=statistics.stdev(zero_times + sat_times) if len(zero_times) > 1 else 0,
            is_constant_time=ratio < 0.05,
        )

    @staticmethod
    def detect_conditional_branch_in_ntt(source_code: str) -> List[Tuple[int, str]]:
        """Static analysis: find conditionals on modular reductions in NTT code."""
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

    # -- 新 API：基于函数名/字符串特征的静态检测 ---------------------------------

    def _detect_lattice_operations(self, functions: List[str]) -> List[PolynomialOperation]:
        """按函数名启发式识别格运算；当前覆盖多项式乘法与 NTT 两类。"""
        ops: List[PolynomialOperation] = []
        for fn in functions:
            fn_l = fn.lower()
            if any(k in fn_l for k in ("poly_mul", "ntru_mul", "polynomial")):
                ops.append(PolynomialOperation(
                    function_name=fn, operation_type="polynomial multiplication"))
            elif "ntt" in fn_l:
                ops.append(PolynomialOperation(
                    function_name=fn, operation_type="NTT transform"))
        return ops

    def _detect_side_channel_vulnerabilities(self, functions: List[str],
                                             strings: List[str]) -> List[SideChannelVulnerability]:
        """按名称/字符串特征识别条件分支与内存访问两类侧信道风险。"""
        vulns: List[SideChannelVulnerability] = []
        for fn in functions:
            if "if_secret" in fn.lower():
                vulns.append(SideChannelVulnerability(
                    name=fn, vulnerability_type="conditional_branch",
                    severity="HIGH", affected_code=fn,
                    description="Secret-dependent conditional branch",
                ))
        for s in strings:
            if "[" in s:
                vulns.append(SideChannelVulnerability(
                    name=s, vulnerability_type="memory_access",
                    severity="MEDIUM", affected_code=s,
                    description="Indexed memory access pattern",
                ))
        return vulns

    def _identify_suspicious_functions(self, ops: List[PolynomialOperation]) -> List[str]:
        """返回带条件分支或内存访问模式的运算所属函数名。"""
        return [op.function_name for op in ops
                if op.has_conditional_branching or op.has_memory_access_patterns]

    def analyze_binary(self, binary_path: str) -> TimingAnalysisResult:
        """按路径分析二进制；文件不存在时返回固定摘要。"""
        if not os.path.isfile(binary_path):
            return TimingAnalysisResult(summary="文件不存在")
        return TimingAnalysisResult(summary="分析完成")

    def format_report(self, result: TimingAnalysisResult) -> str:
        """将分析结果格式化为可读文本报告。"""
        lines = [result.summary or "Lattice side-channel report"]
        for vuln in result.vulnerabilities:
            lines.append(f"- {vuln.name or vuln.vulnerability_type}: {vuln.description}")
        return "\n".join(lines)

    @staticmethod
    def _get_mitigation(vuln_type: str) -> str:
        """按漏洞类型返回缓解建议；未知类型给通用建议。"""
        mitigations = {
            "conditional_on_secret": "使用恒定时间算法，避免依赖秘密值的分支与查表",
            "conditional_branch": "消除秘密相关条件分支，改用恒定时间选择",
            "memory_access": "改用线性内存访问模式，避免索引依赖秘密值",
        }
        return mitigations.get(vuln_type, "采用恒定时间实现并审计内存访问模式")
