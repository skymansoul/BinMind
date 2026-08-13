"""Timing side-channel detector -- constant-time violation identification."""

import dis
import logging
import math
import statistics
import os
import struct
import time
import types
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List

_log = logging.getLogger(__name__)


class TimingIssueSeverity:
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    def __init__(self, value=None):
        self.value = value or self.MEDIUM


class TimingIssueType:
    CONSTANT_TIME_VIOLATION = "constant_time_violation"
    CACHE_TIMING = "cache_timing"
    BRANCH_TIMING = "branch_timing"
    DATA_DEPENDENT_LOOP = "data_dependent_loop"
    UNBALANCED_PATH = "unbalanced_path"
    KEY_DEPENDENT_BRANCH = "key_dependent_branch"
    SECRET_LOOP_BOUNDARY = "secret_loop_boundary"
    UNMASKED_LOOKUP = "unmasked_lookup"
    SECRET_COMPARISON = "secret_comparison"


@dataclass
class TimingAnalysisResult:
    samples: List[float] = field(default_factory=list)
    issue_type: str = ""
    severity: str = TimingIssueSeverity.MEDIUM
    function_name: str = ""
    file_path: str = ""
    line_number: int = 0
    description: str = ""
    error_message: str = ""
    p_value: float = 1.0

    @property
    def type(self):
        # 兼容别名：测试与调用方按规范名 type 读取，实现字段为 issue_type
        return self.issue_type
    t_statistic: float = 0.0
    # 聚合分析结果字段（analyze 路径使用）
    analysis_success: bool = True
    issues: List[Any] = field(default_factory=list)
    analyzed_functions: List[str] = field(default_factory=list)
    binary_path: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            'binary_path': self.binary_path,
            'analysis_success': self.analysis_success,
            'issues': [
                {
                    'type': i.type if hasattr(i, 'type') else i.issue_type,
                    'severity': i.severity if hasattr(i, 'severity') else 'medium',
                    'description': i.description if hasattr(i, 'description') else '',
                    'line_number': i.line_number if hasattr(i, 'line_number') else 0,
                }
                for i in self.issues
            ],
            'analyzed_functions': list(self.analyzed_functions),
        }


class _PreciseTimer:
    def __init__(self):
        self._start = 0

    def start(self) -> None:
        self._start = time.perf_counter_ns()

    def elapsed_ns(self) -> int:
        return time.perf_counter_ns() - self._start

    @staticmethod
    def measure(fn: Callable, iterations: int = 5) -> float:
        times = []
        for _ in range(iterations):
            t0 = time.perf_counter_ns()
            fn()
            times.append(time.perf_counter_ns() - t0)
        return float(statistics.median(times))


class TimingSideChannelDetector:
    """Instrument code to detect secret-dependent timing variations.

    Supports Python bytecode analysis, runtime timing comparison, and C-source
    static analysis.

    Usage::

        detector = TimingSideChannelDetector()
        results = detector.detect(my_crypto_func, secrets=[0, 255])
    """

    _CONSTANT_TIME_OPS = {
        "COMPARE_OP", "IS_OP", "CONTAINS_OP", "POP_JUMP_IF_TRUE",
        "POP_JUMP_IF_FALSE", "JUMP_IF_TRUE_OR_POP", "JUMP_IF_FALSE_OR_POP",
        "FOR_ITER", "JUMP_FORWARD", "JUMP_ABSOLUTE",
    }

    _SECRET_DEPENDENT_PATTERNS = {
        "memory comparison loop": [
            r"if.*memcmp", r"if.*strcmp", r"if.*strncmp",
            r"for.*strcmp", r"while.*memcmp",
        ],
        "lookup table index": [
            r"(\w+)\[.*\b(secret|key|password|token)\b",
            r"sbox\[.*\]",
            r"table\[.*\b(input|key)\b",
        ],
        "conditional on secret": [
            r"if\s*\(.*\b(secret|key|nonce|iv)\b",
            r"if\s*\(.*\b(input|data)\[",
        ],
        "early exit on mismatch": [
            r"if\s*\(.*!=\s*.*\).*return",
            r"if\s*\(.*!=\s*.*\).*break",
        ],
    }

    def __init__(self, binary_path: str = ""):
        self._timer = _PreciseTimer()
        self.binary_path = binary_path

    def analyze(self, pseudocode: str = None) -> TimingAnalysisResult:
        """对反编译伪代码或 C 源码做静态侧信道分析。

        按密钥依赖分支、秘密循环边界、未掩码查表、秘密比较
        四类模式识别问题；无输入时仅校验路径有效性。
        """
        import re as _re
        result = TimingAnalysisResult(binary_path=self.binary_path)
        if self.binary_path and not os.path.exists(self.binary_path):
            result.analysis_success = False
            result.description = '无效的文件路径: ' + self.binary_path
            result.error_message = result.description
            return result

        source = pseudocode or ''
        issues: List[TimingAnalysisResult] = []

        # 密钥依赖分支：if 内比较 key/secret/input 后提前返回
        key_branch = [
            (r'if\s*\([^)]*\b(?:key|secret|input|pin|password|stored|expected)\b[^)]*[!=]=?[^)]*\)', '密钥依赖分支'),
            (r'if\s*\([^)]*\[[^\]]*\]\s*[!=]=?\s*[^)]*\)', '索引依赖分支'),
        ]
        for lineno, line in enumerate(source.split('\n'), 1):
            for pat, desc in key_branch:
                if _re.search(pat, line):
                    issues.append(TimingAnalysisResult(
                        issue_type=TimingIssueType.KEY_DEPENDENT_BRANCH,
                        severity=TimingIssueSeverity.HIGH,
                        line_number=lineno,
                        description=desc + ': ' + line.strip()[:80],
                    ))
                    break

        # 秘密循环边界：循环上限依赖 secret_len/secret
        for lineno, line in enumerate(source.split('\n'), 1):
            if _re.search(r'(?:for|while)\s*\([^)]*\b(?:secret_len|key_len|len|count|size)\b', line):
                issues.append(TimingAnalysisResult(
                    issue_type=TimingIssueType.SECRET_LOOP_BOUNDARY,
                    severity=TimingIssueSeverity.MEDIUM,
                    line_number=lineno,
                    description='秘密依赖循环边界: ' + line.strip()[:80],
                ))

        # 未掩码查表：sbox/table 以秘密索引
        for lineno, line in enumerate(source.split('\n'), 1):
            if _re.search(r'\b(?:sbox|table|lookup)\s*\[[^]]*\]', line) \
               or _re.search(r'\b(?:sbox|table)\[[^\]]*(?:key|byte|input)\b', line):
                issues.append(TimingAnalysisResult(
                    issue_type=TimingIssueType.UNMASKED_LOOKUP,
                    severity=TimingIssueSeverity.HIGH,
                    line_number=lineno,
                    description='未掩码查表: ' + line.strip()[:80],
                ))

        # 秘密比较：strcmp/memcmp 或逐字节 != 比较
        for lineno, line in enumerate(source.split('\n'), 1):
            if _re.search(r'\b(?:strcmp|memcmp|strncmp|timingsafe)\s*\(', line) \
               or _re.search(r'\[[^\]]*\]\s*!=\s*\[[^\]]*\]', line):
                issues.append(TimingAnalysisResult(
                    issue_type=TimingIssueType.SECRET_COMPARISON,
                    severity=TimingIssueSeverity.HIGH,
                    line_number=lineno,
                    description='秘密比较: ' + line.strip()[:80],
                ))

        result.issues = issues
        result.analysis_success = True
        return result

    def generate_report(self) -> str:
        """生成时间侧信道分析报告文本。"""
        result = self.analyze()
        lines = ['时间侧信道漏洞分析报告', '']
        lines.append(f'目标: {self.binary_path or "(无)"}')
        lines.append('')
        for iss in result.issues:
            lines.append(f"- [{iss.severity}] {iss.issue_type}: {iss.description}")
        if not result.issues:
            lines.append('未发现明显时间侧信道风险')
        return '\n'.join(lines)

    def detect(self, impl: Any, **kwargs) -> List[TimingAnalysisResult]:
        results: List[TimingAnalysisResult] = []

        if callable(impl):
            results.extend(self._analyze_callable_runtime(impl, **kwargs))
            if isinstance(impl, types.FunctionType):
                results.extend(self._analyze_bytecode(impl))
        elif isinstance(impl, str):
            if "\n" in impl or impl.endswith((".c", ".h", ".cpp")):
                results.extend(self._analyze_c_source(impl))
            else:
                try:
                    with open(impl, "r", encoding="utf-8", errors="replace") as fh:
                        results.extend(self._analyze_c_source(fh.read()))
                except OSError:
                    pass

        return results

    def _analyze_callable_runtime(self, op: Callable, **kwargs) -> List[TimingAnalysisResult]:
        secrets = kwargs.get("secrets", [b"\x00" * 16, b"\xFF" * 16])
        trials = kwargs.get("trials", 500)

        if len(secrets) < 2:
            return []

        all_timings: Dict[bytes, List[float]] = defaultdict(list)
        for _ in range(trials):
            for secret in secrets:
                t0 = time.perf_counter_ns()
                op(secret)
                all_timings[secret].append(time.perf_counter_ns() - t0)

        results: List[TimingAnalysisResult] = []
        secret_list = list(all_timings.keys())
        for i in range(len(secret_list)):
            for j in range(i + 1, len(secret_list)):
                a, b = secret_list[i], secret_list[j]
                ta = all_timings[a]
                tb = all_timings[b]

                n1, n2 = len(ta), len(tb)
                m1 = float(statistics.mean(ta))
                m2 = float(statistics.mean(tb))
                v1 = statistics.variance(ta) if n1 > 1 else 0.0
                v2 = statistics.variance(tb) if n2 > 1 else 0.0

                se = math.sqrt(v1 / n1 + v2 / n2)
                t = (m1 - m2) / se if se > 0 else 0

                df_num = (v1 / n1 + v2 / n2) ** 2
                df_den = (v1 / n1) ** 2 / (n1 - 1) + (v2 / n2) ** 2 / (n2 - 1)
                df = df_num / df_den if df_den else 1

                xp = df / (df + t * t)
                p_val = 2.0 * max(0.0, min(0.5, _incomplete_beta_tail(xp, df / 2, 0.5)))

                rel_diff = abs(m1 - m2) / max(1.0, min(m1, m2))

                if abs(t) > 4.5 and rel_diff > 0.10:
                    sev = TimingIssueSeverity.HIGH
                elif abs(t) > 3.0:
                    sev = TimingIssueSeverity.MEDIUM
                else:
                    sev = TimingIssueSeverity.LOW

                issue_type = (TimingIssueType.CONSTANT_TIME_VIOLATION
                              if rel_diff > 0.02 else TimingIssueType.CACHE_TIMING)

                results.append(TimingAnalysisResult(
                    samples=ta + tb,
                    issue_type=issue_type,
                    severity=sev,
                    function_name=getattr(op, "__name__", "unknown"),
                    description=(
                        f"Secret {a[:4].hex()}.. median={m1:.1f}ns vs "
                        f"{b[:4].hex()}.. median={m2:.1f}ns "
                        f"(diff={rel_diff:.2%}, t={t:.2f}, p={p_val:.4f})"
                    ),
                    p_value=p_val,
                    t_statistic=abs(t),
                ))

        return results

    def _analyze_bytecode(self, func: types.FunctionType) -> List[TimingAnalysisResult]:
        try:
            instructions = list(dis.get_instructions(func))
        except Exception:
            return []

        results: List[TimingAnalysisResult] = []
        for inst in instructions:
            if inst.opname in self._CONSTANT_TIME_OPS:
                results.append(TimingAnalysisResult(
                    issue_type=TimingIssueType.BRANCH_TIMING,
                    severity=TimingIssueSeverity.LOW,
                    function_name=func.__name__,
                    line_number=inst.positions.lineno if inst.positions else 0,
                    description=f"Bytecode `{inst.opname}` at offset {inst.offset} "
                                f"may introduce data-dependent timing",
                ))
        return results

    def _analyze_c_source(self, source: str) -> List[TimingAnalysisResult]:
        import re
        results: List[TimingAnalysisResult] = []
        for lineno, line in enumerate(source.split("\n"), 1):
            for category, patterns in self._SECRET_DEPENDENT_PATTERNS.items():
                for pat in patterns:
                    if re.search(pat, line, re.IGNORECASE):
                        sev = (TimingIssueSeverity.HIGH
                               if "conditional" in category or "early exit" in category
                               else TimingIssueSeverity.MEDIUM)
                        issue_type = (TimingIssueType.DATA_DEPENDENT_LOOP
                                      if "loop" in category
                                      else TimingIssueType.BRANCH_TIMING)
                        results.append(TimingAnalysisResult(
                            issue_type=issue_type,
                            severity=sev,
                            line_number=lineno,
                            description=f"[{category}] {line.strip()[:100]}",
                        ))
                        break
        return results


def _incomplete_beta_tail(x: float, a: float, b: float) -> float:
    if a <= 0 or b <= 0:
        return 0.5
    return math.exp(
        math.lgamma(a + b) - math.lgamma(a) - math.lgamma(b) +
        a * math.log(x) + b * math.log(1 - x)
    ) / a
