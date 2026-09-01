"""时序侧信道检测, 常量时间违规识别。"""

import dis
import logging
import math
import statistics
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
    # 新增类型
    COVERT_CHANNEL_AUTOCORRELATED = "covert_channel_autocorrelated"
    CACHE_RESIDENCY_LEAK = "cache_residency_leak"


@dataclass
class TimingAnalysisResult:
    samples: List[float] = field(default_factory=list)
    issue_type: str = ""
    severity: str = TimingIssueSeverity.MEDIUM
    function_name: str = ""
    file_path: str = ""
    line_number: int = 0
    description: str = ""
    p_value: float = 1.0
    t_statistic: float = 0.0
    # 新增度量
    cohens_d: float = 0.0
    js_divergence: float = 0.0
    autocorrelation_lag1: float = 0.0


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


# 统计辅助函数

def _cohens_d(a: List[float], b: List[float]) -> float:
    """Cohen's d 效应量。"""
    n1, n2 = len(a), len(b)
    if n1 < 2 or n2 < 2:
        return 0.0
    m1 = statistics.mean(a)
    m2 = statistics.mean(b)
    v1 = statistics.variance(a)
    v2 = statistics.variance(b)
    pooled = math.sqrt(((n1 - 1) * v1 + (n2 - 1) * v2) / (n1 + n2 - 2))
    return abs(m1 - m2) / max(pooled, 1e-10)


def _autocorr_lag1(samples: List[float]) -> float:
    """一阶自相关系数, 检测时序周期模式（隐蔽定时间隔信道）。"""
    n = len(samples)
    if n < 4:
        return 0.0
    mean = statistics.mean(samples)
    num = sum((samples[i] - mean) * (samples[i + 1] - mean) for i in range(n - 1))
    den = sum((x - mean) ** 2 for x in samples)
    return num / max(den, 1e-10)


def _js_divergence(a: List[float], b: List[float], n_bins: int = 20) -> float:
    """Jensen-Shannon 散度：KL(P||M)/2 + KL(Q||M)/2。"""
    all_vals = a + b
    if not all_vals:
        return 0.0
    nb = min(n_bins, int(math.sqrt(len(a) + len(b))))
    rng = (min(all_vals), max(all_vals))
    if rng[1] - rng[0] < 1.0:
        return 0.0
    width = (rng[1] - rng[0]) / nb

    def _hist(arr):
        h = [0] * nb
        for v in arr:
            idx = min(nb - 1, int((v - rng[0]) / width))
            h[idx] += 1
        s = sum(h) or 1
        return [c / s for c in h]

    pa, pb = _hist(a), _hist(b)
    js = 0.0
    for i in range(nb):
        m = (pa[i] + pb[i]) / 2
        if pa[i] > 0 and m > 0:
            js += pa[i] * math.log2(pa[i] / m)
        if pb[i] > 0 and m > 0:
            js += pb[i] * math.log2(pb[i] / m)
    return js / 2


class TimingSideChannelDetector:
    """插桩代码检测密钥依赖的时序变化。

    支持 Python 字节码分析、运行时时序比对及 C 源码静态分析。

    用法::

        detector = TimingSideChannelDetector()
        results = detector.detect(my_crypto_func, secrets=[0, 255])
    """

    _CONSTANT_TIME_OPS = {
        "COMPARE_OP", "IS_OP", "CONTAINS_OP", "POP_JUMP_IF_TRUE",
        "POP_JUMP_IF_FALSE", "JUMP_IF_TRUE_OR_POP", "JUMP_IF_FALSE_OR_POP",
        "FOR_ITER", "JUMP_FORWARD", "JUMP_ABSOLUTE",
    }

    _SECRET_DEPENDENT_PATTERNS = {
        "内存比较循环": [
            r"if.*memcmp", r"if.*strcmp", r"if.*strncmp",
            r"for.*strcmp", r"while.*memcmp",
        ],
        "查找表索引": [
            r"(\w+)\[.*\b(secret|key|password|token)\b",
            r"sbox\[.*\]",
            r"table\[.*\b(input|key)\b",
        ],
        "密钥条件分支": [
            r"if\s*\(.*\b(secret|key|nonce|iv)\b",
            r"if\s*\(.*\b(input|data)\[",
        ],
        "不匹配提前退出": [
            r"if\s*\(.*!=\s*.*\).*return",
            r"if\s*\(.*!=\s*.*\).*break",
        ],
    }

    def __init__(self):
        self._timer = _PreciseTimer()

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

                # 补充统计指标
                cd_val = _cohens_d(ta, tb)
                js_val = _js_divergence(ta, tb)
                # 自相关：全量样本检测周期性模式
                all_samples = ta + tb
                ac1 = _autocorr_lag1(all_samples)

                # 自相关 > 0.3 → 可能为定时间隔隐蔽信道
                if ac1 > 0.3 and issue_type == TimingIssueType.CACHE_TIMING:
                    issue_type = TimingIssueType.COVERT_CHANNEL_AUTOCORRELATED

                results.append(TimingAnalysisResult(
                    samples=ta + tb,
                    issue_type=issue_type,
                    severity=sev,
                    function_name=getattr(op, "__name__", "unknown"),
                    description=(
                        f"密钥 {a[:4].hex()}.. 中位={m1:.1f}ns vs "
                        f"{b[:4].hex()}.. 中位={m2:.1f}ns "
                        f"(diff={rel_diff:.2%}, t={t:.2f}, p={p_val:.4f})"
                    ),
                    p_value=p_val,
                    t_statistic=abs(t),
                    cohens_d=cd_val,
                    js_divergence=js_val,
                    autocorrelation_lag1=ac1,
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
                    description=f"字节码 `{inst.opname}` 偏移 {inst.offset} "
                                f"可能引入数据依赖时序",
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
                               if "条件" in category or "提前退出" in category
                               else TimingIssueSeverity.MEDIUM)
                        issue_type = (TimingIssueType.DATA_DEPENDENT_LOOP
                                      if "循环" in category
                                      else TimingIssueType.BRANCH_TIMING)
                        results.append(TimingAnalysisResult(
                            issue_type=issue_type,
                            severity=sev,
                            line_number=lineno,
                            description=f"[{category}] {line.strip()[:100]}",
                        ))
                        break
        return results

    # 指针追踪缓存驻留检测
    # 基于 GoFetch 的 DMP 侧信道思路：
    # 通过测量指针追踪延迟探测数据是否驻留缓存。

    @staticmethod
    def detect_cache_residency(probe_addrs: List[int],
                                iterations: int = 500) -> List[TimingAnalysisResult]:
        """测量一组地址的缓存驻留时间分布。

        高方差 + 低中位 = 某些地址被预取器带入缓存（GoFetch 风格泄漏）。
        """
        results = []
        for addr in probe_addrs:
            times = []
            for _ in range(iterations):
                # 驱逐
                _ = bytearray(4096 * 16)  # 大数组驱逐 L1
                t0 = time.perf_counter_ns()
                try:
                    import ctypes
                    ctypes.c_char.from_address(addr).value
                except Exception:
                    pass
                times.append(time.perf_counter_ns() - t0)

            med = statistics.median(times)
            var = statistics.variance(times) if len(times) > 1 else 0.0
            if var > 100 and med < 500:  # 纳秒级
                results.append(TimingAnalysisResult(
                    samples=times,
                    issue_type=TimingIssueType.CACHE_RESIDENCY_LEAK,
                    severity=TimingIssueSeverity.MEDIUM,
                    description=f"地址 0x{addr:x}: 中位={med:.1f}ns, 方差={var:.1f} "
                                f"— 可能通过预取器发生缓存驻留泄漏",
                ))
        return results


def _incomplete_beta_tail(x: float, a: float, b: float) -> float:
    if a <= 0 or b <= 0:
        return 0.5
    return math.exp(
        math.lgamma(a + b) - math.lgamma(a) - math.lgamma(b) +
        a * math.log(x) + b * math.log(1 - x)
    ) / a


# 二进制模式扫描（合并自 timing_channel_detector）
# 扫描二进制中的计时原语与隐蔽信道模式

_TIMING_PATS = (
	('RDTSC',                   '时间戳计数器',                True),
	('rdtscp',                  '时间戳计数器',                True),
	('QueryPerformanceCounter', '高精度计时器',                False),
	('timeval',                 '时间测量',                    False),
	('clock_gettime',           'POSIX 计时器',                False),
	('sleep(',                  '显式延迟',                    False),
	('usleep',                  '微秒级睡眠',                  False),
	('nanosleep',               '纳秒级睡眠',                  False),
	('GetTickCount',            'Windows 滴答计数器',          False),
	('GetSystemTime',           '系统时间查询',                False),
	('strcmp',                  '字符串比较',                  True),
	('memcmp',                  '内存比较',                    True),
	('strncmp',                 '限定长度字符串比较',          True),
)

_COVERT_PATTERNS = (
	('pthread_mutex', '互斥锁争用信道',   False),
	('sem_wait',      '信号量等待信道',   False),
	('shm_open',      '共享内存信道',     False),
	('mq_send',       '消息队列信道',     False),
	('sched_yield',   'CPU 隐蔽信道',     False),
)


# detect_timing_channel_in_binary 的 out_dir 参数为旧调用方兼容入口:
# 054bc7b 提交将参数重命名为 f_outdir, microarch_validator 仍传 out_dir=,
# 此处保留双参数并优先采用 out_dir, 待调用方全量迁移后移除。


def detect_timing_channel_in_binary(f_path=None, f_outdir=None, out_dir=None):
	if out_dir is not None:
		f_outdir = out_dir  # 向后兼容：旧调用方仍传 out_dir=
	if f_path is None:
		return {'success': False, 'error': '路径为空'}
	import os as _os
	if not _os.path.isfile(f_path):
		return {'success': False, 'error': '未找到: ' + str(f_path)}

	try:
		channels = []
		with open(f_path, 'rb') as fh:
			raw = fh.read()
		content = raw.decode('latin-1', errors='ignore')

		_pi = 0
		_pn = len(_TIMING_PATS)
		while _pi < _pn:
			_pat, _ptype, _is_high = _TIMING_PATS[_pi]
			if _pat in content:
				_risk = '高' if _is_high else '中'
				channels.append({
					'location': '包含 ' + _pat,
					'type': _ptype,
					'risk': _risk,
				})
			_pi += 1

		_ci = 0
		_cn = len(_COVERT_PATTERNS)
		while _ci < _cn:
			_cpat, _cdesc, _chigh = _COVERT_PATTERNS[_ci]
			if _cpat in content:
				channels.append({
					'location': '包含 ' + _cpat,
					'type': '隐蔽信道: ' + _cdesc,
					'risk': '中',
				})
			_ci += 1

		_entropy = _shannon_entropy(raw)
		if _entropy > 6.0 and len(channels) > 0:
			for _ch in channels:
				if _ch['risk'] == '中':
					_ch['risk'] = '高'
					_ch['entropy_note'] = '数据熵=' + str(round(_entropy, 1)) + ' bits/byte'

		return {
			'success': True,
			'timing_channels': channels,
			'entropy_score': round(_entropy, 2),
		}
	except Exception as _exc:
		return {'success': False, 'error': str(_exc)}


def _shannon_entropy(data: bytes) -> float:
	_n = len(data)
	if _n < 64:
		return 0.0
	_freq = [0] * 256
	import math as _math
	for _b in data:
		_freq[_b] += 1
	_ent = 0.0
	_inv = 1.0 / _n
	for _f in _freq:
		if _f > 0:
			_p = _f * _inv
			_ent -= _p * _math.log2(_p)
	return _ent


def _debug_print(msg: str) -> None:
	# 调试输出占位, 发布版保持静默避免污染stdout
	pass
