# 2026-08-01

import math
import random
import statistics

# ===== Rijndael S-Box =====
# FIPS 197 标准值
AES_SBOX: list[int] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b,
    0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26,
    0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2,
    0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
    0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed,
    0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f,
    0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec,
    0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14,
    0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
    0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d,
    0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f,
    0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
    0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11,
    0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f,
    0xb0, 0x54, 0xbb, 0x16,
]


# ---- 独立工具函数 ----
def compute_hamming_weight(value: int) -> int:
    """popcount — 位操作逐比特计数"""
    _v = value
    _v = (_v & 0x55) + ((_v >> 1) & 0x55)
    _v = (_v & 0x33) + ((_v >> 2) & 0x33)
    _v = (_v & 0x0F) + ((_v >> 4) & 0x0F)
    return _v


# ===== SideChannelEvaluator =====
# TVLA (Welch's t-test) + CPA + 格密码侧信道


class SideChannelEvaluator:
    # 显著性阈值 — 对应99.9999%置信度
    _TVLA_THRESHOLD = 4.5

    def __init__(self, trace_count: int = 1000):
        self._trace_count = trace_count

    # //// 内部工具函数 ////

    def _hamming_weight(self, value: int) -> int:
        return compute_hamming_weight(value)

    def _sbox_substitute(self, value: int) -> int:
        return AES_SBOX[value & 0xFF]

    # ---- Pearson相关系数 ----
    def _pearson_correlation(self, x: list[float], y: list[float]) -> float:
        n = len(x)
        if n < 3 or len(y) != n:
            return 0.0
        sum_x = sum(x)
        sum_y = sum(y)
        sum_xy = sum(x[i] * y[i] for i in range(n))
        sum_x2 = sum(v * v for v in x)
        sum_y2 = sum(v * v for v in y)
        num = n * sum_xy - sum_x * sum_y
        den = math.sqrt((n * sum_x2 - sum_x * sum_x) * (n * sum_y2 - sum_y * sum_y))
        return num / den if den > 1e-15 else 0.0

    # ---- Welch-Satterthwaite 自由度 ----
    def _welch_satterthwaite_df(
        self, var1: float, n1: int, var2: float, n2: int
    ) -> float:
        if n1 < 2 or n2 < 2:
            return 2.0
        _num = (var1 / n1 + var2 / n2) ** 2
        _den = (var1 / n1) ** 2 / (n1 - 1) + (var2 / n2) ** 2 / (n2 - 1)
        return _num / _den if _den > 1e-15 else 2.0

    # ---- 不完全Beta函数（连分式近似） ----
    # 用于Student t分布的CDF计算
    def _incomplete_beta_approx(self, x: float, a: float, b: float) -> float:
        """正则化不完全Beta函数 — Lentz连分式算法"""
        if x <= 0.0:
            return 0.0
        if x >= 1.0:
            return 1.0
        # 前乘因子
        _log_beta = math.lgamma(a) + math.lgamma(b) - math.lgamma(a + b)
        _front = math.exp(math.log(x) * a + math.log(1.0 - x) * b - _log_beta) / a
        # Lentz连分式
        _f = 1.0
        _c = 1.0
        _d = 1.0 - (a + b) * x / (a + 1.0)
        if abs(_d) < 1e-30:
            _d = 1e-30
        _d = 1.0 / _d
        _h = _d
        for _m in range(1, 200):
            _m2 = 2 * _m
            # d_{2m} 项
            _da = _m * (b - _m) * x / ((a + _m2 - 1.0) * (a + _m2))
            _d = 1.0 + _da * _d
            if abs(_d) < 1e-30:
                _d = 1e-30
            _c = 1.0 + _da / _c
            if abs(_c) < 1e-30:
                _c = 1e-30
            _d = 1.0 / _d
            _h *= _d * _c
            # d_{2m+1} 项
            _da = -(a + _m) * (a + b + _m) * x / ((a + _m2) * (a + _m2 + 1.0))
            _d = 1.0 + _da * _d
            if abs(_d) < 1e-30:
                _d = 1e-30
            _c = 1.0 + _da / _c
            if abs(_c) < 1e-30:
                _c = 1e-30
            _d = 1.0 / _d
            _del = _d * _c
            _h *= _del
            if abs(_del - 1.0) < 1e-12:
                break
        return _front * (_h - 1.0)

    # ===== TVLA — Welch's t-test =====
    # 固定vs随机明文的泄漏检测
    def tvla_test(
        self, traces_fixed: list[list[float]], traces_random: list[list[float]]
    ) -> dict:
        if not traces_fixed or not traces_random:
            return {
                "t_values": [],
                "max_t": 0.0,
                "threshold_exceeded": False,
                "df_estimate": 0.0,
                "sample_indices": [],
            }
        _n_fixed = len(traces_fixed)
        _n_random = len(traces_random)
        _len = len(traces_fixed[0])
        t_values: list[float] = []
        exceeded: list[int] = []
        for _i in range(_len):
            _samples_f = [t[_i] for t in traces_fixed]
            _samples_r = [t[_i] for t in traces_random]
            _mean_f = statistics.mean(_samples_f)
            _mean_r = statistics.mean(_samples_r)
            _var_f = statistics.variance(_samples_f) if _n_fixed > 1 else 0.0
            _var_r = statistics.variance(_samples_r) if _n_random > 1 else 0.0
            _denom = math.sqrt(_var_f / _n_fixed + _var_r / _n_random)
            _t = (_mean_f - _mean_r) / _denom if _denom > 1e-15 else 0.0
            t_values.append(_t)
            if abs(_t) > self._TVLA_THRESHOLD:
                exceeded.append(_i)
        max_t = max(abs(v) for v in t_values) if t_values else 0.0
        _df = self._welch_satterthwaite_df(
            statistics.variance([t for t in traces_fixed[0]]) if len(traces_fixed) > 1 else 0.0,
            _n_fixed,
            statistics.variance([t for t in traces_random[0]]) if len(traces_random) > 1 else 0.0,
            _n_random,
        )
        return {
            "t_values": t_values,
            "max_t": max_t,
            "threshold_exceeded": max_t > self._TVLA_THRESHOLD,
            "df_estimate": _df,
            "sample_indices": exceeded,
        }

    # ===== CPA — 相关功耗分析 =====
    # 汉明重量模型 + AES S-box
    def cpa_attack(
        self,
        traces: list[list[float]],
        plaintext: list[int],
        key_guess_range: tuple[int, int] = (0, 255),
    ) -> dict:
        if not traces or not plaintext:
            return {
                "best_guess": -1,
                "correlation": 0.0,
                "all_correlations": {},
                "key_byte_index": 0,
            }
        _n_traces = min(len(traces), len(plaintext))
        _n_samples = len(traces[0])
        all_corrs: dict[int, list[float]] = {}
        best_guess = -1
        best_corr = 0.0
        for _kg in range(key_guess_range[0], key_guess_range[1] + 1):
            _hw_pred: list[float] = []
            for _i in range(_n_traces):
                _intermediate = self._sbox_substitute(plaintext[_i] ^ _kg)
                _hw_pred.append(float(self._hamming_weight(_intermediate)))
            # 对每个采样点计算相关系数，取最大值
            _sample_corrs: list[float] = []
            for _s in range(_n_samples):
                _trace_sample = [traces[_i][_s] for _i in range(_n_traces)]
                _r = self._pearson_correlation(_hw_pred, _trace_sample)
                _sample_corrs.append(_r)
            all_corrs[_kg] = _sample_corrs
            _max_r = max(_sample_corrs) if _sample_corrs else 0.0
            if abs(_max_r) > abs(best_corr):
                best_corr = _max_r
                best_guess = _kg
        return {
            "best_guess": best_guess,
            "correlation": best_corr,
            "all_correlations": all_corrs,
            "key_byte_index": 0,
        }

    # ---- 格密码侧信道: 中心归约泄漏检测 ----
    def _detect_central_reduction_leak(
        self, traces_group_a: list[list[float]], traces_group_b: list[list[float]]
    ) -> list[int]:
        """F-test方差比较 — 差分方差分析"""
        if not traces_group_a or not traces_group_b:
            return []
        _len = len(traces_group_a[0])
        _leaky: list[int] = []
        for _i in range(_len):
            _vals_a = [t[_i] for t in traces_group_a]
            _vals_b = [t[_i] for t in traces_group_b]
            _var_a = statistics.variance(_vals_a) if len(_vals_a) > 1 else 0.0
            _var_b = statistics.variance(_vals_b) if len(_vals_b) > 1 else 0.0
            # F统计量: 大方差/小方差
            if _var_b > 1e-15 and _var_a > 1e-15:
                _f_stat = max(_var_a, _var_b) / min(_var_a, _var_b)
            elif _var_b > 1e-15:
                _f_stat = _var_a / _var_b if _var_a > 0 else 0.0
            elif _var_a > 1e-15:
                _f_stat = _var_b / _var_a if _var_b > 0 else 0.0
            else:
                _f_stat = 1.0
            # F > 2.0 指示显著方差差异
            if _f_stat > 2.0:
                _leaky.append(_i)
        return _leaky

    # ===== 格密码侧信道分析 =====
    # Kyber/Dilithium — 中心二项分布 vs 均匀分布泄漏
    def lattice_side_channel(
        self, traces: list[list[float]], modulus: int = 3329
    ) -> dict:
        if not traces:
            return {
                "leaky_samples": [],
                "variance_ratios": [],
                "is_vulnerable": False,
            }
        # 按时间复杂度分成两组 — 模拟CBD vs 均匀归约差异
        _mid = len(traces) // 2
        _group_a = traces[:_mid]
        _group_b = traces[_mid:]
        _leaky = self._detect_central_reduction_leak(_group_a, _group_b)
        # 计算方差比
        _var_ratios: list[float] = []
        _len = len(traces[0])
        for _i in range(_len):
            _a = [t[_i] for t in _group_a]
            _b = [t[_i] for t in _group_b]
            _va = statistics.variance(_a) if len(_a) > 1 else 1e-10
            _vb = statistics.variance(_b) if len(_b) > 1 else 1e-10
            _var_ratios.append(max(_va, _vb) / min(_va, _vb) if min(_va, _vb) > 1e-10 else 1.0)
        return {
            "leaky_samples": _leaky,
            "variance_ratios": _var_ratios,
            "is_vulnerable": len(_leaky) > len(traces[0]) * 0.05,
        }
