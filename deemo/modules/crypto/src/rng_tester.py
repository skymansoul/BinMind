# ==== NIST SP 800-22 随机数测试套件 (子集) ====
# 自包含实现 -- 不依赖 scipy/numpy。O(n) 或 O(n log n) 内完成。
# gamma 函数: Lanczos 逼近 (log-gamma), erfc: Abramowitz 7.1.26。
# DFT 测试: numpy 可选加速, 无 numpy 时对 <8k bits 用 O(n^2) 降级。
# alpha=0.01, 允许1项失败仍判定为密码学随机。

import math
from typing import List, Dict, Tuple, Optional

try:
    import numpy as _np
    _HAS_NUMPY = True
except ImportError:
    _HAS_NUMPY = False


# ---- 数学辅助: gamma(log) + erfc ----
def _lgamma(x: float) -> float:
    """Lanczos log-gamma, 精度约1e-15."""
    _g = 7
    _c = [0.99999999999980993, 676.5203681218851, -1259.1392167224028,
          771.32342877765313, -176.61502916214059, 12.507343278686905,
          -0.13857109526572012, 9.9843695780195716e-6, 1.5056327351493116e-7]
    if x < 0.5:
        return math.log(math.pi / math.sin(math.pi * x)) - _lgamma(1 - x)
    x -= 1
    _s = _c[0]
    for _i in range(1, _g + 2):
        _s += _c[_i] / (x + _i)
    _t = x + _g + 0.5
    return math.log(math.sqrt(2 * math.pi)) + (x + 0.5) * math.log(_t) - _t + math.log(_s)


def _gamma(x: float) -> float:
    return math.exp(_lgamma(x))


def _igamc(a: float, x: float) -> float:
    """不完全 gamma 正则化补: NIST p 值计算用."""
    # 级数展开 (x < a+1)
    if x < a + 1:
        _sum = 1.0 / a
        _term = 1.0 / a
        for _n in range(1, 100):
            _term *= x / (a + _n)
            _prev = _sum
            _sum += _term
            if abs(_term) < abs(_sum) * 1e-15:
                break
        return 1.0 - _sum * math.exp(-x + a * math.log(x) - _lgamma(a))
    # 连分式展开 (x >= a+1)
    _b = x + 1 - a
    _f = 1.0 / (_b + 1e-30)
    _c = 1.0
    _d = 1.0 / (_b + 1e-30)
    for _n in range(1, 200):
        _an = -_n * (_n - a)
        _b += 2
        _d = _b + _an * _d
        if abs(_d) < 1e-30:
            _d = 1e-30
        _c = _b + _an / (_c + 1e-30)
        if abs(_c) < 1e-30:
            _c = 1e-30
        _d = 1.0 / _d
        _delta = _c * _d
        _f *= _delta
        if abs(_delta - 1) < 1e-15:
            break
    return _f * math.exp(-x + a * math.log(x) - _lgamma(a))


def _erfc(x: float) -> float:
    """互补误差函数 erfc(x) = 1 - erf(x)."""
    if x < 0:
        return 2.0 - _erfc(-x)
    _t = 1.0 / (1.0 + 0.3275911 * x)
    _poly = _t * (0.254829592 + _t * (-0.284496736 + _t * (1.421413741 +
                   _t * (-1.453152027 + _t * 1.061405429))))
    return _poly * math.exp(-x * x)


# ---- NIST SP 800-22 检验 ----
def monobit_test(bits: List[int]) -> float:
    """频率 (单比特) 检验: H0 -> P(0)=P(1)=0.5。返回 p 值."""
    _n = len(bits)
    if _n < 100:
        return 0.0
    _s = sum(1 if _b else -1 for _b in bits)
    _stat = abs(_s) / math.sqrt(_n)
    return _erfc(_stat / math.sqrt(2))


def block_frequency_test(bits: List[int], M: int = 128) -> float:
    """块内频率检验: 每 M 位块内 1 的比例."""
    _n = len(bits)
    _N = _n // M
    if _N < 1:
        return 0.0
    _chi2 = 0.0
    for _i in range(_N):
        _pi = sum(bits[_i * M:(_i + 1) * M]) / M
        _chi2 += (_pi - 0.5) ** 2
    _chi2 *= 4 * M
    return _igamc(_N / 2, _chi2 / 2)


def runs_test(bits: List[int]) -> float:
    """游程检验: 游程数反映序列振荡频率."""
    _n = len(bits)
    if _n < 100:
        return 0.0
    _pi = sum(bits) / _n
    _tau = 2.0 / math.sqrt(_n)
    if abs(_pi - 0.5) >= _tau:
        return 0.0
    _v = 1
    for _i in range(1, _n):
        if bits[_i] != bits[_i - 1]:
            _v += 1
    _num = abs(_v - 2 * _n * _pi * (1 - _pi))
    _den = 2 * math.sqrt(2 * _n) * _pi * (1 - _pi)
    return _erfc(_num / (_den + 1e-15))


def longest_run_of_ones_test(bits: List[int]) -> float:
    """块内最长1游程检验."""
    _n = len(bits)
    if _n < 128:
        return 0.0
    if _n < 6272:
        _M, _K = 8, 3
        _pi_vals = [0.2148, 0.3672, 0.2305, 0.1875]
    elif _n < 750000:
        _M, _K = 128, 5
        _pi_vals = [0.1174, 0.2430, 0.2493, 0.1752, 0.1027, 0.1124]
    else:
        _M, _K = 10000, 6
        _pi_vals = [0.0882, 0.2092, 0.2483, 0.1933, 0.1208, 0.0675, 0.0727]

    _N = _n // _M
    _v = [0] * (_K + 2)
    for _i in range(_N):
        _chunk = bits[_i * _M:(_i + 1) * _M]
        _run = 0
        _longest = 0
        for _b in _chunk:
            if _b:
                _run += 1
                _longest = max(_longest, _run)
            else:
                _run = 0
        if _longest <= _K:
            _v[_longest] += 1
        else:
            _v[_K + 1] += 1

    _chi2 = 0.0
    for _i in range(_K + 1):
        if _i < len(_pi_vals):
            _e = _N * _pi_vals[_i]
            if _e > 0:
                _chi2 += (_v[_i] - _e) ** 2 / _e
    return _igamc(_K / 2, _chi2 / 2)


def approximate_entropy_test(bits: List[int], m: int = 5) -> float:
    """近似熵 (ApEn) 检验: 比较 m 和 m+1 位模式频率."""
    _n = len(bits)
    if _n < m + 2:
        return 0.0

    def _aphi(m_val):
        _freq = {}
        _mask = (1 << m_val) - 1
        _val = 0
        for _i in range(m_val):
            _val = (_val << 1) | bits[_i]
        _freq[_val] = 1
        for _i in range(1, _n - m_val + 1):
            _val = ((_val << 1) & _mask) | bits[_i + m_val - 1]
            _freq[_val] = _freq.get(_val, 0) + 1
        _total = _n - m_val + 1
        _phi = 0.0
        for _c in _freq.values():
            _p = _c / _total
            _phi += _p * math.log(_p)
        return _phi

    _phi_m = _aphi(m)
    _phi_mp1 = _aphi(m + 1)
    _apen = _phi_m - _phi_mp1
    _chi2 = 2 * _n * (math.log(2) - _apen)
    return _igamc(2 ** (m - 1), _chi2 / 2)


def cusum_test(bits: List[int]) -> Tuple[float, float]:
    """累积和检验: 前向和后向, 检测序列部分和是否过大."""
    _n = len(bits)
    if _n < 100:
        return 0.0, 0.0
    _x = [1 if _b else -1 for _b in bits]

    def _cusum(seq):
        _s = 0
        _mx = 0
        for _v in seq:
            _s += _v
            _mx = max(_mx, abs(_s))
        _z = _mx / math.sqrt(_n)
        _p = 0.0
        _k1 = int((-_n / _z + 1) / 4)
        _k2 = int((_n / _z - 1) / 4)
        for _k in range(_k1, _k2 + 1):
            _t1 = (4 * _k + 1) * _z / math.sqrt(_n)
            _t2 = (4 * _k - 1) * _z / math.sqrt(_n)
            _p += _normal_cdf(_t1) - _normal_cdf(_t2)
        _k1 = int((-_n / _z - 3) / 4)
        _k2 = int((_n / _z - 1) / 4)
        for _k in range(_k1, _k2 + 1):
            _t1 = (4 * _k + 3) * _z / math.sqrt(_n)
            _t2 = (4 * _k + 1) * _z / math.sqrt(_n)
            _p += _normal_cdf(_t1) - _normal_cdf(_t2)
        return 1 - _p

    return _cusum(_x), _cusum(list(reversed(_x)))


def _normal_cdf(x: float) -> float:
    return 0.5 * _erfc(-x / math.sqrt(2))


def dft_test(bits: List[int]) -> float:
    """离散傅里叶变换检验: 检测序列周期性特征."""
    _n = len(bits)
    if _n < 100:
        return 0.0
    _x = [2.0 * _b - 1.0 for _b in bits]

    if _HAS_NUMPY and _n >= 8192:
        _fft = _np.fft.fft(_x)
        _mag = _np.abs(_fft[:_n // 2]) / math.sqrt(_n)
    else:
        # O(n^2) 降级
        _mag = []
        _half = _n // 2
        for _k in range(_half):
            _re = 0.0
            _im = 0.0
            for _j in range(_n):
                _theta = 2 * math.pi * _k * _j / _n
                _re += _x[_j] * math.cos(_theta)
                _im -= _x[_j] * math.sin(_theta)
            _mag.append(math.sqrt(_re * _re + _im * _im) / math.sqrt(_n))

    _T = math.sqrt(math.log(1 / 0.05) * _n)
    _N1 = sum(1 for _m in _mag if _m < _T)
    _N0 = 0.95 * _n / 2
    _d = (_N1 - _N0) / math.sqrt(_n * 0.95 * 0.05 / 4)
    return _erfc(abs(_d) / math.sqrt(2))


# ---- 综合检验 ----
def test_randomness(data: bytes) -> Dict[str, float]:
    # 对字节数据执行 NIST 检验集, 返回 {test_name: p_value}
    _bits = [(b >> i) & 1 for b in data for i in range(8)]
    _res = {}
    _res['monobit'] = monobit_test(_bits)
    _res['block_freq'] = block_frequency_test(_bits)
    _res['runs'] = runs_test(_bits)
    _res['longest_run'] = longest_run_of_ones_test(_bits)
    _res['approx_entropy'] = approximate_entropy_test(_bits)
    _fw, _rv = cusum_test(_bits)
    _res['cusum_fwd'] = _fw
    _res['cusum_rev'] = _rv
    _res['dft'] = dft_test(_bits)
    return {_k: round(_v, 6) for _k, _v in _res.items()}


def is_cryptographically_random(data: bytes) -> bool:
    """alpha=0.01, 允许1项失败."""
    _r = test_randomness(data)
    _fail = sum(1 for _v in _r.values() if _v < 0.01)
    return _fail <= 1


def entropy_differential(a: bytes, b: bytes) -> float:
    """两个字节序列间的熵差异 (比较加密前后)."""
    from .utils import shannon_entropy
    return abs(shannon_entropy(a) - shannon_entropy(b))
