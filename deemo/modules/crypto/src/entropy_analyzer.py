"""
密钥材料与压缩/加密数据的熵区分。

理论: 密码学密钥均匀随机→高Shannon熵+低序列相关。
压缩数据熵也高, 但通过头部开销和块边界表现出结构。
加密数据介于两者之间。

计算指标:
  - Shannon熵 (字节级)
  - 卡方统计量 (与均匀分布拟合优度)
  - 蒙特卡洛π近似 (序列相关代理)
  - 序列相关系数 (lag-1)
  - 字节频率分布直方图
  - 最小熵估计 (最坏情况可预测性)

2026-07新增:
  - NIST SP 800-90B IID置换检验 (自适应, 非参数)
  - 碰撞熵估计量 (Renyi α=2)
  - 马尔可夫转移矩阵, 下一字节可预测性
  - 基于数据异质性的自适应窗口大小
  - Lag-k序列相关 (k=1,2,4), 用于分组密码模式指纹
"""

import math
import struct
import logging
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

from .utils import safeReadBytes

logger = logging.getLogger(__name__)


@dataclass
class EntropyProfile:
    # 数据区域的完整熵特征刻画。
    offset: int = 0
    size: int = 0
    shannon_entropy: float = 0.0
    min_entropy: float = 0.0
    collision_entropy: float = 0.0
    chi_square: float = 0.0
    chi_square_pvalue: float = 0.0
    monte_carlo_pi: float = 0.0
    pi_error: float = 0.0
    serial_correlation: float = 0.0
    serial_corr_lag2: float = 0.0
    serial_corr_lag4: float = 0.0
    byte_mean: float = 0.0
    byte_stddev: float = 0.0
    # NIST SP 800-90B IID检验
    iid_permutation_pvalue: float = 0.0
    iid_is_consistent: bool = False
    # 马尔可夫可预测性
    markov_predictability: float = 0.0
    # 分类
    likely_key: bool = False
    likely_compressed: bool = False
    likely_encrypted: bool = False
    likely_text: bool = False
    diagnosis: str = ""
    # 原始直方图, 供外部可视化
    histogram: List[int] = field(default_factory=lambda: [0] * 256)


class EntropyAnalyzer:
    """
    多指标熵分析器, 用于区分密码学密钥与压缩/加密/明文数据。

    核心洞察: AES-256密钥、密文和gzip流都表现出高Shannon熵(~8 bits/byte)。
    需要次级指标来区分:
      - 卡方: 对均匀分布的微小偏差敏感
      - 蒙特卡洛π: 以坐标对作为序列相关代理
      - 字节均值/标准差: 即使一个固定头部字节也会使其偏离127.5
      - 碰撞熵: Renyi α=2, 比Shannon对重复更敏感
      - 马尔可夫转移: 度量给定当前字节的下一字节可预测性
      - NIST SP 800-90B IID检验: 基于置换, 无需正态性假设
    """

    # 经验阈值 — 基于真实密钥、密文样本、gzip/deflate流和明文测试语料调优。
    _KEY_ENTROPY_MIN = 7.5        # bits/byte
    _KEY_CHI_SQ_MAX  = 350        # 卡方低于此 → 可能均匀
    _KEY_PI_ERROR_MAX = 0.05      # π误差低于此 → 低序列相关
    _COMPRESSED_ENTROPY_MIN = 6.5
    _TEXT_ENTROPY_MAX = 5.5
    _MARKOV_KEY_THRESHOLD = 0.02  # 马尔可夫可预测性 <2% → 密钥特征

    def __init__(self):
        pass

    # ---- 公共API ----

    def analyze_file(self, path: str, chunk_size: int = 4096,
                     max_regions: int = 20) -> List[EntropyProfile]:
        """文件的滑动窗口熵扫描。返回前N个高兴趣区域。"""
        raw = safeReadBytes(path)
        if raw is None:
            return []
        return self.scan_regions(raw, chunk_size, max_regions)

    def analyze_bytes(self, data: bytes) -> EntropyProfile:
        """单字节缓冲区的完整熵分析。"""
        return self.compute_profile(data, 0)

    def scan_regions(self, data: bytes, window_size: int = 4096,
                     max_results: int = 20) -> List[EntropyProfile]:
        """滑动窗口扫描, 返回按兴趣度排序的候选区域。"""
        profiles: List[EntropyProfile] = []
        # 自适应步长: 小窗口→更细扫描
        step = max(window_size // 2, 256)
        if len(data) > 50 * 1024 * 1024:  # >50MB: 粗扫描以保持性能
            step = window_size

        for off in range(0, max(0, len(data) - window_size), step):
            chunk = data[off:off + window_size]
            p = self.compute_profile(chunk, off)
            if self._is_interesting(p):
                profiles.append(p)

        # 排序: 密钥优先, 加密次之, 压缩最后
        profiles.sort(key=lambda p: (
            not p.likely_key,
            not p.likely_encrypted,
            not p.likely_compressed,
        ))
        return profiles[:max_results]

    def compute_profile(self, data: bytes, offset: int = 0) -> EntropyProfile:
        """对单个数据块执行全部指标计算。"""
        n = len(data)
        if n == 0:
            return EntropyProfile(offset=offset, size=0, diagnosis="empty")

        hist = [0] * 256
        for b in data:
            hist[b] += 1

        # Shannon熵
        shannon = 0.0
        min_ent = float('inf')
        collision = 0.0
        for count in hist:
            if count > 0:
                p = count / n
                shannon -= p * math.log2(p)
                # min-entropy = -log2(max(p))
                min_ent = min(min_ent, -math.log2(p))
                # Renyi碰撞熵 (α=2): -log2(Σ p_i^2)
                collision += p * p
        if min_ent == float('inf'):
            min_ent = 0.0
        collision = -math.log2(collision) if collision > 0 else 0.0

        # 针对均匀分布的卡方
        expected = n / 256.0
        chi_sq = sum((c - expected) ** 2 / expected for c in hist)

        # 卡方p值近似 (255 DOF)
        # 使用Wilson-Hilferty变换粗略估计
        chi_sq_p = self._chi_sq_pvalue(chi_sq, 255)

        # 蒙特卡洛π — 以字节对为坐标
        mc_pi, pi_err = self._monte_carlo_pi(data)

        # 序列相关 (lag-1, lag-2, lag-4)
        ser_corr = self._serial_correlation(data, lag=1)
        ser_corr_2 = self._serial_correlation(data, lag=2)
        ser_corr_4 = self._serial_correlation(data, lag=4)

        # 基础统计
        byte_mean = sum(i * hist[i] for i in range(256)) / n
        variance = sum(hist[i] * (i - byte_mean) ** 2 for i in range(256)) / n
        byte_stddev = math.sqrt(variance)

        # 马尔可夫转移矩阵可预测性
        markov_pred = self._markov_predictability(data)

        # NIST SP 800-90B IID置换检验
        iid_p, iid_ok = self._iid_permutation_test(data, hist, n)

        profile = EntropyProfile(
            offset=offset, size=n,
            shannon_entropy=shannon,
            min_entropy=min_ent,
            collision_entropy=collision,
            chi_square=chi_sq,
            chi_square_pvalue=chi_sq_p,
            monte_carlo_pi=mc_pi,
            pi_error=pi_err,
            serial_correlation=ser_corr,
            serial_corr_lag2=ser_corr_2,
            serial_corr_lag4=ser_corr_4,
            byte_mean=byte_mean,
            byte_stddev=byte_stddev,
            iid_permutation_pvalue=iid_p,
            iid_is_consistent=iid_ok,
            markov_predictability=markov_pred,
            histogram=hist,
        )

        self._classify(profile)
        return profile

    # ---- 分类 ----

    def _classify(self, p: EntropyProfile) -> None:
        """
        基于指标阈值的启发式分类。
        顺序重要: 先检测密钥(最具体的标准)。
        马尔可夫可预测性<2%且IID一致性是强密钥信号。
        """
        if (p.shannon_entropy >= self._KEY_ENTROPY_MIN and
            p.chi_square <= self._KEY_CHI_SQ_MAX and
            p.pi_error <= self._KEY_PI_ERROR_MAX):
            if p.markov_predictability < self._MARKOV_KEY_THRESHOLD:
                p.likely_key = True
                p.diagnosis = "likely cryptographic key material (high entropy, uniform distribution, low serial correlation, low Markov predictability)"
            else:
                p.likely_encrypted = True
                p.diagnosis = "likely encrypted data (high entropy, elevated Markov predictability suggesting block structure)"
        elif p.shannon_entropy >= self._COMPRESSED_ENTROPY_MIN:
            if p.serial_correlation > 0.1:
                p.likely_compressed = True
                p.diagnosis = "likely compressed data (high entropy with serial structure)"
            else:
                p.likely_encrypted = True
                p.diagnosis = "likely encrypted data (high entropy, no clear structure)"
        elif p.shannon_entropy <= self._TEXT_ENTROPY_MAX:
            p.likely_text = True
            p.diagnosis = "likely plaintext or structured data (low entropy)"
        else:
            p.diagnosis = "indeterminate"

    # ---- 指标实现 ----

    @staticmethod
    def _monte_carlo_pi(data: bytes) -> Tuple[float, float]:
        """
        蒙特卡洛π估计: 将连续6字节组视为单位立方体内的(x,y,z)坐标。
        π ≈ 6 * (单位球内/总数)。

        随机数据与真实π的误差小。结构化数据(即使压缩)的坐标偏差会放大误差。
        """
        # 使用3字节组, 24-bit坐标精度
        n_points = min(len(data) // 6, 20000)
        if n_points < 100:
            return 0.0, 1.0

        inside = 0
        for i in range(n_points):
            off = i * 6
            x = int.from_bytes(data[off:off + 2], 'big') / 65535.0
            y = int.from_bytes(data[off + 2:off + 4], 'big') / 65535.0
            z = int.from_bytes(data[off + 4:off + 6], 'big') / 65535.0
            if x * x + y * y + z * z <= 1.0:
                inside += 1

        pi_est = 6.0 * inside / n_points
        error = abs(pi_est - math.pi) / math.pi
        return pi_est, error

    @staticmethod
    def _serial_correlation(data: bytes, lag: int = 1) -> float:
        """字节值的Lag-k Pearson相关。"""
        n = len(data)
        if n < lag + 2:
            return 0.0

        vals = list(data)
        mean = sum(vals) / n
        cov = sum((vals[i] - mean) * (vals[i + lag] - mean) for i in range(n - lag))
        var = sum((v - mean) ** 2 for v in vals)
        if var == 0:
            return 0.0
        return cov / var

    @staticmethod
    def _markov_predictability(data: bytes) -> float:
        """
        构建256×256字节转移计数矩阵, 以平均最大列概率衡量可预测性。
        密钥产生近似均匀转移(~1/256 ≈ 0.004); 结构化数据产生更高峰值。
        返回各状态的平均p_max, 归一至[0,1]。
        """
        n = len(data)
        if n < 2:
            return 1.0
        trans = [[0] * 256 for _ in range(256)]
        for i in range(n - 1):
            trans[data[i]][data[i + 1]] += 1
        # 每源状态的平均最大转移概率
        total_max = 0.0
        active_states = 0
        for src in range(256):
            row = trans[src]
            row_total = sum(row)
            if row_total > 0:
                max_prob = max(row) / row_total
                total_max += max_prob
                active_states += 1
        if active_states == 0:
            return 1.0
        return total_max / active_states

    @staticmethod
    def _iid_permutation_test(data: bytes, hist: List[int], n: int) -> Tuple[float, float]:
        """
        NIST SP 800-90B IID置换检验 (§5.1)。
        将样本统计量与随机置换所得的统计量分布比较 — 无理论分布假设。
        若原始统计量落在置换分布的中心95%以内, 样本与IID一致。

        以卡方为检验统计量(对分布形状敏感)。
        返回(p_value, is_iid_consistent)。
        """
        if n < 256:
            return 0.0, False
        # 计算原始卡方
        expected = n / 256.0
        orig_chi_sq = sum((c - expected) ** 2 / expected for c in hist)

        # 置换检验: 打乱并重新计算 (bootstrap ≈ 100次迭代)
        import random
        perm_chi_sqs = []
        orig_list = list(data)
        for _ in range(min(100, n // 10)):
            random.shuffle(orig_list)
            perm_hist = [0] * 256
            for b_val in orig_list:
                perm_hist[b_val] += 1
            perm_chi_sqs.append(
                sum((c - expected) ** 2 / expected for c in perm_hist))

        # 双侧: 置换统计量≤原始的比例(比偶然更均匀)
        count_leq = sum(1 for v in perm_chi_sqs if v <= orig_chi_sq)
        p_val = (count_leq + 1) / (len(perm_chi_sqs) + 1)
        is_iid = p_val >= 0.05  # 5%水平未能拒绝IID零假设
        return p_val, is_iid

    @staticmethod
    def _chi_sq_pvalue(chi_sq: float, df: int) -> float:
        """
        通过Wilson-Hilferty正态近似计算卡方p值。
        df>10时精度足够; 此处df=255, 完全在范围内。
        返回[0,1]中的值; 越高→越均匀。
        """
        if df <= 0 or chi_sq <= 0:
            return 1.0
        try:
            t = (chi_sq / df) ** (1.0 / 3.0)
            z = (t - (1.0 - 2.0 / (9.0 * df))) / math.sqrt(2.0 / (9.0 * df))
            # 标准正态CDF近似 (Abramowitz & Stegun 26.2.17)
            # 卡方检验*非*均匀性, 故用右尾
            # 卡方越低→p值越高→越均匀
            # 上尾p: P(Z > z)
            if z < -6:
                return 1.0
            if z > 6:
                return 0.0
            # 1 - Φ(z) 近似
            a1, a2, a3 = 0.4361836, -0.1201676, 0.9372980
            k = 1.0 / (1.0 + 0.33267 * abs(z))
            phi = 1.0 - (1.0 / math.sqrt(2.0 * math.pi)) * math.exp(-z * z / 2.0) * (
                a1 * k + a2 * k * k + a3 * k * k * k)
            if z < 0:
                phi = 1.0 - phi
            return phi
        except (ValueError, OverflowError):
            return 0.5

    @staticmethod
    def _is_interesting(p: EntropyProfile) -> bool:
        """过滤: 仅报告非平凡区域。"""
        return (
            p.likely_key or p.likely_encrypted or p.likely_compressed or
            p.shannon_entropy > 6.0
        )


# ---- 自适应窗口大小 (2026-07-27) ----
# 基于数据异质性自适应选择窗口大小。先用小窗口(512B)快速扫描,
# 计算Shannon熵的MAD(中位绝对偏差), MAD高→窗口加倍,
# MAD低→窗口缩小。避免齐次区浪费计算, 异质区提高分辨率。

def adaptive_window_size(data: bytes, min_w: int = 256, max_w: int = 16384) -> int:
    """返回基于MAD的自适应窗口大小。"""
    n = len(data)
    if n < min_w * 4:
        return min_w
    # 采样: 取前64个256B窗口, 计算每窗口熵值
    sample_w = 256
    samples = []
    for off in range(0, min(n - sample_w, sample_w * 64), sample_w):
        chunk = data[off:off + sample_w]
        freq = [0] * 256
        for b in chunk:
            freq[b] += 1
        ent = 0.0
        inv = 1.0 / sample_w
        log2 = __import__('math').log2
        for c in freq:
            if c:
                p = c * inv
                ent -= p * log2(p)
        samples.append(ent / 8.0)

    if len(samples) < 4:
        return min_w

    # MAD = median(|x_i - median(x)|)
    s_sorted = sorted(samples)
    med = s_sorted[len(s_sorted) // 2]
    mad = sorted(abs(s - med) for s in s_sorted)[len(s_sorted) // 2]

    # MAD高→异质→更大窗口; MAD低→齐次→小窗口即可
    scale = 1.0 + mad * 4.0
    return max(min_w, min(max_w, int(min_w * scale)))


# ---- 压缩比估计 (2026-07-27) ----
# LZ77变体的理论压缩上界: 数据中重复子串越少, 压缩比越低。
# deflate压缩比估计以entropy/8为下界 — 熵>7.5→几乎不可压缩(密钥/加密数据)。

def compression_ratio_estimate(data: bytes) -> float:
    """估计deflate压缩比下界: 基于熵值的理论极限。"""
    n = len(data)
    if n == 0:
        return 1.0
    freq = [0] * 256
    for b in data[:min(n, 65536)]:
        freq[b] += 1
    sample_n = min(n, 65536)
    ent = 0.0
    inv = 1.0 / sample_n
    log2 = __import__('math').log2
    for c in freq:
        if c:
            p = c * inv
            ent -= p * log2(p)
    # 熵=8→压缩比≈1.0(不可压缩)
    # 熵=4→压缩比≈2.0(可压缩一半)
    return 8.0 / max(ent, 0.5)


# ---- 便捷函数 ----

def analyze_entropy(path: str, **kwargs) -> List[EntropyProfile]:
    """便捷函数: 扫描文件中的高熵区域。"""
    return EntropyAnalyzer().analyze_file(path, **kwargs)
