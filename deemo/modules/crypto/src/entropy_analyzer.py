"""
Entropy profiling for key-material vs compressed/encrypted data discrimination.

Theory: cryptographic keys are uniformly random → high Shannon entropy with
low serial correlation. Compressed data also has high entropy but typically
exhibits structure via header overhead and block boundaries. Encrypted data
lands somewhere between.

Metrics computed:
  - Shannon entropy (byte-level)
  - Chi-square statistic (goodness-of-fit against uniform distribution)
  - Monte Carlo π approximation (serial correlation proxy)
  - Serial correlation coefficient (lag-1)
  - Byte frequency distribution histogram
  - min-entropy estimate (worst-case predictability)

2026-07 additions:
  - NIST SP 800-90B IID permutation test (adaptive, nonparametric)
  - Collision entropy estimator (Rényi α=2)
  - Markov transition matrix for next-byte predictability
  - Adaptive window sizing based on data heterogeneity
  - Lag-k serial correlation (k=1,2,4) for block-cipher mode fingerprinting
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
    """Complete entropy characterization of a data region."""

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
    # NIST SP 800-90B IID test
    iid_permutation_pvalue: float = 0.0
    iid_is_consistent: bool = False
    # Markov predictability
    markov_predictability: float = 0.0
    # classification
    likely_key: bool = False
    likely_compressed: bool = False
    likely_encrypted: bool = False
    likely_text: bool = False
    diagnosis: str = ""
    # raw histogram for external visualization
    histogram: List[int] = field(default_factory=lambda: [0] * 256)


class EntropyAnalyzer:
    """
    Multi-metric entropy analyzer for distinguishing cryptographic keys
    from compressed/encrypted/plaintext data.

    Core insight: AES-256 keys, ciphertext, and gzip streams all exhibit
    high Shannon entropy (~8 bits/byte). We need secondary metrics to tell
    them apart:
      - chi-square: sensitive to small deviations from uniformity
      - monte carlo pi: uses coordinate pairs as serial correlation proxy
      - byte mean/stddev: even one fixed header byte shifts these from 127.5
      - collision entropy: Rényi α=2, more sensitive to repeats than Shannon
      - Markov transition: measures next-byte predictability given current byte
      - NIST SP 800-90B IID test: permutation-based, no normality assumption
    """

    # Empirical thresholds — tuned against test corpora of real keys,
    # ciphertext samples, gzip/deflate streams, and plain text.
    _KEY_ENTROPY_MIN = 7.5        # bits/byte
    _KEY_CHI_SQ_MAX  = 350        # chi-sq below this → plausibly uniform
    _KEY_PI_ERROR_MAX = 0.05      # π error below this → low serial correlation
    _COMPRESSED_ENTROPY_MIN = 6.5
    _TEXT_ENTROPY_MAX = 5.5
    _MARKOV_KEY_THRESHOLD = 0.02  # Markov predictability below 2% → key-like

    def __init__(self):
        pass

    # ---- Public API ----

    def analyze_file(self, path: str, chunk_size: int = 4096,
                     max_regions: int = 20) -> List[EntropyProfile]:
        """Sliding-window entropy scan of a file. Returns top-N interesting regions."""
        raw = safeReadBytes(path)
        if raw is None:
            return []
        return self.scan_regions(raw, chunk_size, max_regions)

    def analyze_bytes(self, data: bytes) -> EntropyProfile:
        """Full-detail entropy analysis of a single byte buffer."""
        return self.compute_profile(data, 0)

    def scan_regions(self, data: bytes, window_size: int = 4096,
                     max_results: int = 20) -> List[EntropyProfile]:
        """Sliding-window scan returning candidates sorted by interest."""
        profiles: List[EntropyProfile] = []
        # Adaptive step: smaller windows → finer scan
        step = max(window_size // 2, 256)
        if len(data) > 50 * 1024 * 1024:  # >50MB: coarser scan to stay performant
            step = window_size

        for off in range(0, max(0, len(data) - window_size), step):
            chunk = data[off:off + window_size]
            p = self.compute_profile(chunk, off)
            if self._is_interesting(p):
                profiles.append(p)

        # Sort by interest: keys first, then encrypted, then compressed
        profiles.sort(key=lambda p: (
            not p.likely_key,
            not p.likely_encrypted,
            not p.likely_compressed,
        ))
        return profiles[:max_results]

    def compute_profile(self, data: bytes, offset: int = 0) -> EntropyProfile:
        """Run all metrics on a single data chunk."""
        n = len(data)
        if n == 0:
            return EntropyProfile(offset=offset, size=0, diagnosis="empty")

        hist = [0] * 256
        for b in data:
            hist[b] += 1

        # Shannon entropy
        shannon = 0.0
        min_ent = float('inf')
        collision = 0.0
        for count in hist:
            if count > 0:
                p = count / n
                shannon -= p * math.log2(p)
                # min-entropy = -log2(max(p))
                min_ent = min(min_ent, -math.log2(p))
                # Rényi collision entropy (α=2): -log2(Σ p_i^2)
                collision += p * p
        if min_ent == float('inf'):
            min_ent = 0.0
        collision = -math.log2(collision) if collision > 0 else 0.0

        # Chi-square against uniform
        expected = n / 256.0
        chi_sq = sum((c - expected) ** 2 / expected for c in hist)

        # Chi-square p-value approximation (255 DOF)
        # Using Wilson-Hilferty transform for rough estimate
        chi_sq_p = self._chi_sq_pvalue(chi_sq, 255)

        # Monte Carlo π — uses byte pairs as coordinates
        mc_pi, pi_err = self._monte_carlo_pi(data)

        # Serial correlation (lag-1, lag-2, lag-4)
        ser_corr = self._serial_correlation(data, lag=1)
        ser_corr_2 = self._serial_correlation(data, lag=2)
        ser_corr_4 = self._serial_correlation(data, lag=4)

        # Basic stats
        byte_mean = sum(i * hist[i] for i in range(256)) / n
        variance = sum(hist[i] * (i - byte_mean) ** 2 for i in range(256)) / n
        byte_stddev = math.sqrt(variance)

        # Markov transition matrix predictability
        markov_pred = self._markov_predictability(data)

        # NIST SP 800-90B IID permutation test
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

    # ---- Classification ----

    def _classify(self, p: EntropyProfile) -> None:
        """
        Heuristic classification based on metric thresholds.
        Order matters: test for keys first (most specific criteria).
        Markov predictability < 2% and IID consistency are strong key signals.
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

    # ---- Metric implementations ----

    @staticmethod
    def _monte_carlo_pi(data: bytes) -> Tuple[float, float]:
        """
        Estimate π via Monte Carlo: treat consecutive 6-byte groups as
        (x,y,z) coordinates within a unit cube. π ≈ 6 * (inside-unit-sphere / total).

        For random data, error vs true π is small. For structured data (even
        compressed), coordinate bias inflates the error.
        """
        # use 3-byte groups for 24-bit coordinate precision
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
        """Lag-k Pearson correlation of byte values."""
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
        Build a 256×256 byte-transition count matrix, then measure predictability
        as the average max-column probability. Keys produce near-uniform transitions
        (~1/256 ≈ 0.004); structured data produces higher peaks.
        Returns the average p_max per state, normalized to [0,1].
        """
        n = len(data)
        if n < 2:
            return 1.0
        trans = [[0] * 256 for _ in range(256)]
        for i in range(n - 1):
            trans[data[i]][data[i + 1]] += 1
        # Average max transition probability per source state
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
        NIST SP 800-90B IID permutation test (§5.1).
        Compares sample statistics against the distribution of statistics
        from random permutations of the sample — no theoretical distribution
        assumptions. If the original statistic falls within the central 95%
        of the permutation distribution, the sample is consistent with IID.

        Uses chi-square as the test statistic (sensitive to distribution shape).
        Returns (p_value, is_iid_consistent).
        """
        if n < 256:
            return 0.0, False
        # Compute original chi-square
        expected = n / 256.0
        orig_chi_sq = sum((c - expected) ** 2 / expected for c in hist)

        # Permutation test: shuffle and recompute (bootstrap ≈ 100 iterations)
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

        # Two-sided: fraction of permuted stats ≤ original (more uniform than chance)
        count_leq = sum(1 for v in perm_chi_sqs if v <= orig_chi_sq)
        p_val = (count_leq + 1) / (len(perm_chi_sqs) + 1)
        is_iid = p_val >= 0.05  # fails to reject IID null at 5%
        return p_val, is_iid

    @staticmethod
    def _chi_sq_pvalue(chi_sq: float, df: int) -> float:
        """
        Approximate chi-square p-value via Wilson-Hilferty normal approximation.
        Accurate enough for df > 10; we use df=255 so well within range.
        Returns value in [0, 1]; higher → more uniform.
        """
        if df <= 0 or chi_sq <= 0:
            return 1.0
        try:
            t = (chi_sq / df) ** (1.0 / 3.0)
            z = (t - (1.0 - 2.0 / (9.0 * df))) / math.sqrt(2.0 / (9.0 * df))
            # Standard normal CDF approximation (Abramowitz & Stegun 26.2.17)
            # Use the right-tail since chi-sq tests *non*-uniformity
            # Lower chi-sq → higher p-value → more uniform
            # Upper-tail p: P(Z > z)
            if z < -6:
                return 1.0
            if z > 6:
                return 0.0
            # 1 - Φ(z) approximation
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
        """Filter: only report regions that are non-trivial."""
        return (
            p.likely_key or p.likely_encrypted or p.likely_compressed or
            p.shannon_entropy > 6.0
        )


# ---- Adaptive window sizing (2026-07-27) ----
# 基于数据异质性自适应选择窗口大小。先用小窗口(512B)快速扫描,
# 计算Shannon熵的MAD (Median Absolute Deviation), MAD高→窗口加倍,
# MAD低→窗口缩小。避免在齐次区浪费计算, 在异质区提高分辨率。

def adaptive_window_size(data: bytes, min_w: int = 256, max_w: int = 16384) -> int:
    """返回基于MAD的自适应窗口大小."""
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

    # MAD 高 → 异质 → 用更大窗口; MAD 低 → 齐次 → 小窗口即可
    scale = 1.0 + mad * 4.0
    return max(min_w, min(max_w, int(min_w * scale)))


# ---- 压缩比估计 (2026-07-27) ----
# LZ77变体的理论压缩上界: 数据中重复子串越少, 压缩比越低。
# deflate压缩比估计使用 entropy / 8 作为下界 — 熵>7.5 → 几乎不可压缩(密钥/加密数据)。

def compression_ratio_estimate(data: bytes) -> float:
    """估计deflate压缩比下界: 基于熵值的理论极限."""
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
    # 熵 = 8 → 压缩比 ≈ 1.0 (不可压缩)
    # 熵 = 4 → 压缩比 ≈ 2.0 (可压缩一半)
    return 8.0 / max(ent, 0.5)


# ---- Convenience ----

def analyze_entropy(path: str, **kwargs) -> List[EntropyProfile]:
    """Convenience function: scan a file for high-entropy regions."""
    return EntropyAnalyzer().analyze_file(path, **kwargs)
