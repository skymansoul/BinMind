"""
ASLR 熵质量评估 — 样本驱动的有效随机化位数估计 + 静态基线回退。

问题定义:
  CCS 2024 "The Illusion of Randomness" 用 NSB 估计器实测了 Linux/Windows/macOS
  的 ASLR 有效熵。本模块在报告阶段复用这些基线，并提供两个评估路径:
    1. 样本驱动: 若有地址样本 → Miller-Madow 校正的离散熵估计
    2. 静态回退: 从二进制类型/OS指纹推断 CCS 2024 基线

Miller-Madow 校正:
  H_mm = H_plug-in + (K-1)/(2N)
  H_plug-in = -Σ p_i × log2(p_i), 其中 p_i = count_i / N
  K = 唯一值的数量, N = 样本总数
  此校正在 N<K 时 (欠采样) 降低 plug-in 估计器的向上偏差。
  近似于 NSB 的一阶 Taylor 展开——保留了 NSB 在小样本场景的优势
  但避免了 NSB 的数值积分开销。

参考:
  Binosi et al. (CCS 2024): NSB entropy estimation across OSes
  Miller (1955) & Madow (MS thesis): plug-in entropy bias correction
  Nemenman, Shafee & Bialek (2001): NSB entropy estimator

修改记录:
  创建 2026-08-01 — 静态基线评估 (assess_aslr_entropy)
  2026-08-03 — 追加样本驱动的 Miller-Madow 熵估计
"""

import math
from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


_OS_ENTROPY_BASELINE: Dict[str, Tuple[float, float, float, float]] = {
    'linux':       (28.8, 28.8, 28.8, 28.8),
    'linux_5.18+': (28.8, 28.8, 28.8, 19.0),
    'linux_hardened': (32.0, 40.0, 40.0, 33.0),
    'windows':     (19.0, 31.0, 31.0, 19.0),
    'windows_boot':(19.0, 31.0, 31.0, 19.0),
    'macos':       (14.0, 13.0, 13.0, 14.0),
    'macos_arm':   (13.0, 12.0, 12.0, 13.0),
}

_ENTROPY_TIME_LABELS = [
    (40, 'infeasible (>10 years)'), (35, 'centuries'), (30, 'months'),
    (25, 'hours'), (20, 'minutes'), (15, 'seconds'), (0, 'trivial (<1 second)'),
]


@dataclass
class AslrEntropyScore:
    os_fingerprint: str
    text_entropy: float
    stack_entropy: float
    heap_entropy: float
    library_entropy: float
    overall_score: float
    weakest_region: str
    brute_force_feasibility: str
    hardening_gaps: List[str] = field(default_factory=list)
    estimation_method: str = 'baseline'    # 'baseline' / 'miller_madow'
    confidence_interval: Optional[Tuple[float, float]] = None


def _miller_madow_entropy(samples: List[int], bits_to_extract: int = 36) -> Tuple[float, float, float]:
    """
    从地址样本估计有效熵。返回 (H_mm, H_plug_in, K)。

    1. 提取高位随机比特 (mask off 低 12 位页偏移)
    2. plug-in Shannon 熵 → H = -Σ p_i × log2(p_i)
    3. Miller-Madow 校正 → H_mm = H + (K-1)/(2N)
    4. 上限 clamp 到 bits_to_extract

    至少需要 100 个样本才能产生有意义的估计。
    """
    N = len(samples)
    if N < 50:
        return 0.0, 0.0, 0

    page_mask = (1 << 12) - 1
    shift = 12
    extracted = [(s & ~page_mask) >> shift for s in samples if s > 0]

    if len(extracted) < 50:
        return 0.0, 0.0, 0

    counter = Counter(extracted)
    K = len(counter)
    total = len(extracted)
    h_plug = 0.0
    for count in counter.values():
        p = count / total
        h_plug -= p * math.log2(p)

    # Miller-Madow: 加 (K-1)/(2N) 修正 plug-in 的向下偏差
    correction = (K - 1) / (2 * total) if total > 1 else 0.0
    h_mm = h_plug + correction

    # 上限: 理论最大 log2(K) (均匀分布)
    max_possible = math.log2(K) if K > 1 else 0.0
    h_mm = min(h_mm, max_possible, bits_to_extract)

    return round(h_mm, 2), round(h_plug, 2), K


def _estimate_confidence(h_mm: float, N: int, K: int) -> Tuple[float, float]:
    """基于样本量的粗略置信区间。K/N 比越高 → 区间越宽。"""
    if N < 50: return (0.0, 0.0)
    # 经验公式: 半宽 ∝ (K/N) × 1/√N
    half_width = (K / max(N, 1)) * (1.0 / math.sqrt(N)) * 10.0
    half_width = min(half_width, h_mm * 0.5)  # 不超过估计值的一半
    return round(max(0, h_mm - half_width), 1), round(h_mm + half_width, 1)


def estimate_entropy_from_samples(
    samples: List[int],
    bits_to_extract: int = 36,
    label: str = 'empirical',
) -> Dict[str, Any]:
    """
    从地址样本估计 ASLR 有效熵。
    返回 {label, h_mm, h_plug_in, unique_count, sample_count, confidence_interval}。
    """
    h_mm, h_plug, K = _miller_madow_entropy(samples, bits_to_extract)
    ci = _estimate_confidence(h_mm, len(samples), K)
    return {
        'label': label, 'h_mm': h_mm, 'h_plug_in': h_plug,
        'unique_values': K, 'sample_count': len(samples),
        'confidence_interval': ci,
        'brute_force_time': _entropy_to_brute_force_label(h_mm) if h_mm > 0 else 'N/A',
    }


def _detect_os_profile(
    binary_format: str,
    os_hints: Optional[Dict[str, Any]] = None,
    kernel_version: str = '',
) -> str:
    fmt = binary_format.lower()
    hints = os_hints or {}
    if 'mach' in fmt:
        arch = hints.get('arch', '').lower()
        return 'macos_arm' if 'arm' in arch else 'macos'
    if 'pe' in fmt:
        return 'windows'
    if kernel_version:
        try:
            parts = kernel_version.lstrip('v').split('.')
            major, minor = int(parts[0]), int(parts[1]) if len(parts) > 1 else 0
            if major > 5 or (major == 5 and minor >= 18):
                return 'linux_5.18+'
        except (ValueError, IndexError): pass
    return 'linux'


def _entropy_to_brute_force_label(bits: float) -> str:
    for threshold, label in _ENTROPY_TIME_LABELS:
        if bits >= threshold: return label
    return 'trivial (<1 second)'


def assess_aslr_entropy(
    binary_format: str = 'elf', is_pie: bool = False,
    is_stripped: bool = False, arch: str = 'amd64',
    kernel_version: str = '',
    os_hints: Optional[Dict[str, Any]] = None,
    address_samples: Optional[Dict[str, List[int]]] = None,
) -> AslrEntropyScore:
    """
    评估 ASLR 熵质量。双路径:
      - address_samples 提供时: Miller-Madow 经验估计
      - 否则: CCS 2024 基线表回退

    address_samples: {'text': [...], 'stack': [...], 'heap': [...], 'lib': [...]}
    """
    profile = _detect_os_profile(binary_format, os_hints, kernel_version)
    base = _OS_ENTROPY_BASELINE.get(profile, _OS_ENTROPY_BASELINE['linux'])
    t_base, s_base, h_base, l_base = base
    gaps: List[str] = []
    method = 'baseline'
    ci = None

    if address_samples:
        method = 'miller_madow'
        text_s = address_samples.get('text', [])
        stack_s = address_samples.get('stack', [])
        heap_s = address_samples.get('heap', [])
        lib_s = address_samples.get('lib', [])

        t_est = estimate_entropy_from_samples(text_s) if text_s else {}
        s_est = estimate_entropy_from_samples(stack_s) if stack_s else {}
        h_est = estimate_entropy_from_samples(heap_s) if heap_s else {}
        l_est = estimate_entropy_from_samples(lib_s) if lib_s else {}

        text_ent = t_est.get('h_mm', 0) or t_base
        stack_ent = s_est.get('h_mm', 0) or s_base
        heap_ent = h_est.get('h_mm', 0) or h_base
        lib_ent = l_est.get('h_mm', 0) or l_base

        # 从最大样本集合取 CI
        all_ests = [(t_est, len(text_s)), (s_est, len(stack_s)),
                    (h_est, len(heap_s)), (l_est, len(lib_s))]
        best = max(all_ests, key=lambda x: x[1])
        if best[1] >= 50:
            ci = best[0].get('confidence_interval')

        if not is_pie: text_ent = 0.0
    else:
        text_ent = 0.0 if not is_pie else t_base
        stack_ent, heap_ent, lib_ent = s_base, h_base, l_base

    if not is_pie:
        gaps.append('非PIE二进制 — 代码段基址固定')
    if is_stripped:
        gaps.append('stripped — 无符号表, 漏洞定位难度增加但 ASLR 熵不变')

    if '32' in arch or 'i386' in arch.lower():
        text_ent = max(0, text_ent - 8); stack_ent = max(0, stack_ent - 8)
        heap_ent = max(0, heap_ent - 8); lib_ent = max(0, lib_ent - 8)
        gaps.append('32-bit — 地址空间限制, -8 bits')

    avg_ent = (text_ent + stack_ent + heap_ent + lib_ent) / 4.0
    overall = round(min(avg_ent / 40.0 * 100, 100), 1)
    regions = {'text': text_ent, 'stack': stack_ent, 'heap': heap_ent, 'library': lib_ent}
    weakest = min(regions, key=regions.get)

    return AslrEntropyScore(
        os_fingerprint=profile,
        text_entropy=round(text_ent, 1), stack_entropy=round(stack_ent, 1),
        heap_entropy=round(heap_ent, 1), library_entropy=round(lib_ent, 1),
        overall_score=overall, weakest_region=weakest,
        brute_force_feasibility=_entropy_to_brute_force_label(min(regions.values())),
        hardening_gaps=gaps, estimation_method=method, confidence_interval=ci)


def aslr_summary(score: AslrEntropyScore) -> Dict[str, Any]:
    recs = list(score.hardening_gaps)
    if score.text_entropy == 0:
        recs.append('启用 PIE (-fPIE -pie) 以随机化代码段')
    if score.os_fingerprint == 'linux_5.18+':
        recs.append('Linux 5.18+ folio 退化, 考虑 linux-hardened 内核')
    if score.os_fingerprint.startswith('macos'):
        recs.append('macOS ASLR 熵显著低, 考虑运行时防护')

    result = {
        'overall_score': score.overall_score, 'os_profile': score.os_fingerprint,
        'entropy_bits': {'text': score.text_entropy, 'stack': score.stack_entropy,
                         'heap': score.heap_entropy, 'library': score.library_entropy},
        'weakest_region': score.weakest_region,
        'brute_force_feasibility': score.brute_force_feasibility,
        'estimation_method': score.estimation_method,
        'recommendations': recs,
    }
    if score.confidence_interval:
        result['confidence_interval'] = score.confidence_interval
    return result
