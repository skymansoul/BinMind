# 修改记录:
# 2025-09-05 15:49 — 初始实现：JSD/NCD/MI 三种信息论距离
# 2025-09-06 09:13 — 增加 permutation test 显著性检验

"""Information-Theoretic Patch Distance — 基于信息论的补丁相似度。

UniASM 使用 UniLM Transformer 做二进制代码相似度检测。
BinGAT 使用图注意力网络。这些方法依赖深度学习嵌入。

本模块提供不依赖 ML 的信息论替代方案——纯统计方法，可审计，可解释：
  1. Jensen-Shannon 散度 (JSD): 两补丁的字节分布差异
  2. 归一化压缩距离 (NCD): 基于压缩器的通用距离度量
  3. 互信息 (MI): 两补丁修改区域间的共享信息量
  4. Permutation test: 距离是否统计显著

信息论方法的核心优势：
  - 不需要训练数据（零样本）
  - 不需要 GPU
  - 数学可解释性（距离的每个 bit 都有信息论含义）
  - 对编译器差异更鲁棒（压缩器自动学习统计规律）

NCD 的理论基础：
  NCD(x, y) = (C(xy) - min(C(x), C(y))) / max(C(x), C(y))
  其中 C 是压缩长度。NCD 逼近归一化信息距离 (NID)，
  而 NID 是满足所有距离公理的通用相似度度量。
"""

import math
import zlib
import hashlib
import logging
import random
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple, Set
from collections import Counter

_log = logging.getLogger(__name__)


@dataclass
class InfoDistance:
    """多种信息论距离的容器。"""
    js_divergence: float = 0.0
    ncd: float = 0.0
    mutual_information: float = 0.0
    # 统计显著性
    js_pvalue: float = 1.0
    ncd_pvalue: float = 1.0


@dataclass
class InfoDistReport:
    """信息论补丁相似度报告。"""
    patch_id_a: str = ""
    patch_id_b: str = ""
    distances: InfoDistance = field(default_factory=InfoDistance)
    # 综合相似度 (0..1)
    composite_similarity: float = 0.0
    interpretation: str = ""

    def to_dict(self) -> Dict:
        return {
            'patch_a': self.patch_id_a,
            'patch_b': self.patch_id_b,
            'jsd': round(self.distances.js_divergence, 4),
            'ncd': round(self.distances.ncd, 4),
            'mi': round(self.distances.mutual_information, 4),
            'similarity': round(self.composite_similarity, 4),
            'interpretation': self.interpretation,
        }


# Jensen-Shannon 散度

def jensen_shannon_divergence(data_a: bytes, data_b: bytes) -> float:
    """两字节序列间的 Jensen-Shannon 散度。

    JSD(P||Q) = 0.5 * KL(P||M) + 0.5 * KL(Q||M)
    其中 M = 0.5 * (P + Q), KL 是 Kullback-Leibler 散度。

    JSD ∈ [0, ln(2)]，对称且有界——优于 KL 散度。
    除以 ln(2) 归一化到 [0, 1]。
    """
    freq_a = Counter(data_a)
    freq_b = Counter(data_b)
    all_bytes = set(freq_a.keys()) | set(freq_b.keys())

    n_a = len(data_a)
    n_b = len(data_b)
    if n_a == 0 or n_b == 0:
        return 1.0

    jsd = 0.0
    for byte_val in all_bytes:
        p = freq_a.get(byte_val, 0) / n_a
        q = freq_b.get(byte_val, 0) / n_b
        if p == 0 and q == 0:
            continue
        m = (p + q) / 2.0
        if p > 0:
            jsd += 0.5 * p * math.log(p / m)
        if q > 0:
            jsd += 0.5 * q * math.log(q / m)

    return jsd / math.log(2) if math.log(2) > 0 else 0.0


# 归一化压缩距离

def normalized_compression_distance(data_a: bytes, data_b: bytes) -> float:
    """归一化压缩距离 (NCD)。

    NCD(x,y) = (C(xy) - min(C(x), C(y))) / max(C(x), C(y))
    其中 C 是压缩长度 (zlib, level=6)。

    使用 zlib (deflate) 作为压缩器。deflate 基于 LZ77 + Huffman，
    在实践中是良好的通用压缩器。

    NCD ∈ [0, ~1.1]，理论上下界为 0（完全相同），
    上界可能略大于 1（因压缩器不完美）。
    """
    c_x = len(zlib.compress(data_a, level=6))
    c_y = len(zlib.compress(data_b, level=6))
    c_xy = len(zlib.compress(data_a + data_b, level=6))

    c_min = min(c_x, c_y)
    c_max = max(c_x, c_y)
    if c_max == 0:
        return 0.0

    ncd = (c_xy - c_min) / c_max
    return max(0.0, ncd)


# 互信息

def mutual_information(data_a: bytes, data_b: bytes) -> float:
    """两字节序列的互信息。

    I(X;Y) = H(X) + H(Y) - H(X,Y)
    归一化: NMI = 2 * I(X;Y) / (H(X) + H(Y))

    使用字节对 (a[i], b[i]) 的联合分布估计。
    不对齐的部分取 min_len。
    """
    min_len = min(len(data_a), len(data_b))
    if min_len == 0:
        return 0.0

    # 单变量熵
    def entropy(data: bytes) -> float:
        freq = Counter(data)
        n = len(data)
        return -sum((c/n) * math.log2(c/n) for c in freq.values() if c > 0)

    # 联合熵
    joint_freq = Counter()
    for i in range(min_len):
        pair = (data_a[i], data_b[i])
        joint_freq[pair] += 1
    joint_entropy = -sum((c/min_len) * math.log2(c/min_len)
                        for c in joint_freq.values() if c > 0)

    h_a = entropy(data_a[:min_len])
    h_b = entropy(data_b[:min_len])

    mi = h_a + h_b - joint_entropy
    # 归一化
    if h_a + h_b > 0:
        return 2.0 * mi / (h_a + h_b)
    return 0.0


# Permutation Test

def permutation_test(data_a: bytes, data_b: bytes,
                     metric_fn, n_permutations: int = 500,
                     seed: int = 42) -> float:
    """Permutation test 检验观测距离是否统计显著。

    H₀: 两样本来自同一分布（距离为随机波动）。
    若 p < 0.05 → 拒绝 H₀，距离具有统计显著性。

    metric_fn: 距离函数 (bytes, bytes) → float。
    返回 p-value。
    """
    observed = metric_fn(data_a, data_b)
    combined = bytearray(data_a) + bytearray(data_b)
    n_a = len(data_a)

    rng = random.Random(seed)
    count_extreme = 0
    for _ in range(n_permutations):
        perm = combined[:]
        # Fisher-Yates shuffle on combined
        for i in range(len(perm) - 1, 0, -1):
            j = rng.randint(0, i)
            perm[i], perm[j] = perm[j], perm[i]
        perm_a = bytes(perm[:n_a])
        perm_b = bytes(perm[n_a:])
        perm_dist = metric_fn(perm_a, perm_b)
        if perm_dist >= observed:
            count_extreme += 1

    return (count_extreme + 1) / (n_permutations + 1)


# 信息距离计算器

class InfoDistanceCalculator:
    """补丁间信息论距离计算器。

    用法:
        calc = InfoDistanceCalculator()
        report = calc.compare(patch_a_bytes, patch_b_bytes, 'patch_1', 'patch_2')
        print(f'JSD={report.distances.js_divergence:.3f}, NCD={report.distances.ncd:.3f}')
    """

    def __init__(self, significance_test: bool = True,
                 n_permutations: int = 200):
        self._sig_test = significance_test
        self._n_perm = n_permutations

    def compare(self, data_a: bytes, data_b: bytes,
                patch_id_a: str = "", patch_id_b: str = ""
                ) -> InfoDistReport:
        """计算两个补丁间的全套信息论距离。"""
        report = InfoDistReport(
            patch_id_a=patch_id_a, patch_id_b=patch_id_b)

        dist = InfoDistance()
        dist.js_divergence = jensen_shannon_divergence(data_a, data_b)
        dist.ncd = normalized_compression_distance(data_a, data_b)
        dist.mutual_information = mutual_information(data_a, data_b)

        if self._sig_test:
            dist.js_pvalue = permutation_test(
                data_a, data_b, jensen_shannon_divergence, self._n_perm)
            dist.ncd_pvalue = permutation_test(
                data_a, data_b, normalized_compression_distance,
                min(self._n_perm, 100))  # NCD 较慢，限制排列数

        report.distances = dist

        # 综合相似度: (1-JSD) * 0.4 + (1-min(NCD,1)) * 0.35 + NMI * 0.25
        jsd_sim = 1.0 - dist.js_divergence
        ncd_sim = 1.0 - min(dist.ncd, 1.0)
        nmi_sim = dist.mutual_information
        report.composite_similarity = (0.40 * jsd_sim + 0.35 * ncd_sim +
                                       0.25 * nmi_sim)
        report.composite_similarity = max(0.0, min(1.0, report.composite_similarity))

        # 解释
        sim = report.composite_similarity
        if sim > 0.90:
            report.interpretation = "极相似——可能来自同一修复模板或同一作者"
        elif sim > 0.70:
            report.interpretation = "高度相似——修复了同类漏洞"
        elif sim > 0.50:
            report.interpretation = "中度相似——可能有共享的修复逻辑元素"
        elif sim > 0.30:
            report.interpretation = "低度相似——修复了不同的漏洞类别"
        else:
            report.interpretation = "几乎无关——完全不同的补丁"

        return report
