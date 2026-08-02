# 2026-07-26
# 熵值计算与数据随机性评估工具
# 包含: Shannon 熵、Renyi 熵、条件熵、Chi-square 随机性检验、字节频率分析
# Beyond Embeddings [arXiv:2509.23449] 指出可解释特征（熵分布、字节直方图）
# 在跨架构二进制相似性任务中可与训练型嵌入方法竞争。
# 熵分析是区分代码段和数据段的经典方法，参考 [Lyda & Hamrock 2007]。
import math
from typing import Dict, List, Tuple, Optional
from collections import Counter

# ---- Shannon 熵 ---------------------------------------------------------

def shannon_entropy(data: bytes, base: int = 2) -> float:
    """字节级 Shannon 熵。base 默认 2 (bits/byte, 上限 8)。
    空数据 → 0.0。"""
    if not data: return 0.0
    counts = Counter(data); total = len(data); entropy = 0.0
    log_fn = math.log if base == 0 else (lambda x: math.log(x) / math.log(base))
    for cnt in counts.values():
        if cnt > 0:
            p = cnt / total; entropy -= p * log_fn(p)
    return entropy

def shannon_entropy_fast(data: bytes) -> float:
    """Shannon 熵的快速版本（base=e，自然对数）。
    使用预先计算的频率表，无 Counter 构造开销。
    适用于大缓冲区 (>1MB) 的性能敏感路径。"""
    n = len(data)
    if n == 0:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    ent = 0.0
    inv_n = 1.0 / n
    for f in freq:
        if f > 0:
            p = f * inv_n
            ent -= p * math.log(p)
    return ent

# ---- Renyi 熵 (alpha 阶泛化) -------------------------------------------

def renyi_entropy(data: bytes, alpha: float = 2.0, base: int = 2) -> float:
    """Renyi 熵: H_α = (1/(1-α)) * log_base(Σ p(x)^α)
    alpha=1 时退化为 Shannon 熵（通过极限处理）。
    alpha=2 即碰撞熵（Collision Entropy），衡量两独立采样碰撞的概率下界。
    alpha→∞ 即 min-entropy（此处不实现）。"""
    if alpha == 1.0:
        return shannon_entropy(data, base=base)
    if len(data) == 0:
        return 0.0
    counts = Counter(data)
    total = len(data)
    sum_pow = sum((c / total) ** alpha for c in counts.values())
    log_fn = math.log if base == 0 else (lambda x: math.log(x) / math.log(base))
    return (1.0 / (1.0 - alpha)) * log_fn(sum_pow)

# 字节频率 -----------------------------------------------------------

def byte_histogram(data: bytes) -> List[int]:
    """返回 256 个槽位的字节频率列表。索引即字节值。"""
    hist = [0] * 256
    for b in data:
        hist[b] += 1
    return hist

def byte_frequencies(data: bytes) -> List[float]:
    """返回 256 个字节值的归一化频率 (0.0–1.0)。"""
    n = len(data)
    if n == 0:
        return [0.0] * 256
    hist = byte_histogram(data)
    inv = 1.0 / n
    return [h * inv for h in hist]

def most_frequent_bytes(data: bytes, top_n: int = 10) -> List[Tuple[int, int]]:
    """返回出现次数最多的 top_n 个字节及其频次。"""
    return Counter(data).most_common(top_n)

# ---- Chi-square 随机性检验 ----------------------------------------------
# 用于区分密文/压缩数据（高熵、均匀分布）与明文/代码（偏态分布）

def chi_square_uniformity(data: bytes) -> Tuple[float, float]:
    """Chi-square 均匀性检验。
    零假设 H0: 数据服从 [0,255] 上的均匀分布。
    返回 (chi2_statistic, p_value)。
    p_value < 0.01 强烈拒绝 H0（数据非均匀分布）。
    适用于最少 256 字节以上的样本（期望频次 ≥5 每桶）。"""
    n = len(data)
    if n == 0:
        return (0.0, 1.0)
    expected = n / 256.0
    hist = byte_histogram(data)
    chi2 = sum((obs - expected) ** 2 / expected for obs in hist)
    # 自由度 = 255
    p_value = _chi2_survival(chi2, 255)
    return (chi2, p_value)

def _chi2_survival(x: float, dof: int) -> float:
    """Chi-square 分布的生存函数近似（Wilson-Hilferty 变换）。
    精度对 dof > 30 可接受。对于极端值用 1.0 或 0.0 截断。"""
    if x <= 0:
        return 1.0
    # Wilson-Hilferty: (χ²/dof)^(1/3) ~ N(1 - 2/(9*dof), sqrt(2/(9*dof)))
    z = ((x / dof) ** (1.0 / 3.0) - (1.0 - 2.0 / (9.0 * dof))) / math.sqrt(2.0 / (9.0 * dof))
    # 正态分布右尾概率 (Abramowitz & Stegun 近似)
    p = 0.5 * math.erfc(z / math.sqrt(2.0))
    return max(0.0, min(1.0, p))

# ---- 压缩率估计 (作为熵的补充指标) --------------------------------------

def compression_ratio_estimate(data: bytes, window: int = 64) -> float:
    """通过滑动窗口 LZ 风格匹配估计可压缩性。
    返回估计压缩比 (compressed / original)。
    值越接近 0，可压缩性越高。
    取样策略：每 window 字节采样一次，避免 O(n²)。"""
    n = len(data)
    if n < window * 2:
        return 1.0
    matches = 0
    total_samples = 0
    for i in range(window, n, window):
        # 在前 window 字节中搜索当前片段
        search_start = max(0, i - window * 16)
        needle = data[i:i + min(window, n - i)]
        pos = data[search_start:i].find(needle)
        if pos != -1:
            matches += 1
        total_samples += 1
    if total_samples == 0:
        return 1.0
    return 1.0 - (matches / total_samples) * 0.5

# ---- 数据段检测 ---------------------------------------------------------

def is_likely_code(data: bytes, threshold: float = 5.5) -> bool:
    """基于熵值启发式判断数据是否像机器码。
    x86/x64 指令流熵值通常在 5.0–6.5 bits/byte 范围。
    低于 5.5 → 可能是代码段。"""
    ent = shannon_entropy(data, base=2)
    return ent < threshold

def is_likely_compressed_or_crypto(data: bytes, threshold: float = 7.5) -> bool:
    """基于熵值判断数据是否像压缩/加密内容。
    接近 8.0 bits/byte → 高度随机 → 可能是密文或压缩数据。"""
    ent = shannon_entropy(data, base=2)
    return ent > threshold

def entropy_profile(data: bytes, block_size: int = 256) -> List[float]:
    """分块计算 Shannon 熵，返回每块的熵值列表。
    用于识别文件中不同区域的熵分布（如 PE 文件各节的对比）。"""
    profile = []
    for i in range(0, len(data), block_size):
        block = data[i:i + block_size]
        profile.append(shannon_entropy(block, base=2))
    return profile
