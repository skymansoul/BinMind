# 多分辨率熵分析 — 从字节级到段级的层级化熵剖面
# "HAWKEYE" — 基于图论的门级加密原语检测
#       中的分块熵分析方法，将网表划分为局部/全局两个尺度
# "DeepMem" — 图神经网络用于内存对象检测
#       中的全内存图熵特征 — 不同内核对象类型显示不同的熵指纹
"Wavelet-Based Entropy for Malware Detection"
#       — 小波多分辨率熵用于区分加壳与正常代码

import math as _math
import struct as _struct
import hashlib as _hl
from collections import Counter as _Counter, defaultdict

# 字节级熵 (Byte-Level Shannon Entropy)
# 最基础且计算量最大的层级 — 256 维频率向量
# 仅从 Python 层面实现，性能敏感场景应使用 C 扩展或 numpy


def byte_entropy(data: bytes, wsize: int = 0) -> float | list[float]:
    # 字节级香农熵。wsize=0 → 全局; wsize>0 → 滑动窗口
    if not data:
        return 0.0 if wsize == 0 else []

    if wsize == 0:
        freq = [0] * 256
        for b in data:
            freq[b] += 1
        n = len(data)
        return -sum((f / n) * _math.log2(f / n) for f in freq if f > 0)

    # 滑动窗口
    entropies = []
    for i in range(0, len(data) - wsize + 1, max(1, wsize // 4)):
        window = data[i:i + wsize]
        freq = [0] * 256
        for b in window:
            freq[b] += 1
        n_w = len(window)
        ent = -sum((f / n_w) * _math.log2(f / n_w) for f in freq if f > 0)
        entropies.append(round(ent, 3))
    return entropies


# 结构熵 (Structural Entropy)
# 基于 n-gram 马尔可夫链的字节转移熵
# 压缩/加密代码的字节转移常接近均匀；正常代码显示结构化转移

def markov_entropy(data: bytes, order: int = 2) -> float:
    """计算 n 阶马尔可夫转移熵。
    order=1 → 字节对转移概率的熵；order=2 → 三元组转移概率。
    压缩/加密数据在所有阶上都接近 8；正常代码在 order=1-2 上熵显著偏低。"""
    if len(data) < order + 1:
        return 0.0

    # 构建转移计数矩阵: {prefix: {next_byte: count}}
    transitions: dict[bytes, _Counter] = defaultdict(_Counter)
    for i in range(len(data) - order):
        prefix = data[i:i + order]
        next_byte = data[i + order]
        transitions[prefix][next_byte] += 1

    if not transitions:
        return 0.0

    # 对每个前缀计算其转移分布的熵，然后取平均
    total_ent = 0.0
    for prefix, counts in transitions.items():
        total = sum(counts.values())
        if total == 0:
            continue
        prefix_ent = -sum((c / total) * _math.log2(c / total) for c in counts.values())
        total_ent += prefix_ent * (total / len(data))

    return round(total_ent, 3)


# 分块熵剖面 (Chunked Entropy Profile)
# 将二进制按 256B/512B/1KB/4KB 四个尺度分块，每个尺度计算一维熵向量
# 多分辨率方法可以同时捕获细粒度异常（如嵌入的 shellcode）和
# 粗粒度区域（如整个加密段）

def multi_scale_entropy_profile(data: bytes) -> dict:
    """生成多尺度熵剖面。

    四个尺度:
    - fine (256B): 检测嵌入的短 shellcode (典型长度 100-500B)
    - medium (512B): 检测小型加密块
    - coarse (1KB): 区分代码节与数据节
    - section (4KB): 对齐到内存页 — 检测 packer 的段级特征

    对每个尺度返回: min, max, mean, std, local_maxima_count
    高 local_maxima_count → 熵波动剧烈 → 建议进一步分析。"""
    if not data:
        return {}

    scales = {'fine_256B': 256, 'medium_512B': 512,
              'coarse_1KB': 1024, 'section_4KB': 4096}
    profile = {}

    for scale_name, chunk_size in scales.items():
        entropies = []
        for i in range(0, len(data), chunk_size):
            chunk = data[i:i + chunk_size]
            if len(chunk) < 64:
                continue
            ent = byte_entropy(chunk)
            if isinstance(ent, (int, float)):
                entropies.append(ent)

        if entropies:
            n = len(entropies)
            mean_e = sum(entropies) / n
            variance = sum((e - mean_e) ** 2 for e in entropies) / n

            # 统计局部极大值 (熵峰值)
            local_maxima = 0
            for i in range(1, n - 1):
                if entropies[i] > entropies[i - 1] and entropies[i] > entropies[i + 1]:
                    if entropies[i] > mean_e + _math.sqrt(max(variance, 0.01)):
                        local_maxima += 1

            profile[scale_name] = {
                'min': round(min(entropies), 2),
                'max': round(max(entropies), 2),
                'mean': round(mean_e, 2),
                'std': round(_math.sqrt(variance), 2),
                'chunks_analyzed': n,
                'local_maxima': local_maxima,
            }

    return profile


# ===== 熵异常检测 (Anomaly Detection in Entropy Space) =====
# 基于 Z-score 的异常块定位 — 熵偏离均值 2σ 的块标记为异常
# 这些块通常是: 嵌入的 payload、加密字符串表、多层壳的解密存根

def detect_entropy_anomalies(data: bytes, chunk_size: int = 1024,
                               z_threshold: float = 2.0) -> list[dict]:
    """使用 Z-score 检测熵异常块。
    z_threshold: Z-score 阈值 (默认 2.0 → 约 5% 的块被标记)。

    返回异常块列表，按 |Z-score| 降序排列（偏差最大的优先）。"""
    if not data:
        return []

    entropies = []
    positions = []
    for i in range(0, len(data), chunk_size):
        chunk = data[i:i + chunk_size]
        if len(chunk) < 64:
            continue
        ent = byte_entropy(chunk)
        if isinstance(ent, (int, float)):
            entropies.append(ent)
            positions.append(i)

    if len(entropies) < 3:
        return []

    n = len(entropies)
    mean_e = sum(entropies) / n
    std_e = _math.sqrt(sum((e - mean_e) ** 2 for e in entropies) / n)

    if std_e < 0.01:
        return []  # 熵过于均匀，无异常

    anomalies = []
    for i in range(n):
        z = (entropies[i] - mean_e) / std_e
        if abs(z) >= z_threshold:
            anomaly_type = 'high_entropy' if z > 0 else 'low_entropy'
            anomalies.append({
                'offset': positions[i],
                'entropy': round(entropies[i], 2),
                'z_score': round(z, 2),
                'type': anomaly_type,
                'chunk_size': min(chunk_size, len(data) - positions[i]),
                'interpretation': (
                    'possible_encrypted_or_compressed' if z > 0
                    else 'possible_padding_or_zero_fill'
                ),
            })

    anomalies.sort(key=lambda a: -abs(a['z_score']))
    return anomalies


# 熵热力图生成
# 将二进制文件的熵剖面转换为 ASCII 热力图字符串
# 用于终端快速可视化 — 一行 = 一个分块，颜色用字符密度编码

def entropy_heatmap(data: bytes, chunk_size: int = 512,
                     columns: int = 80) -> str:
    """生成 ASCII 熵热力图。
    每行表示一个 chunk 的熵水平，使用字符密度编码:
    ' ' (0-1), '.' (1-2), '-' (2-3), ':' (3-4), 'o' (4-5),
    'O' (5-6), '0' (6-7), '#' (7-8) """
    if not data:
        return ''

    density_chars = [' ', '.', '-', ':', 'o', 'O', '0', '#']
    lines = []
    for i in range(0, len(data), chunk_size):
        chunk = data[i:i + chunk_size]
        if len(chunk) < 64:
            continue
        ent = byte_entropy(chunk)
        if not isinstance(ent, (int, float)):
            continue
        idx = min(int(ent), 7)
        bar = density_chars[idx] * min(80, chunk_size // 8)
        offset_str = f'{i:08x}'
        ent_str = f'{ent:.1f}'
        lines.append(f'{offset_str} [{ent_str}] |{bar}|')

    return '\n'.join(lines)


# 字节分布偏度
# 正常编译器生成的代码中，x86 操作码的分布高度不规则
# (mov ≈ 30%, call ≈ 5%, nop ≈ 0.1%)。
# 加壳或加密的代码接近均匀分布 — 偏度接近 0
# 可利用此特性快速筛除压缩层

def byte_distribution_skewness(data: bytes) -> float:
    """计算字节分布的偏度 (skewness)。
    正值 → 集中于低频字节（正常可执行代码的典型特征）;
    接近 0 → 接近均匀分布（加密/压缩特征）。"""
    if len(data) < 256:
        return 0.0

    freq = [0] * 256
    for b in data:
        freq[b] += 1
    n = len(data)
    mean_freq = n / 256.0

    # 三阶矩（偏度）: E[(X-μ)³] / σ³
    m3 = sum(((f - mean_freq) ** 3) for f in freq) / 256.0
    m2 = sum(((f - mean_freq) ** 2) for f in freq) / 256.0
    if m2 < 1e-9:
        return 0.0
    return round(m3 / (m2 ** 1.5), 2)


# 全局熵-大小比率
# 一个综合指标: 总体文件大小与加密/压缩比例的比值
# 低比率 (< 0.3) → 大部分数据为高熵 → 高度压缩或加密
# GUARD 的壳严重度评分体系

def assess_compression_ratio(data: bytes, entropy_threshold: float = 7.0,
                               chunk_size: int = 4096) -> dict:
    """评估文件的整体压缩/加密比例。
    统计熵高于阈值的 4KB 页占比，推断加壳密度。"""
    if not data:
        return {'ratio': 0.0, 'assessment': 'empty_file'}

    high_ent_chunks = 0
    total_chunks = 0
    for i in range(0, len(data), chunk_size):
        chunk = data[i:i + chunk_size]
        if len(chunk) < 256:
            continue
        total_chunks += 1
        ent = byte_entropy(chunk)
        if isinstance(ent, (int, float)) and ent >= entropy_threshold:
            high_ent_chunks += 1

    if total_chunks == 0:
        return {'ratio': 0.0, 'assessment': 'too_small'}

    compression_ratio = high_ent_chunks / total_chunks
    if compression_ratio >= 0.8:
        assessment = 'heavily_compressed_or_encrypted'
    elif compression_ratio >= 0.4:
        assessment = 'partially_compressed'
    elif compression_ratio >= 0.15:
        assessment = 'mostly_plaintext_with_some_high_entropy'
    else:
        assessment = 'mostly_plaintext'

    return {
        'ratio': round(compression_ratio, 3),
        'high_entropy_pages': high_ent_chunks,
        'total_pages': total_chunks,
        'assessment': assessment,
        'average_global_entropy': round(byte_entropy(data) if isinstance(byte_entropy(data), (int, float)) else 0.0, 2),
    }


# Headless 批量熵分析
def headless_entropy_scan(binary_paths: list[str], output_json: str = '',
                           chunk_size: int = 1024) -> dict:
    """批量熵分析入口 — 对多个文件输出熵摘要。"""
    import json as _json
    results = {}
    for bp in binary_paths:
        try:
            with open(bp, 'rb') as f:
                data = f.read()
            profile = multi_scale_entropy_profile(data)
            anomalies = detect_entropy_anomalies(data, chunk_size)
            comp = assess_compression_ratio(data)
            results[bp] = {
                'size': len(data),
                'global_entropy': byte_entropy(data) if isinstance(byte_entropy(data), (int, float)) else 0.0,
                'profile': profile,
                'anomaly_count': len(anomalies),
                'compression': comp,
            }
        except Exception as exc:
            results[bp] = {'status': 'error', 'reason': str(exc)}
    out = {'files_analyzed': len(binary_paths), 'results': results}
    if output_json:
        with open(output_json, 'w') as f:
            _json.dump(out, f, indent=2)
    return out
