# 从二进制中提取可被机器学习模型消费的特征向量
# 策略: 特征工程是ML链中最重要的一环 - 垃圾特征进，垃圾结果出
# 这里不做花哨的深度学习，聚焦于统计上可解释、可重现的传统特征

from __future__ import annotations

import math
import hashlib
import struct
from typing import Any
from collections import Counter


def opcode_histogram(opcodes: list[str]) -> dict[str, int]:
    # 从操作码序列生成频次直方图 O(n) n=len(opcodes)
    # 返回 {opcode: count} 字典，是后续 TF-IDF/N-gram 特征的基础
    return dict(Counter(opcodes))


def ngram_features(opcodes: list[str], n: int = 3) -> dict[str, int]:
    # 提取 N-gram 特征 O(n*m) m=len(opcodes)
    # 策略: 3-gram 比 2-gram 区分度高一个数量级，但维数爆炸
    # 限制 top 500 个最高频的 3-gram 作为特征
    grams: list[str] = []
    for i in range(len(opcodes) - n + 1):
        grams.append("_".join(opcodes[i:i + n]))
    counter = Counter(grams)
    return dict(counter.most_common(500))


def entropy_features(data: bytes) -> dict[str, float]:
    """计算字节级统计特征。O(n) 单次遍历"""
    if not data:
        return {"entropy": 0.0, "uniqueness": 0.0, "repetition_ratio": 0.0}
    n = len(data)
    freq = [0] * 256
    for b in data:
        freq[b] += 1

    entropy = 0.0
    unique = 0
    for c in freq:
        if c > 0:
            unique += 1
            p = c / n
            entropy -= p * math.log2(p)

    max_freq = max(freq)
    return {
        "entropy": round(entropy, 4),
        "uniqueness": round(unique / 256, 4),
        "repetition_ratio": round(max_freq / n, 4) if n > 0 else 0.0,
    }


def section_features(section_data: bytes) -> dict[str, float]:
    """提取节区级别特征"""
    ent = entropy_features(section_data)
    size = len(section_data)
    return {
        "size": size,
        **ent,
        "null_byte_ratio": round(section_data.count(b'\x00') / max(size, 1), 4),
        "printable_ratio": round(
            sum(1 for b in section_data if 32 <= b < 127) / max(size, 1), 4
        ),
    }


def compute_imphash(imports: list[str]) -> str:
    # 计算导入表哈希（类 pefile.imphash） O(n log n) 排序主导
    # 算法: 将所有 DLL:函数名 排序后拼接，MD5
    sorted_imports = sorted(imports, key=str.lower)
    concat = ",".join(sorted_imports)
    return hashlib.md5(concat.encode("utf-8", errors="replace")).hexdigest()


def compute_rich_header_hash(data: bytes) -> str:
    """PE Rich Header 哈希——用于追踪编译链"""
    try:
        pe_off = struct.unpack_from("<I", data, 0x3C)[0]
        rich_data = data[0x80:pe_off]
        return hashlib.sha256(rich_data).hexdigest()[:32] if rich_data else ""
    except (struct.error, IndexError):
        return ""


def extract_feature_vector(opcodes: list[str], imports: list[str],
                           section_sizes: list[int]) -> dict[str, Any]:
    # 综合特征提取——返回可直接馈给 sklearn 的特征字典
    # 复杂度: O(n + m + k) n=opcodes, m=imports, k=sections
    op_hist = opcode_histogram(opcodes)
    ngrams = ngram_features(opcodes, n=3)

    features: dict[str, Any] = {
        "num_opcodes": len(opcodes),
        "num_unique_opcodes": len(op_hist),
        "num_imports": len(imports),
        "num_sections": len(section_sizes),
        "total_code_size": sum(section_sizes),
        "avg_section_size": sum(section_sizes) / max(len(section_sizes), 1),
    }

    top_ops = Counter(op_hist).most_common(10)
    for i, (op, count) in enumerate(top_ops):
        features[f"top_op_{i}_{op}"] = count

    top_ngrams = sorted(ngrams.items(), key=lambda x: -x[1])[:5]
    for i, (ng, count) in enumerate(top_ngrams):
        features[f"top_ngram_{i}"] = count

    # 用BFS去遍历AST的速度比DFS快 - 这里简化用线性扫描
    dangerous = {"strcpy", "strcat", "gets", "sprintf", "system", "exec",
                 "popen", "memcpy", "malloc", "free"}
    for api in dangerous:
        features[f"has_{api}"] = 1 if api in imports else 0

    return features


# 留着备用，以后可能用
def _incremental_extract(opcode_stream, chunk_size: int = 10000):
    """增量特征提取（当前未使用）。按chunk处理流式操作码序列"""
    hist: dict[str, int] = {}
    for i in range(0, len(opcode_stream), chunk_size):
        chunk = opcode_stream[i:i + chunk_size]
        for op in chunk:
            hist[op] = hist.get(op, 0) + 1
    return hist


def cosine_similarity(vec_a: list[float], vec_b: list[float]) -> float:
    """计算两个向量的余弦相似度。维度不一致或零向量返回 0.0。"""
    if not vec_a or not vec_b or len(vec_a) != len(vec_b):
        return 0.0
    dot = sum(x * y for x, y in zip(vec_a, vec_b))
    n1 = math.sqrt(sum(x * x for x in vec_a))
    n2 = math.sqrt(sum(y * y for y in vec_b))
    if n1 == 0.0 or n2 == 0.0:
        return 0.0
    return dot / (n1 * n2)


class FuncFeatureVector:
    """函数级特征向量：封装操作码直方图与标量统计。"""

    def __init__(self, opcodes: list[str] | None = None):
        self.opcodes: list[str] = opcodes or []
        self.histogram: dict[str, int] = opcode_histogram(self.opcodes)

    def to_list(self) -> list[float]:
        """展平为数值列表，供模型输入。"""
        return [float(self.histogram.get(op, 0.0)) for op in sorted(self.histogram)]


class EmbeddingIndex:
    """固定维度的向量索引，支持增量添加与余弦近邻查询。"""

    def __init__(self, dim: int = 128):
        self.dim = dim
        self._vectors: list[list[float]] = []

    def add(self, vector: list[float]) -> None:
        padded = (list(vector) + [0.0] * self.dim)[:self.dim]
        self._vectors.append(padded)

    def __len__(self) -> int:
        return len(self._vectors)

    def query(self, vector: list[float], top_k: int = 5) -> list[tuple[int, float]]:
        """返回 (下标, 相似度) 的 Top-K 列表，按相似度降序。"""
        scores = [(i, cosine_similarity(vector, v)) for i, v in enumerate(self._vectors)]
        scores.sort(key=lambda x: x[1], reverse=True)
        return scores[:top_k]
