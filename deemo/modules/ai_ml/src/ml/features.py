# 2026-07-16
# ---- 经典特征提取管线：从原始字节到结构化特征向量 ----
# 策略：轻量级统计特征先行，必要时再上复杂模型
# 编译器检测用启发式字符串匹配，避免训练成本

import math
import re
from collections import Counter

import numpy as np


# ===== 内部工具 =====

def _rolling_hash(data, window: int) -> int:
    """滑动窗口哈希，用于快速n-gram索引"""
    h = 0
    for i, b in enumerate(data[:window]):
        h ^= (b << (8 * (i % 8)))
    return h & 0xFFFFFFFFFFFFFFFF


# ===== 字节直方图 =====

def extract_byte_histogram(data: bytes, bins: int = 256) -> np.ndarray:
    """归一化字节频率分布: (bins,)"""
    if not data:
        return np.zeros(bins, dtype=np.float64)

    counts = np.zeros(256, dtype=np.float64)
    for b in data:
        counts[b] += 1

    # 截取或补齐到bins
    hist = counts[:bins] if bins <= 256 else np.pad(counts, (0, bins - 256))
    total = hist.sum()
    if total > 0:
        hist /= total
    return hist


# ===== 香农熵 =====

def compute_entropy(data: bytes) -> float:
    """字节级香农熵，衡量随机性/压缩率"""
    if not data:
        return 0.0
    ln2 = math.log(2)
    counts = Counter(data)
    n = float(len(data))
    entropy = 0.0
    # 循环替代推导，避免中间数组
    for cnt in counts.values():
        if cnt > 0:
            p = cnt / n
            entropy -= p * math.log(p) / ln2
    return round(entropy, 6)


# ===== N-gram特征 =====

def extract_ngram_features(data: bytes, n: int = 4, top_k: int = 20) -> np.ndarray:
    """
    提取最高频n-gram字节序列的归一化频率。
    输出: (top_k,) float array
    """
    if len(data) < n:
        return np.zeros(top_k, dtype=np.float64)

    ngrams = []
    for i in range(len(data) - n + 1):
        ngrams.append(data[i : i + n])

    counter = Counter(ngrams)
    most_common = counter.most_common(top_k)
    total = max(counter.total(), 1)

    feats = np.zeros(top_k, dtype=np.float64)
    for j, (_, cnt) in enumerate(most_common):
        feats[j] = cnt / total
    return feats


# ===== 编译器探测 =====

_GCC_SIGS = [".GCC:", "GCC:", "_GLOBAL__", "__gnu_", "mingw", "DW.ref.__gcc_", "gcc_compiled"]
_MSVC_SIGS = [".rdata", ".pdata", "__security_cookie", "GSHandlerCheck", "__RTC_", "_RTC_"]
_CLANG_SIGS = ["__clang_", "-clang", "clang version", "LLVM", "__blocks"]


def detect_compiler_from_strings(strings_list: list) -> dict:
    """
    启发式编译器指纹匹配。
    返回 {'compiler', 'confidence', 'indicators'}
    confidence: 匹配到的签名数占总候选的比例
    """
    text = " ".join(strings_list)
    tlower = text.lower()

    # ---- 各编译器特征计数 ----
    gcc_hits = [sig for sig in _GCC_SIGS if sig.lower() in tlower or sig in text]
    msvc_hits = [sig for sig in _MSVC_SIGS if sig.lower() in tlower or sig in text]
    clang_hits = [sig for sig in _CLANG_SIGS if sig.lower() in tlower or sig in text]

    # 计算置信度: 命中数 / 该编译器签名总数
    def _conf(hits, total):
        if not hits:
            return 0.0
        return round(len(hits) / total, 3)

    candidates = {
        "gcc":   (_conf(gcc_hits, len(_GCC_SIGS)), gcc_hits),
        "msvc":  (_conf(msvc_hits, len(_MSVC_SIGS)), msvc_hits),
        "clang": (_conf(clang_hits, len(_CLANG_SIGS)), clang_hits),
    }

    best = max(candidates.items(), key=lambda kv: kv[1][0])

    if best[1][0] <= 0.0:
        return {"compiler": "unknown", "confidence": 0.0, "indicators": []}

    return {
        "compiler": best[0],
        "confidence": best[1][0],
        "indicators": best[1][1],
    }


# ===== 特征提取器 =====

class FeatureExtractor:
    """
    统一特征提取器：一次调用，输出完整特征dict。
    内部组合byte/entropy/ngram/compiler四个维度。
    """

    def __init__(self):
        pass

    # //// 主提取入口

    def extract(self, data: bytes, strings: list = None) -> dict:
        """全部特征汇聚"""
        feats = {}

        # 字节统计
        feats["byte_hist"] = extract_byte_histogram(data)
        feats["entropy"] = compute_entropy(data)
        feats["ngram_top20"] = extract_ngram_features(data, n=4, top_k=20)

        # 基本统计
        feats["size"] = len(data)
        feats["unique_bytes"] = len(set(data)) if data else 0

        # 编译器指纹
        if strings:
            feats["compiler"] = detect_compiler_from_strings(strings)
        else:
            feats["compiler"] = {"compiler": "unknown", "confidence": 0.0, "indicators": []}

        return feats

    # //// 结构特征 (PE/ELF元数据)

    def extract_structural(self, pe_or_elf: dict) -> dict:
        """
        从解析后的PE/ELF字典提取结构特征。
        输入: {'sections': [...], 'imports': [...], ...}
        输出: 节数、导入数、特征数值dict
        """
        sects = pe_or_elf.get("sections", [])
        imports = pe_or_elf.get("imports", [])

        return {
            "section_count": len(sects),
            "import_count": len(imports),
            "total_section_size": sum(
                s.get("size", 0) if isinstance(s, dict) else 0 for s in sects
            ),
            # 标记可执行节
            "exec_section_count": sum(
                1 for s in sects
                if isinstance(s, dict) and (s.get("flags", 0) or 0) & 0x20000000
            ),
        }
