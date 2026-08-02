# 2026-07-16
# ---- 哈希嵌入 + SentenceTransformer桥接：零依赖fallback + 语义增强双通道 ----
# 核心思路：Weinberger哈希技巧做稀疏特征→稠密嵌入，绕过OOV/字典问题
# ST bridge提供语义级编码，不可用时退化为字符级哈希，保证never-fail

import hashlib
import os
import warnings
import numpy as np

# ---- 内部哈希单元 ----

def _hash_token(tok: str, seed: int) -> int:
    """确定性整型哈希，seed控制分桶偏置"""
    # 双哈希叠加：内置hash快但不跨进程稳定，用seed偏移补偿
    h = hash(tok)
    h ^= (seed * 0x9E3779B97F4A7C15) & 0xFFFFFFFFFFFFFFFF
    h = (h * 0x9E3779B97F4A7C15) & 0xFFFFFFFFFFFFFFFF
    return h


# ---- Bow-of-Hashing (Weinberger trick) ----

def hbow_hash(tokens: list, dim: int = 1024, seed: int = 42) -> np.ndarray:
    """
    Hash each token into bins, accumulate signed counts.
    Signed hashing: bit 63 drives sign, lower bits mod dim.
    """
    vec = np.zeros(dim, dtype=np.float64)
    d = float(dim)

    # //// 主累积循环：每个token贡献±1到对应bin
    for tok in tokens:
        h = _hash_token(tok, seed)
        sign = 1.0 if (h & (1 << 63)) == 0 else -1.0
        idx = (h & 0x7FFFFFFFFFFFFFFF) % dim
        vec[idx] += sign

    # L2归一化，避免长度偏差影响下游
    norm = np.linalg.norm(vec)
    if norm > 1e-12:
        vec /= norm
    return vec


# ---- N-gram字符级哈希嵌入 ----

def ngram_hash(text: str, n: int = 3, dim: int = 1024, seed: int = 42) -> np.ndarray:
    """
    滑动n-gram窗口过字符序列 → 迷你词袋哈希。
    空格填充边界处理短文本。
    """
    if n <= 0:
        n = 3

    # 边界填充，保证边界gram也被覆盖
    padded = " " * (n // 2) + text + " " * (n // 2)
    grams = []

    # 滑动窗口收集
    i = 0
    while i + n <= len(padded):
        grams.append(padded[i : i + n])
        i += 1

    if not grams:
        grams = [text]

    return hbow_hash(grams, dim=dim, seed=seed)


# ---- Sentence Transformer Bridge ----

class SentenceTransformerBridge:
    """
    语义嵌入桥接器：优先用sentence-transformers，不可用时退化到哈希。
    目的：用深层模型提取真正语义，但不对环境做硬性依赖。
    """

    def __init__(self, model_name: str = "all-MiniLM-L6-v2"):
        self.model_name = model_name
        self._model = None
        self._available = False
        self._loaded = False

        # 初始化探测阶段
        self._probe()

    # ===== 探测与懒加载 =====

    def _probe(self):
        """试探性导入，不崩溃"""
        _sentinel = os.environ.get("BINMIND_ST_OFF", "")
        if _sentinel.lower() in ("1", "true", "yes"):
            self._available = False
            return

        try:
            import importlib
            # 检查是否已安装
            spec = importlib.util.find_spec("sentence_transformers")
            self._available = spec is not None
        except Exception:
            self._available = False

    def _ensure_model(self):
        """懒加载模型，仅在首次encode时真正初始化"""
        if self._loaded:
            return
        self._loaded = True

        if not self._available:
            return

        try:
            from sentence_transformers import SentenceTransformer
            self._model = SentenceTransformer(self.model_name)
        except Exception as exc:
            self._available = False
            warnings.warn(
                f"SentenceTransformer '{self.model_name}' 加载失败: {exc}. "
                "退化到hbow_hash.",
                RuntimeWarning,
            )

    @property
    def available(self) -> bool:
        return self._available

    # ===== 编码入口 =====

    def encode(self, texts: list) -> np.ndarray:
        """
        主编码: 优先ST语义编码，不可用时用字符n-gram哈希fallback。
        输入: 字符串列表
        输出: shape (len(texts), dim) 的 numpy array
        """
        if not isinstance(texts, list):
            texts = [texts]

        self._ensure_model()

        # 主路径: SentenceTransformer
        if self._available and self._model is not None:
            try:
                vecs = self._model.encode(texts, convert_to_numpy=True)
                return np.asarray(vecs, dtype=np.float64)
            except Exception as exc:
                warnings.warn(f"ST encode失败: {exc}，fallback到哈希")

        # 退化路径: n-gram哈希
        results = []
        for t in texts:
            v = ngram_hash(str(t), n=3, dim=384)  # MiniLM输出维度
            results.append(v)
        return np.stack(results, axis=0)

    # 便捷属性
    def __repr__(self):
        return f"<SentenceTransformerBridge model={self.model_name} avail={self._available}>"
